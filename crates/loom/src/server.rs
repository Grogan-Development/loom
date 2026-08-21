//! Combined standalone Loom HTTP surface: CAS RPC, features, CI, and Git.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{delete, get, post},
};
use futures_util::stream::{self, StreamExt as _};
use serde::{Deserialize, Serialize};

use crate::auth::{AccessToken, bearer_token};
use crate::ci::CiEngine;
use crate::events::{DEFAULT_CATCH_UP, Event, EventLog, MAX_CATCH_UP};
use crate::features::{CandidateSubmit, Feature, FeatureCreate, FeatureStore, promotion_updates};
use crate::git::{GitBridge, GitHttpGateway};
use crate::insights::InsightsEngine; // insights-slice
use crate::origin::{OriginCiRequest, OriginConfig, OriginEngine, OriginEvidence, OriginMirrorJob};
use crate::review::{
    CommentCreate, FindingApply, FindingsAppend, ReviewComplete, ReviewStart, ReviewStatus,
    ReviewStore,
};
use crate::review_runner::{ReviewDispatcher, ReviewRunnerConfig};
use crate::tokens::{Authority, Principal, TokenMint, TokenPerm, TokenStore};
use crate::{AtomicRefResult, LoomError, LoomRpc, NamespaceGrant, PersistentLoomStore};
use tokio::sync::broadcast;

/// Runtime configuration for the combined Loom server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Listen address. Docker typically uses `0.0.0.0:8080`.
    pub bind: SocketAddr,
    /// Absolute private dataset root.
    pub root: PathBuf,
    /// Owner bearer token. Authorizes features, CAS RPC, Git, CI, and evidence GET.
    pub token: AccessToken,
    /// Deploy-only bearer token. Distinct from `token` unless tests set them equal.
    pub deploy_token: Option<AccessToken>,
    /// Origin clone, webhook, check-run, and apply configuration.
    pub origin: OriginConfig,
    /// Absolute Git executable.
    pub git_program: PathBuf,
    /// Absolute pre-receive hook executable (`loom-git-hook`).
    pub hook_program: PathBuf,
    /// Optional dedicated Grid/Nero candidate-review backend.
    pub review_runner: Option<ReviewRunnerConfig>,
}

#[derive(Clone)]
struct AppState {
    token: AccessToken,
    deploy_token: Option<AccessToken>,
    authority: Authority,
    features: FeatureStore,
    reviews: ReviewStore,
    ci: CiEngine,
    insights: InsightsEngine, // insights-slice
    origin: OriginEngine,
    store: PersistentLoomStore,
    events: EventLog, // events-slice
    review_dispatcher: Option<ReviewDispatcher>,
}

/// Combined Loom process: native RPC + features + lightning CI + Git HTTP.
pub struct LoomApp {
    bind: SocketAddr,
    router: Router,
}

impl LoomApp {
    /// Opens the dataset and builds the authenticated application router.
    ///
    /// # Errors
    ///
    /// Returns for unsafe roots, missing Git executables, or storage failure.
    pub fn new(config: ServerConfig) -> Result<Self, LoomError> {
        let store = PersistentLoomStore::open(&config.root)?;
        let features = FeatureStore::new(store.clone());
        let reviews = ReviewStore::new(store.clone());
        let ci = CiEngine::new(store.clone());
        let insights = InsightsEngine::new(store.clone()); // insights-slice
        let authority = Authority::new(config.token.clone(), TokenStore::new(store.clone()));
        let token_state = TokenState(config.token.clone());
        let rpc = LoomRpc::new(store.clone())
            .router()
            .layer(middleware::from_fn_with_state(token_state, require_bearer));
        let git_router = GitBridge::new(store.clone(), &config.git_program, &config.hook_program)
            .map_or_else(
                |_| Router::new(),
                |bridge| GitHttpGateway::new(bridge, authority.clone()).router(),
            );
        let origin = OriginEngine::new(store.clone(), config.origin);
        let events = EventLog::new(store.clone()); // events-slice
        let review_dispatcher = config.review_runner.map(|review_runner| {
            ReviewDispatcher::new(
                review_runner,
                authority.clone(),
                reviews.clone(),
                events.clone(),
            )
        });
        let state = AppState {
            token: config.token,
            deploy_token: config.deploy_token,
            authority,
            features,
            reviews,
            ci,
            insights,
            origin,
            store,
            events,
            review_dispatcher,
        };
        let api = Router::new()
            .route("/healthz", get(healthz))
            .route("/v1/tokens", get(list_tokens).post(mint_token))
            .route("/v1/tokens/{id}", delete(revoke_token))
            .route("/v1/events", get(list_events)) // events-slice
            .route("/v1/features", get(list_features).post(create_feature))
            .route("/v1/features/{id}", get(get_feature))
            .route("/v1/features/{id}/approve", post(approve_feature))
            .route("/v1/features/{id}/candidates", post(submit_candidate))
            .route("/v1/features/{id}/insights", get(get_insights)) // insights-slice
            .route("/v1/features/{id}/accept", post(accept_feature))
            .route("/v1/features/{id}/reject", post(reject_feature))
            .route(
                "/v1/features/{id}/reviews",
                get(list_reviews).post(create_review),
            )
            .route(
                "/v1/features/{id}/reviews/{rid}/findings",
                post(append_findings),
            )
            .route(
                "/v1/features/{id}/reviews/{rid}/complete",
                post(complete_review),
            )
            .route(
                "/v1/features/{id}/findings/{fid}/approve",
                post(approve_finding),
            )
            .route(
                "/v1/features/{id}/findings/{fid}/apply",
                post(apply_finding),
            )
            .route(
                "/v1/features/{id}/comments",
                get(list_comments).post(create_comment),
            )
            .route("/v1/origin/webhook", post(origin_webhook))
            .route("/v1/releases/{repo}/ci", post(origin_start_ci))
            .route("/v1/releases/{repo}/{oid}", get(origin_get_release))
            .route(
                "/v1/releases/{repo}/{oid}/deploy",
                post(origin_deploy_release),
            )
            .route("/v1/mirrors", get(origin_list_mirrors))
            .layer(DefaultBodyLimit::max(24 * 1024 * 1024))
            .with_state(state);
        let router = Router::new().merge(api).merge(rpc).nest("/git", git_router);
        Ok(Self {
            bind: config.bind,
            router,
        })
    }

    /// Listen address.
    #[must_use]
    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Application router.
    pub fn router(self) -> Router {
        self.router
    }
}

#[derive(Clone)]
struct TokenState(AccessToken);

async fn require_bearer(State(token): State<TokenState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    if presented.is_some_and(|value| token.0.matches(value)) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                code: "loom.unauthorized".to_owned(),
                message: "bearer token required".to_owned(),
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct HealthBody {
    schema_version: &'static str,
    persistent_state_ready: bool,
}

async fn healthz(State(state): State<AppState>) -> Response {
    match state.store.health() {
        Ok(()) => Json(HealthBody {
            schema_version: "v1",
            persistent_state_ready: true,
        })
        .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthBody {
                schema_version: "v1",
                persistent_state_ready: false,
            }),
        )
            .into_response(),
    }
}

fn require_deploy_token(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(expected) = state.deploy_token.as_ref() else {
        return Err(Box::new(unauthorized()));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    match presented {
        Some(token) if expected.matches(token) => Ok(()),
        _ => Err(Box::new(unauthorized())),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody {
            code: "loom.unauthorized".to_owned(),
            message: "bearer token required".to_owned(),
        }),
    )
        .into_response()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

async fn origin_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let webhook_id = header_str(&headers, "webhook-id");
    let timestamp = header_str(&headers, "webhook-timestamp");
    let signature = header_str(&headers, "webhook-signature");
    if !state.origin.config().webhook_keys.is_empty()
        && state
            .origin
            .verify_webhook(webhook_id, timestamp, signature, &body)
            .await
            .is_err()
    {
        return unauthorized();
    }
    let excerpt: String = String::from_utf8_lossy(&body).chars().take(2000).collect();
    eprintln!(
        "loom: origin webhook ignored (mirror_only, {} bytes): {excerpt}",
        body.len()
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn origin_start_ci(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(repo): AxumPath<String>,
    Json(request): Json<OriginCiRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let origin = state.origin.clone();
    match tokio::task::spawn_blocking(move || origin.run_ci(&repo, &request.git_oid)).await {
        Ok(Ok(release)) => Json(OriginEvidence::from(&release)).into_response(),
        Ok(Err(LoomError::OriginRepositoryDenied { .. })) => {
            feature_error(StatusCode::NOT_FOUND, "origin.repository_denied")
        }
        Ok(Err(LoomError::InvalidSourceCommit)) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "origin.oid_invalid")
        }
        Ok(Err(_)) => feature_error(StatusCode::CONFLICT, "origin.ci_failed"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "origin.unavailable"),
    }
}

async fn origin_get_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((repo, oid)): AxumPath<(String, String)>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    if !principal.allows(TokenPerm::Evidence, [repo.as_str()]) {
        return forbidden();
    }
    match state.origin.release(&repo, &oid) {
        Ok(Some(release)) => Json(OriginEvidence::from(&release)).into_response(),
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "origin.release_missing"),
        Err(LoomError::OriginRepositoryDenied { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "origin.repository_denied")
        }
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "origin.oid_invalid"),
    }
}

async fn origin_deploy_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((repo, oid)): AxumPath<(String, String)>,
) -> Response {
    if let Err(response) = require_deploy_token(&state, &headers) {
        return *response;
    }
    let origin = state.origin.clone();
    match tokio::task::spawn_blocking(move || origin.deploy(&repo, &oid)).await {
        Ok(Ok(release)) => Json(OriginEvidence::from(&release)).into_response(),
        Ok(Err(LoomError::OriginDeployBlocked { .. })) => {
            feature_error(StatusCode::CONFLICT, "origin.deploy_blocked")
        }
        Ok(Err(LoomError::OriginRepositoryDenied { .. })) => {
            feature_error(StatusCode::NOT_FOUND, "origin.repository_denied")
        }
        Ok(Err(_)) => feature_error(StatusCode::CONFLICT, "origin.deploy_failed"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "origin.unavailable"),
    }
}

async fn origin_list_mirrors(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.origin.mirrors() {
        Ok(jobs) => Json(MirrorList { jobs }).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "origin.unavailable"),
    }
}

#[derive(Serialize)]
struct MirrorList {
    jobs: Vec<OriginMirrorJob>,
}

fn require_token(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    match presented {
        Some(token) if state.token.matches(token) => Ok(()),
        _ => Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    code: "loom.unauthorized".to_owned(),
                    message: "bearer token required".to_owned(),
                }),
            )
                .into_response(),
        )),
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// Resolves the caller to the owner or a live scoped token.
fn resolve_principal(state: &AppState, headers: &HeaderMap) -> Result<Principal, Box<Response>> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .and_then(|secret| state.authority.resolve(secret))
        .ok_or_else(|| Box::new(unauthorized()))
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            code: "loom.forbidden".to_owned(),
            message: "token scope does not cover this repository set".to_owned(),
        }),
    )
        .into_response()
}

fn feature_repositories(feature: &Feature) -> impl Iterator<Item = &str> {
    feature
        .repositories
        .iter()
        .map(|binding| binding.base.repository.as_str())
}

async fn mint_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TokenMint>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.authority.tokens().mint(&request) {
        Ok(minted) => (StatusCode::CREATED, Json(minted)).into_response(),
        Err(LoomError::StorageUnavailable) => {
            feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable")
        }
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "token.invalid"),
    }
}

async fn list_tokens(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.authority.tokens().list() {
        Ok(tokens) => Json(tokens).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.authority.tokens().revoke(&id) {
        Ok(removed) => Json(removed).into_response(),
        Err(LoomError::UnknownToken { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "token.not_found")
        }
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn list_features(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    match state.features.list() {
        Ok(features) => {
            let visible = features
                .into_iter()
                .filter(|feature| {
                    principal_allows_any(
                        &principal,
                        &[TokenPerm::Features, TokenPerm::Review],
                        feature,
                    )
                })
                .collect::<Vec<_>>();
            Json(visible).into_response()
        }
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn create_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FeatureCreate>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    if !principal.allows(
        TokenPerm::Features,
        request
            .repositories
            .iter()
            .map(|binding| binding.base.repository.as_str()),
    ) {
        return forbidden();
    }
    match state.features.create(request) {
        Ok(feature) => {
            emit_feature(&state.events, "feature.created", &feature);
            (StatusCode::CREATED, Json(feature)).into_response()
        }
        Err(LoomError::InvalidRef { ref_name }) => feature_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("invalid ref {ref_name}"),
        ),
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "feature.invalid"),
    }
}

async fn get_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    match state.features.get(&id) {
        Ok(feature) => {
            if principal_allows_any(
                &principal,
                &[TokenPerm::Features, TokenPerm::Review],
                &feature,
            ) {
                Json(feature).into_response()
            } else {
                forbidden()
            }
        }
        Err(_) => feature_error(StatusCode::NOT_FOUND, "feature.not_found"),
    }
}

async fn approve_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.features.approve(&id) {
        Ok(feature) => {
            emit_feature(&state.events, "feature.approved", &feature);
            Json(feature).into_response()
        }
        Err(LoomError::UnknownRevision { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "feature.not_found")
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
    }
}

async fn submit_candidate(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<CandidateSubmit>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let Ok(feature) = state.features.get(&id) else {
        return feature_error(StatusCode::NOT_FOUND, "feature.not_found");
    };
    let mut touched = feature_repositories(&feature).collect::<BTreeSet<_>>();
    for binding in &request.repositories {
        touched.insert(binding.base.repository.as_str());
        if let Some(head) = &binding.head {
            touched.insert(head.repository.as_str());
        }
    }
    if !principal.allows(TokenPerm::Features, touched) {
        return forbidden();
    }
    if feature.gate != crate::features::FeatureGate::Approved {
        return feature_error(StatusCode::CONFLICT, "feature.invalid_transition");
    }
    let repos = feature_repositories(&feature)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    emit_json(
        &state.events,
        "ci.started",
        repos.clone(),
        serde_json::json!({ "id": id, "title": feature.title }),
    );
    let Ok(job) = state.ci.run(&id, &request.repositories) else {
        emit_json(
            &state.events,
            "ci.finished",
            repos,
            serde_json::json!({ "id": id, "status": "failed" }),
        );
        return feature_error(StatusCode::CONFLICT, "ci.not_ready");
    };
    emit_json(
        &state.events,
        "ci.finished",
        repos,
        serde_json::json!({
            "id": id,
            "job_id": job.id,
            "status": job.status,
        }),
    );
    match state.ci.candidate_from_job(&job, request.repositories) {
        Ok(mut candidate) => {
            // insights-slice: advisory pre-flight after CI; never blocks the candidate.
            match state.insights.run(&id, &candidate.repositories) {
                Ok(bundle) => {
                    if let Ok(insights_ref) = state.insights.ref_for(&bundle) {
                        InsightsEngine::attach_to_candidate(&mut candidate, insights_ref);
                    }
                    emit_json(
                        &state.events,
                        "insights.ready",
                        feature_repositories(&feature).map(str::to_owned),
                        serde_json::json!({
                            "id": id,
                            "digest": bundle.digest,
                            "error": bundle.error,
                        }),
                    );
                }
                Err(error) => {
                    emit_json(
                        &state.events,
                        "insights.ready",
                        feature_repositories(&feature).map(str::to_owned),
                        serde_json::json!({
                            "id": id,
                            "error": error.to_string(),
                        }),
                    );
                }
            }
            match state.features.attach_candidate(&id, candidate) {
                Ok(feature) => {
                    emit_feature(&state.events, "candidate.submitted", &feature);
                    if let Some(dispatcher) = &state.review_dispatcher
                        && let Err(error) = dispatcher.queue(&feature)
                    {
                        eprintln!(
                            "loom: review dispatch preparation failed ({}): {error}",
                            feature.id
                        );
                    }
                    Json(feature).into_response()
                }
                Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
            }
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "ci.failed"),
    }
}

async fn get_insights(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let Ok(feature) = state.features.get(&id) else {
        return feature_error(StatusCode::NOT_FOUND, "feature.not_found");
    };
    if !principal.allows(TokenPerm::Evidence, feature_repositories(&feature)) {
        return forbidden();
    }
    match state.insights.bundle_for_feature(&feature) {
        Ok(bundle) => Json(bundle).into_response(),
        Err(_) => feature_error(StatusCode::NOT_FOUND, "insights.not_found"),
    }
}

async fn accept_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(feature) = state.features.get(&id) else {
        return feature_error(StatusCode::NOT_FOUND, "feature.not_found");
    };
    // review-slice
    if feature.evidence_policy.review_blocking && !state.reviews.blocking_ok(&id) {
        return feature_error(StatusCode::CONFLICT, "review.blocking");
    }
    let Some(candidate) = feature.candidate.as_ref() else {
        return feature_error(StatusCode::CONFLICT, "feature.candidate_missing");
    };
    if !candidate.evidence.tests_passed {
        return feature_error(StatusCode::CONFLICT, "ci.failed");
    }
    let Some(updates) = promotion_updates(&candidate.repositories) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "feature.bindings_invalid");
    };
    let grant = NamespaceGrant::new(
        updates
            .iter()
            .map(|update| update.repository.clone())
            .collect::<BTreeSet<_>>(),
    );
    let rollback = match state.store.compare_and_swap_refs(&grant, &updates) {
        Ok(rollback) => rollback,
        Err(LoomError::RefConflict { .. }) => {
            return feature_error(StatusCode::CONFLICT, "loom.ref_conflict");
        }
        Err(_) => return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "loom.promotion_invalid"),
    };
    emit_json(
        &state.events,
        "refs.moved",
        updates.iter().map(|update| update.repository.clone()),
        serde_json::json!({
            "refs": updates.iter().map(|update| serde_json::json!({
                "repo": update.repository,
                "ref_name": update.ref_name,
                "revision": update.head.revision,
            })).collect::<Vec<_>>(),
        }),
    );
    match state.features.accept(&id, rollback) {
        Ok(feature) => {
            emit_feature(&state.events, "feature.accepted", &feature);
            // origin-slice: Loom evidence is the deploy key; Origin is a backup mirror.
            record_origin_mirrors(&state.origin, candidate.evidence.tests_passed, &updates);
            Json(AcceptedFeature {
                feature,
                read_back: true,
            })
            .into_response()
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
    }
}

/// origin-slice: after `refs/main` CAS for loom|nero|grid, mint a release and queue a mirror.
fn record_origin_mirrors(
    origin: &OriginEngine,
    tests_passed: bool,
    updates: &[crate::RefCasUpdate],
) {
    for update in updates {
        if !OriginEngine::is_main_promotion(&update.ref_name)
            || !OriginEngine::is_allowlisted(&update.repository)
        {
            continue;
        }
        let git_oid = origin.git_oid_for_revision(&update.repository, &update.head);
        if let Some(oid) = git_oid.as_deref()
            && let Err(error) = origin.record_loom_release(&update.repository, oid, tests_passed)
        {
            eprintln!(
                "loom: origin release record failed for {}@{oid}: {error}",
                update.repository
            );
        }
        if let Err(error) = origin.queue_mirror(&update.repository, git_oid.as_deref()) {
            eprintln!(
                "loom: origin mirror queue failed for {}: {error}",
                update.repository
            );
        }
    }
}

async fn reject_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.features.reject(&id) {
        Ok(feature) => {
            emit_feature(&state.events, "feature.rejected", &feature);
            Json(feature).into_response()
        }
        Err(LoomError::UnknownRevision { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "feature.not_found")
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
    }
}

fn require_feature_access(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
) -> Result<Feature, Box<Response>> {
    require_feature_access_for(state, headers, id, &[TokenPerm::Features])
}

fn require_feature_access_for(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    permissions: &[TokenPerm],
) -> Result<Feature, Box<Response>> {
    let principal = resolve_principal(state, headers)?;
    let Ok(feature) = state.features.get(id) else {
        return Err(Box::new(feature_error(
            StatusCode::NOT_FOUND,
            "feature.not_found",
        )));
    };
    if !principal_allows_any(&principal, permissions, &feature) {
        return Err(Box::new(forbidden()));
    }
    Ok(feature)
}

fn principal_allows_any(
    principal: &Principal,
    permissions: &[TokenPerm],
    feature: &Feature,
) -> bool {
    permissions
        .iter()
        .any(|permission| principal.allows(*permission, feature_repositories(feature)))
}

fn review_result<T: Serialize>(result: Result<T, LoomError>, created: bool) -> Response {
    match result {
        Ok(value) if created => (StatusCode::CREATED, Json(value)).into_response(),
        Ok(value) => Json(value).into_response(),
        Err(LoomError::UnknownRevision { repository, .. }) if repository == "reviews" => {
            feature_error(StatusCode::NOT_FOUND, "review.not_found")
        }
        Err(LoomError::UnknownRevision { repository, .. }) if repository == "findings" => {
            feature_error(StatusCode::NOT_FOUND, "review.finding_not_found")
        }
        Err(LoomError::UnknownRevision { repository, .. }) if repository == "comments" => {
            feature_error(StatusCode::NOT_FOUND, "review.comment_not_found")
        }
        Err(LoomError::UnknownRevision { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "feature.not_found")
        }
        Err(LoomError::ResourceLimit) => {
            feature_error(StatusCode::PAYLOAD_TOO_LARGE, "review.too_large")
        }
        Err(LoomError::StorageUnavailable) => {
            feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable")
        }
        Err(LoomError::DuplicateSourceMutation { .. } | LoomError::InvalidPath { .. }) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "review.invalid")
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "review.conflict"),
    }
}

async fn create_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ReviewStart>,
) -> Response {
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    match state.reviews.start_or_get(&id, request) {
        Ok((review, created)) => {
            if created {
                emit_review(&state.events, "review.started", &feature, &review);
                for finding in &review.findings {
                    emit_review_finding(&state.events, &feature, &review, finding);
                }
                if review.status == ReviewStatus::Completed {
                    emit_review(&state.events, "review.completed", &feature, &review);
                }
            }
            review_result(Ok(review), created)
        }
        Err(error) => review_result::<crate::review::Review>(Err(error), false),
    }
}

async fn list_reviews(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        return *response;
    }
    review_result(state.reviews.list_for_feature(&id), false)
}

async fn append_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, rid)): AxumPath<(String, String)>,
    Json(request): Json<FindingsAppend>,
) -> Response {
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    let appended = request.findings.len();
    match state.reviews.append_findings(&id, &rid, request) {
        Ok(review) => {
            for finding in review
                .findings
                .iter()
                .skip(review.findings.len().saturating_sub(appended))
            {
                emit_review_finding(&state.events, &feature, &review, finding);
            }
            Json(review).into_response()
        }
        Err(LoomError::InvalidSourceCommit | LoomError::InvalidPath { .. }) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "review.invalid")
        }
        Err(error) => review_result::<crate::review::Review>(Err(error), false),
    }
}

async fn complete_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, rid)): AxumPath<(String, String)>,
    Json(request): Json<ReviewComplete>,
) -> Response {
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    let previous = state.reviews.get(&id, &rid).ok();
    match state.reviews.complete(&id, &rid, request) {
        Ok(review) => {
            let changed = previous.is_none_or(|previous| {
                previous.status != ReviewStatus::Completed || previous.verdict != review.verdict
            });
            if changed {
                emit_review(&state.events, "review.completed", &feature, &review);
            }
            Json(review).into_response()
        }
        Err(error) => review_result::<crate::review::Review>(Err(error), false),
    }
}

async fn approve_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, fid)): AxumPath<(String, String)>,
) -> Response {
    if let Err(response) = require_feature_access(&state, &headers, &id) {
        return *response;
    }
    review_result(state.reviews.approve_finding(&id, &fid), false)
}

async fn apply_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((id, fid)): AxumPath<(String, String)>,
    Json(request): Json<FindingApply>,
) -> Response {
    if let Err(response) = require_feature_access(&state, &headers, &id) {
        return *response;
    }
    review_result(state.reviews.apply_finding(&id, &fid, request), false)
}

async fn list_comments(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        return *response;
    }
    review_result(state.reviews.list_comments(&id), false)
}

async fn create_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<CommentCreate>,
) -> Response {
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    if matches!(
        &principal,
        Principal::Scoped(token)
            if token.perms.contains(&TokenPerm::Review)
                && !token.perms.contains(&TokenPerm::Features)
                && !request.author.starts_with("agent:")
    ) {
        return forbidden();
    }
    match state.reviews.add_comment(&id, request) {
        Ok(comment) => {
            emit_json(
                &state.events,
                "comment.added",
                feature_repositories(&feature).map(str::to_owned),
                serde_json::json!({
                    "id": feature.id,
                    "feature_id": feature.id,
                    "comment_id": comment.id,
                    "author": comment.author,
                    "finding_id": comment.finding_id,
                }),
            );
            (StatusCode::CREATED, Json(comment)).into_response()
        }
        Err(LoomError::InvalidSourceCommit) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "review.invalid")
        }
        Err(error) => review_result::<crate::review::Comment>(Err(error), false),
    }
}

#[derive(Serialize)]
struct AcceptedFeature {
    feature: Feature,
    read_back: bool,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    since: Option<String>,
    follow: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct EventsPage {
    events: Vec<Event>,
    cursor: String,
}

async fn list_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    if !principal.allows(TokenPerm::Events, std::iter::empty::<&str>()) {
        return forbidden();
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_CATCH_UP)
        .clamp(1, MAX_CATCH_UP);
    let follow = wants_follow(&query, &headers);
    let rx = state.events.subscribe();
    let Ok(scanned) = state.events.since(query.since.as_deref(), limit) else {
        return feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable");
    };
    // The cursor tracks the last *scanned* event, not the last visible one:
    // a page of events all filtered out for this principal must still advance
    // the cursor, or the caller polls the same invisible window forever.
    let cursor = scanned
        .last()
        .map(|event| event.id.clone())
        .or_else(|| query.since.clone())
        .unwrap_or_default();
    let catch_up = scanned
        .into_iter()
        .filter(|event| event_visible(&principal, event))
        .collect::<Vec<_>>();
    if !follow {
        return Json(EventsPage {
            events: catch_up,
            cursor,
        })
        .into_response();
    }
    let seen = catch_up
        .iter()
        .map(|event| event.id.clone())
        .collect::<BTreeSet<_>>();
    let catch_up_stream = stream::iter(catch_up.into_iter().filter_map(|event| sse_data(&event)));
    let live_stream = stream::unfold(
        (rx, seen, principal),
        |(mut rx, mut seen, principal)| async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if seen.insert(event.id.clone()) && event_visible(&principal, &event) {
                            return sse_data(&event).map(|item| (item, (rx, seen, principal)));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(catch_up_stream.chain(live_stream))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn wants_follow(query: &EventsQuery, headers: &HeaderMap) -> bool {
    let follow = query
        .follow
        .as_deref()
        .is_some_and(|value| matches!(value, "1" | "true" | "yes"));
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"));
    follow || accept
}

fn event_visible(principal: &Principal, event: &Event) -> bool {
    principal.allows(TokenPerm::Events, event.repos.iter().map(String::as_str))
}

fn sse_data(event: &Event) -> Option<Result<SseEvent, std::convert::Infallible>> {
    serde_json::to_string(event)
        .ok()
        .map(|data| Ok(SseEvent::default().data(data)))
}

fn emit_feature(events: &EventLog, kind: &str, feature: &Feature) {
    emit_json(
        events,
        kind,
        feature_repositories(feature).map(str::to_owned),
        serde_json::json!({
            "id": feature.id,
            "title": feature.title,
            "gate": feature.gate,
            "candidate_id": feature.candidate.as_ref().map(|candidate| &candidate.id),
        }),
    );
}

fn emit_review(events: &EventLog, kind: &str, feature: &Feature, review: &crate::review::Review) {
    emit_json(
        events,
        kind,
        feature_repositories(feature).map(str::to_owned),
        serde_json::json!({
            "id": feature.id,
            "feature_id": feature.id,
            "review_id": review.id,
            "candidate_id": review.candidate_id,
            "status": review.status,
            "verdict": review.verdict,
        }),
    );
}

fn emit_review_finding(
    events: &EventLog,
    feature: &Feature,
    review: &crate::review::Review,
    finding: &crate::review::Finding,
) {
    emit_json(
        events,
        "review.finding",
        feature_repositories(feature).map(str::to_owned),
        serde_json::json!({
            "id": feature.id,
            "feature_id": feature.id,
            "review_id": review.id,
            "candidate_id": review.candidate_id,
            "finding_id": finding.id,
            "severity": finding.severity,
            "repo": finding.repo,
            "path": finding.path,
        }),
    );
}

fn emit_json(
    events: &EventLog,
    kind: &str,
    repos: impl IntoIterator<Item = impl Into<String>>,
    payload: serde_json::Value,
) {
    if let Err(error) = events.emit(kind, repos, payload) {
        eprintln!("loom: event emit failed ({kind}): {error}");
    }
}

fn feature_error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            code: code.to_owned(),
            message: code.to_owned(),
        }),
    )
        .into_response()
}

/// Helper used by docs; the native RPC remains mounted at `/loom/v1/*`.
#[must_use]
pub fn native_rpc_prefix() -> &'static str {
    "/loom/v1"
}

/// Dataset path helper.
#[must_use]
pub fn dataset_root(root: &Path) -> &Path {
    root
}

/// Unused atomic result alias for documentation.
pub type PromotionResult = AtomicRefResult;
