//! Combined standalone Loom HTTP surface: CAS RPC, features, CI, and Git.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Serialize;

use crate::auth::{AccessToken, bearer_token};
use crate::ci::CiEngine;
use crate::features::{CandidateSubmit, Feature, FeatureCreate, FeatureStore, promotion_updates};
use crate::git::{GitBridge, GitHttpGateway};
use crate::origin::{OriginCiRequest, OriginConfig, OriginEngine, OriginEvidence};
use crate::tokens::{Authority, Principal, TokenMint, TokenPerm, TokenStore};
use crate::{AtomicRefResult, LoomError, LoomRpc, NamespaceGrant, PersistentLoomStore};

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
}

#[derive(Clone)]
struct AppState {
    token: AccessToken,
    deploy_token: Option<AccessToken>,
    authority: Authority,
    features: FeatureStore,
    ci: CiEngine,
    origin: OriginEngine,
    store: PersistentLoomStore,
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
        let ci = CiEngine::new(store.clone());
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
        let state = AppState {
            token: config.token,
            deploy_token: config.deploy_token,
            authority,
            features,
            ci,
            origin,
            store,
        };
        let api = Router::new()
            .route("/healthz", get(healthz))
            .route("/v1/tokens", get(list_tokens).post(mint_token))
            .route("/v1/tokens/{id}", delete(revoke_token))
            .route("/v1/features", get(list_features).post(create_feature))
            .route("/v1/features/{id}", get(get_feature))
            .route("/v1/features/{id}/approve", post(approve_feature))
            .route("/v1/features/{id}/candidates", post(submit_candidate))
            .route("/v1/features/{id}/accept", post(accept_feature))
            .route("/v1/features/{id}/reject", post(reject_feature))
            .route("/v1/origin/webhook", post(origin_webhook))
            .route("/v1/releases/{repo}/ci", post(origin_start_ci))
            .route("/v1/releases/{repo}/{oid}", get(origin_get_release))
            .route(
                "/v1/releases/{repo}/{oid}/deploy",
                post(origin_deploy_release),
            )
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
    if state
        .origin
        .verify_webhook(webhook_id, timestamp, signature, &body)
        .await
        .is_err()
    {
        return unauthorized();
    }
    // Receipt log for verified deliveries: non-CI events (installation.*,
    // pull_request.closed, ...) would otherwise leave no operational trace.
    let excerpt: String = String::from_utf8_lossy(&body).chars().take(2000).collect();
    eprintln!(
        "loom: origin webhook verified ({} bytes): {excerpt}",
        body.len()
    );
    let origin = state.origin.clone();
    let targets = OriginEngine::targets_from_webhook(&body);
    tokio::spawn(async move {
        for (repository, oid) in targets {
            let job = origin.clone();
            match tokio::task::spawn_blocking(move || job.run_ci(&repository, &oid)).await {
                Ok(Ok(release)) => origin.publish_check(&release).await,
                Ok(Err(error)) => eprintln!("loom: origin webhook ci failed: {error}"),
                Err(error) => eprintln!("loom: origin webhook join failed: {error}"),
            }
        }
    });
    StatusCode::ACCEPTED.into_response()
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
        Ok(Ok(release)) => {
            state.origin.publish_check(&release).await;
            Json(OriginEvidence::from(&release)).into_response()
        }
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
                    principal.allows(TokenPerm::Features, feature_repositories(feature))
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
        Ok(feature) => (StatusCode::CREATED, Json(feature)).into_response(),
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
            if principal.allows(TokenPerm::Features, feature_repositories(&feature)) {
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
        Ok(feature) => Json(feature).into_response(),
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
    let Ok(job) = state.ci.run(&id, &request.repositories) else {
        return feature_error(StatusCode::CONFLICT, "ci.not_ready");
    };
    match state.ci.candidate_from_job(&job, request.repositories) {
        Ok(candidate) => match state.features.attach_candidate(&id, candidate) {
            Ok(feature) => Json(feature).into_response(),
            Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
        },
        Err(_) => feature_error(StatusCode::CONFLICT, "ci.failed"),
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
    match state.features.accept(&id, rollback) {
        Ok(feature) => Json(AcceptedFeature {
            feature,
            read_back: true,
        })
        .into_response(),
        Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
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
        Ok(feature) => Json(feature).into_response(),
        Err(LoomError::UnknownRevision { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "feature.not_found")
        }
        Err(_) => feature_error(StatusCode::CONFLICT, "feature.invalid_transition"),
    }
}

#[derive(Serialize)]
struct AcceptedFeature {
    feature: Feature,
    read_back: bool,
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
