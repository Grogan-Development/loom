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
    routing::{get, post},
};
use futures_util::stream::{self, StreamExt as _};
use serde::{Deserialize, Serialize};

use crate::agent::AgentConfig;
use crate::app::{AppCreate, EnvAction, pin_environment, rollback_environment};
use crate::auth::{AccessToken, bearer_token};
use crate::backup::{backup, restore};
use crate::catalog::{RepoCatalog, RepoUpsert};
use crate::ci::CiEngine;
use crate::contracts::RepositoryRevision;
use crate::control::ControlStore;
use crate::dashboard::StatusPage;
use crate::events::{DEFAULT_CATCH_UP, Event, EventLog, MAX_CATCH_UP};
use crate::features::{
    CandidateSubmit, Feature, FeatureClass, FeatureCreate, FeatureStore, promotion_updates,
};
use crate::git::{GitBridge, GitHttpGateway};
use crate::import::ImportRequest;
use crate::insights::InsightsEngine; // insights-slice
use crate::maintain::{MaintainStatus, enqueue, ensure_maintain_bot};
use crate::origin::{OriginCiRequest, OriginConfig, OriginEngine, OriginEvidence, OriginMirrorJob};
use crate::project::{PauseRequest, ProjectUpsert};
use crate::review::{
    CommentCreate, FindingApply, FindingsAppend, ReviewComplete, ReviewStart, ReviewStatus,
    ReviewStore,
};
use crate::review_runner::{ReviewDispatcher, ReviewRunnerConfig};
use crate::secrets::{SecretStore, SecretUpsert};
use crate::tokens::{Authority, Principal, TokenMint, TokenPerm, TokenStore};
use crate::webhook::WebhookCreate;
use crate::{LoomError, LoomRpc, NamespaceGrant, PersistentLoomStore};
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
    catalog: RepoCatalog,
    git_bridge: Option<GitBridge>,
    store: PersistentLoomStore,
    events: EventLog, // events-slice
    review_dispatcher: Option<ReviewDispatcher>,
    control: ControlStore,
    secrets: SecretStore,
    agent: AgentConfig,
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
    #[allow(clippy::too_many_lines)]
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
        let origin = OriginEngine::new(store.clone(), config.origin);
        let catalog = origin.catalog().clone();
        catalog.ensure_seeded()?;
        let git_bridge =
            GitBridge::new(store.clone(), &config.git_program, &config.hook_program).ok();
        let git_router = git_bridge.clone().map_or_else(Router::new, |bridge| {
            GitHttpGateway::new(bridge, authority.clone(), catalog.clone()).router()
        });
        let events = EventLog::new(store.clone()); // events-slice
        let review_dispatcher = config.review_runner.map(|review_runner| {
            ReviewDispatcher::new(
                review_runner,
                authority.clone(),
                features.clone(),
                reviews.clone(),
                events.clone(),
            )
        });
        if let Some(dispatcher) = &review_dispatcher {
            dispatcher.recover()?;
        }
        let control = ControlStore::new(store.clone());
        let secrets_key = std::env::var("LOOM_SECRETS_KEY").unwrap_or_default();
        let secrets = SecretStore::new(store.clone(), &secrets_key);
        let agent = AgentConfig::from_env();
        if !secrets_key.is_empty()
            && let Ok(Some(path)) = ensure_maintain_bot(&store, authority.tokens())
        {
            eprintln!("loom: maintain bot token written to {path}");
        }
        let state = AppState {
            token: config.token,
            deploy_token: config.deploy_token,
            authority,
            features,
            reviews,
            ci,
            insights,
            origin,
            catalog,
            git_bridge,
            store,
            events,
            review_dispatcher,
            control,
            secrets,
            agent,
        };
        let api = Router::new()
            .route("/", get(dashboard))
            .route("/status", get(dashboard))
            .route("/healthz", get(healthz))
            .route("/v1/tokens", get(list_tokens).post(mint_token))
            .route("/v1/tokens/{id}", get(get_token).delete(revoke_token))
            .route("/v1/repos", get(list_repos).post(upsert_repo))
            .route("/v1/repos/import", post(import_repo))
            .route("/v1/repos/{*name}", get(get_repo).delete(delete_repo))
            .route("/loom/v1/refs/bootstrap", post(bootstrap_ref))
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
            .route("/v1/projects", get(list_projects).post(upsert_project))
            .route(
                "/v1/projects/{name}",
                get(get_project).delete(delete_project),
            )
            .route("/v1/projects/{name}/pause", post(pause_project))
            .route(
                "/v1/projects/{name}/secrets",
                get(list_secrets).post(upsert_secret),
            )
            .route("/v1/search", get(search_repo))
            .route("/v1/compare", post(compare_revisions))
            .route("/v1/tree", post(tree_revision))
            .route("/v1/blob", post(blob_revision))
            .route("/v1/apps", get(list_apps).post(create_app))
            .route("/v1/apps/gc", post(gc_apps))
            .route("/v1/apps/promote", post(promote_app))
            .route("/v1/apps/rollback", post(rollback_app))
            .route("/v1/apps/{*id}", get(get_app))
            .route("/v1/maintain", get(maintain_status))
            .route("/v1/webhooks", get(list_webhooks).post(create_webhook))
            .route("/v1/backup", post(create_backup))
            .route("/v1/restore", post(restore_backup))
            .route("/v1/mcp", get(mcp_manifest).post(mcp_call))
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
        Ok(Err(LoomError::UnknownRevision { .. })) => {
            feature_error(StatusCode::NOT_FOUND, "origin.revision_unknown")
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
        Ok(Err(LoomError::DeployUnconfigured { .. })) => {
            feature_error(StatusCode::CONFLICT, "origin.deploy_unconfigured")
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

/// Every repository a candidate submission touches: the feature's bindings
/// plus the submitted bases and heads.
fn candidate_repositories<'a>(
    feature: &'a Feature,
    request: &'a CandidateSubmit,
) -> BTreeSet<&'a str> {
    let mut touched = feature_repositories(feature).collect::<BTreeSet<_>>();
    for binding in &request.repositories {
        touched.insert(binding.base.repository.as_str());
        if let Some(head) = &binding.head {
            touched.insert(head.repository.as_str());
        }
    }
    touched
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

/// Owner-only reconciliation read: exists, repos, perms, feature/review
/// binding, expiry, and revocation for one token id. Never returns secrets;
/// the durable record carries only the SHA-256 hash.
async fn get_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.authority.tokens().get(&id) {
        Ok(Some(token)) => Json(token).into_response(),
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "token.not_found"),
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

async fn list_repos(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.catalog.list() {
        Ok(entries) => Json(entries).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn upsert_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RepoUpsert>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(entry) = request.into_entry() else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "repo.invalid");
    };
    match state.catalog.upsert(entry) {
        Ok(entry) => (StatusCode::CREATED, Json(entry)).into_response(),
        Err(LoomError::ResourceLimit) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "repo.invalid")
        }
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn get_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.catalog.get(&name) {
        Ok(Some(entry)) => Json(entry).into_response(),
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "repo.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

async fn delete_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.catalog.remove(&name) {
        Ok(removed) => Json(removed).into_response(),
        Err(LoomError::UnknownRepo { .. }) => feature_error(StatusCode::NOT_FOUND, "repo.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable"),
    }
}

/// Requires every repository to be registered in the durable repo catalog.
/// Unknown repositories read as 404; storage failures fail closed as 503.
fn require_registered<'a>(
    state: &AppState,
    repositories: impl IntoIterator<Item = &'a str>,
) -> Result<(), Box<Response>> {
    for repository in repositories {
        match state.catalog.get(repository) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(Box::new(feature_error(
                    StatusCode::NOT_FOUND,
                    "repo.unknown",
                )));
            }
            Err(_) => {
                return Err(Box::new(feature_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "loom.storage_unavailable",
                )));
            }
        }
    }
    Ok(())
}

/// Request body for the owner-only `POST /loom/v1/refs/bootstrap`.
///
/// Exactly one of `revision` (native snapshot) or `git_oid` (Git-imported
/// commit resolved through the durable oid↔revision mapping) is required.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    #[serde(alias = "repository")]
    repo: String,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    git_oid: Option<String>,
}

#[derive(Serialize)]
struct BootstrapResponse {
    repo: String,
    ref_name: String,
    revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_oid: Option<String>,
    created: bool,
    read_back: bool,
}

/// Owner-only, idempotent creation of the initial protected ref from an
/// already-imported revision. Never moves an existing ref: a protected ref
/// at a different revision is a 409.
async fn bootstrap_ref(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BootstrapRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let entry = match state.catalog.get(&request.repo) {
        Ok(Some(entry)) => entry,
        Ok(None) => return feature_error(StatusCode::NOT_FOUND, "repo.unknown"),
        Err(_) => {
            return feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable");
        }
    };
    let revision = match bootstrap_revision(&state, &request) {
        Ok(revision) => revision,
        Err(response) => return *response,
    };
    let grant = NamespaceGrant::new(BTreeSet::from([request.repo.clone()]));
    let created =
        match state
            .store
            .create_ref(&grant, &request.repo, &entry.protected_ref, &revision)
        {
            Ok(()) => true,
            Err(LoomError::RefConflict { .. }) => false,
            Err(LoomError::UnknownRevision { .. }) => {
                return feature_error(StatusCode::NOT_FOUND, "revision.unknown");
            }
            Err(LoomError::InvalidRef { .. } | LoomError::InvalidRepository { .. }) => {
                return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "bootstrap.invalid");
            }
            Err(_) => {
                return feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable");
            }
        };
    // Exact read-back: the protected ref must resolve to the requested
    // revision whether it was just created or already existed. Anything else
    // is a conflict the owner has to resolve explicitly.
    match state
        .store
        .resolve_ref(&grant, &request.repo, &entry.protected_ref)
    {
        Ok(current) if current == revision => {}
        Ok(_) => return feature_error(StatusCode::CONFLICT, "loom.ref_conflict"),
        Err(_) => {
            return feature_error(StatusCode::SERVICE_UNAVAILABLE, "loom.storage_unavailable");
        }
    }
    if created {
        emit_json(
            &state.events,
            "refs.bootstrapped",
            [request.repo.clone()],
            serde_json::json!({
                "repo": request.repo,
                "ref_name": entry.protected_ref,
                "revision": revision.revision,
                "git_oid": request.git_oid,
                "source": if request.git_oid.is_some() { "git" } else { "revision" },
            }),
        );
    }
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(BootstrapResponse {
            repo: request.repo,
            ref_name: entry.protected_ref,
            revision: revision.revision,
            git_oid: request.git_oid,
            created,
            read_back: true,
        }),
    )
        .into_response()
}

/// Resolves the requested bootstrap source to a revision Loom already holds.
fn bootstrap_revision(
    state: &AppState,
    request: &BootstrapRequest,
) -> Result<RepositoryRevision, Box<Response>> {
    match (&request.revision, &request.git_oid) {
        (Some(revision), None) => RepositoryRevision::new(&request.repo, revision).map_err(|_| {
            Box::new(feature_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "bootstrap.invalid",
            ))
        }),
        (None, Some(git_oid)) => {
            let Some(bridge) = &state.git_bridge else {
                return Err(Box::new(feature_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "loom.git_unavailable",
                )));
            };
            let grant = NamespaceGrant::new(BTreeSet::from([request.repo.clone()]));
            bridge
                .revision_for_git_oid(&grant, &request.repo, git_oid)
                .map_err(|_| Box::new(feature_error(StatusCode::NOT_FOUND, "revision.unknown")))
        }
        _ => Err(Box::new(feature_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bootstrap.invalid",
        ))),
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
    if request.class == FeatureClass::Maintenance {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "feature.invalid");
    }
    if !principal.allows(
        TokenPerm::Features,
        request
            .repositories
            .iter()
            .map(|binding| binding.base.repository.as_str()),
    ) {
        return forbidden();
    }
    if let Err(response) = require_registered(
        &state,
        request
            .repositories
            .iter()
            .map(|binding| binding.base.repository.as_str()),
    ) {
        return *response;
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
    let touched = candidate_repositories(&feature, &request);
    if !principal.allows(TokenPerm::Features, touched.iter().copied()) {
        return forbidden();
    }
    if let Err(response) = require_registered(&state, touched) {
        return *response;
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
    if !principal.allows_feature(
        TokenPerm::Evidence,
        feature_repositories(&feature),
        &feature.id,
    ) {
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
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let Ok(feature) = state.features.get(&id) else {
        return feature_error(StatusCode::NOT_FOUND, "feature.not_found");
    };
    let repos = feature_repositories(&feature).collect::<Vec<_>>();
    let may_accept = match feature.class {
        FeatureClass::Product => principal.is_owner(),
        FeatureClass::Maintenance => principal.allows_maintain(repos),
    };
    if !may_accept {
        return unauthorized();
    }
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

/// origin-slice: after a protected-ref CAS on a registered repository, mint a
/// release and queue a mirror. The repo catalog decides which ref is protected.
fn record_origin_mirrors(
    origin: &OriginEngine,
    tests_passed: bool,
    updates: &[crate::RefCasUpdate],
) {
    for update in updates {
        let Ok(Some(entry)) = origin.catalog().get(&update.repository) else {
            continue;
        };
        if update.ref_name != entry.protected_ref {
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
    permissions.iter().any(|permission| {
        principal.allows_feature(*permission, feature_repositories(feature), &feature.id)
    })
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
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    if let Some((bound_feature, bound_review)) = principal.review_binding() {
        if bound_feature != id {
            return forbidden();
        }
        return review_result(state.reviews.get(&id, bound_review), false);
    }
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
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    if !principal.allows_review(feature_repositories(&feature), &id, &rid) {
        return forbidden();
    }
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
    let principal = match resolve_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let feature = match require_feature_access_for(
        &state,
        &headers,
        &id,
        &[TokenPerm::Features, TokenPerm::Review],
    ) {
        Ok(feature) => feature,
        Err(response) => return *response,
    };
    if !principal.allows_review(feature_repositories(&feature), &id, &rid) {
        return forbidden();
    }
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

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match StatusPage::load(&state.control, &state.events, state.agent.configured()) {
        Ok(page) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            page.render(),
        )
            .into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn list_projects(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.list_projects() {
        Ok(projects) => Json(projects).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn upsert_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProjectUpsert>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(project) = request.into_project() else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "project.invalid");
    };
    match state.control.upsert_project(project) {
        Ok(project) => (StatusCode::CREATED, Json(project)).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.get_project(&name) {
        Ok(Some(project)) => Json(project).into_response(),
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "project.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn delete_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.delete_project(&name) {
        Ok(project) => Json(project).into_response(),
        Err(LoomError::UnknownProject { .. }) => {
            feature_error(StatusCode::NOT_FOUND, "project.unknown")
        }
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn pause_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(request): Json<PauseRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.get_project(&name) {
        Ok(Some(mut project)) => {
            project.maintain_policy.paused = request.paused;
            match state.control.upsert_project(project) {
                Ok(project) => Json(project).into_response(),
                Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
            }
        }
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "project.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.secrets.list(&name) {
        Ok(records) => Json(records).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn upsert_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(mut request): Json<SecretUpsert>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    request.project = name;
    match state.secrets.upsert(request) {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(LoomError::InvalidControl | LoomError::ResourceLimit) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "secret.invalid")
        }
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn import_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ImportRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let workdir = state.store.root.join("import-work");
    let create_app = request.app;
    let arm_maintain = request.maintain;
    match crate::import::import(
        &state.store,
        &state.catalog,
        state.git_bridge.as_ref(),
        &workdir,
        &request,
    ) {
        Ok(result) => {
            if create_app && result.flags.create_app {
                let files = state
                    .store
                    .materialize(
                        &NamespaceGrant::new([result.repo.clone()].into_iter().collect()),
                        &RepositoryRevision::new(&result.repo, &result.revision).unwrap_or_else(
                            |_| RepositoryRevision {
                                repository: result.repo.clone(),
                                revision: result.revision.clone(),
                            },
                        ),
                    )
                    .unwrap_or_default();
                if let Ok(app) = (AppCreate {
                    project: result
                        .repo
                        .split_once('/')
                        .map_or_else(|| result.repo.clone(), |(project, _)| project.to_owned()),
                    name: result
                        .repo
                        .split_once('/')
                        .map_or_else(|| result.repo.clone(), |(_, name)| name.to_owned()),
                    repo: Some(result.repo.clone()),
                    kind: None,
                    start: Vec::new(),
                })
                .into_record(&files)
                {
                    let _ = state.control.upsert_app(app);
                }
            }
            if arm_maintain && result.flags.arm_maintain {
                let _ = enqueue(
                    &state.control,
                    &result.repo,
                    if result.flags.needs_legacy {
                        "runtime"
                    } else {
                        "deps"
                    },
                    "import",
                    state.agent.configured(),
                );
            }
            (StatusCode::CREATED, Json(result)).into_response()
        }
        Err(LoomError::InvalidControl | LoomError::InvalidRepository { .. }) => {
            feature_error(StatusCode::UNPROCESSABLE_ENTITY, "import.invalid")
        }
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "import.failed"),
    }
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    repo: String,
    revision: String,
}

async fn search_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(revision) = RepositoryRevision::new(&query.repo, &query.revision) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "search.invalid");
    };
    let grant = NamespaceGrant::new([query.repo.clone()].into_iter().collect());
    match crate::search::search(&state.store, &grant, &revision, &query.q, 50) {
        Ok(hits) => Json(hits).into_response(),
        Err(_) => feature_error(StatusCode::NOT_FOUND, "search.miss"),
    }
}

#[derive(Deserialize)]
struct RevisionPair {
    repo: String,
    base: String,
    head: String,
}

async fn compare_revisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevisionPair>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(base) = RepositoryRevision::new(&request.repo, &request.base) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "compare.invalid");
    };
    let Ok(head) = RepositoryRevision::new(&request.repo, &request.head) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "compare.invalid");
    };
    let grant = NamespaceGrant::new([request.repo].into_iter().collect());
    match crate::search::compare(&state.store, &grant, &base, &head) {
        Ok(delta) => Json(delta).into_response(),
        Err(_) => feature_error(StatusCode::NOT_FOUND, "compare.miss"),
    }
}

#[derive(Deserialize)]
struct RevisionRef {
    repo: String,
    revision: String,
    #[serde(default)]
    path: String,
}

async fn tree_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevisionRef>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(revision) = RepositoryRevision::new(&request.repo, &request.revision) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "tree.invalid");
    };
    let grant = NamespaceGrant::new([request.repo].into_iter().collect());
    match crate::search::tree(&state.store, &grant, &revision) {
        Ok(entries) => Json(entries).into_response(),
        Err(_) => feature_error(StatusCode::NOT_FOUND, "tree.miss"),
    }
}

async fn blob_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevisionRef>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let Ok(revision) = RepositoryRevision::new(&request.repo, &request.revision) else {
        return feature_error(StatusCode::UNPROCESSABLE_ENTITY, "blob.invalid");
    };
    let grant = NamespaceGrant::new([request.repo].into_iter().collect());
    match crate::search::blob(&state.store, &grant, &revision, &request.path) {
        Ok(bytes) => bytes.into_response(),
        Err(_) => feature_error(StatusCode::NOT_FOUND, "blob.miss"),
    }
}

async fn list_apps(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.list_apps() {
        Ok(apps) => Json(apps).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn create_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AppCreate>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let files = request
        .repo
        .as_ref()
        .map_or_else(std::collections::BTreeMap::new, |repo| {
            state
                .catalog
                .get(repo)
                .ok()
                .flatten()
                .and_then(|entry| {
                    let grant = NamespaceGrant::new([repo.clone()].into_iter().collect());
                    state
                        .store
                        .resolve_ref(&grant, repo, &entry.protected_ref)
                        .ok()
                        .and_then(|revision| state.store.materialize(&grant, &revision).ok())
                })
                .unwrap_or_default()
        });
    match request.into_record(&files) {
        Ok(app) => match state.control.upsert_app(app) {
            Ok(app) => (StatusCode::CREATED, Json(app)).into_response(),
            Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
        },
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "app.invalid"),
    }
}

async fn get_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.get_app(&id) {
        Ok(Some(app)) => Json(app).into_response(),
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "app.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn promote_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(action): Json<EnvAction>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.get_app(&action.id) {
        Ok(Some(mut app)) => {
            let digest = app
                .environments
                .get("staging")
                .map(|env| env.image_digest.clone())
                .unwrap_or_default();
            if digest.is_empty() {
                return feature_error(StatusCode::CONFLICT, "app.image_missing");
            }
            pin_environment(&mut app, &action.environment, &digest, true);
            match state.control.upsert_app(app) {
                Ok(app) => Json(app).into_response(),
                Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
            }
        }
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "app.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn rollback_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(action): Json<EnvAction>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.get_app(&action.id) {
        Ok(Some(mut app)) => match rollback_environment(&mut app, &action.environment) {
            Ok(_) => match state.control.upsert_app(app) {
                Ok(app) => Json(app).into_response(),
                Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
            },
            Err(LoomError::ImageMissing) => {
                feature_error(StatusCode::CONFLICT, "app.image_missing")
            }
            Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "app.invalid"),
        },
        Ok(None) => feature_error(StatusCode::NOT_FOUND, "app.unknown"),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn gc_apps(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    feature_error(StatusCode::NOT_IMPLEMENTED, "app.gc_unimplemented")
}

async fn maintain_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.list_jobs() {
        Ok(jobs) => Json(MaintainStatus {
            agent_configured: state.agent.configured(),
            jobs,
        })
        .into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn list_webhooks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match state.control.list_webhooks() {
        Ok(hooks) => Json(hooks).into_response(),
        Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
    }
}

async fn create_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WebhookCreate>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match request.into_endpoint() {
        Ok(hook) => match state.control.upsert_webhook(hook) {
            Ok(hook) => (StatusCode::CREATED, Json(hook)).into_response(),
            Err(_) => feature_error(StatusCode::SERVICE_UNAVAILABLE, "control.unavailable"),
        },
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "webhook.invalid"),
    }
}

#[derive(Deserialize)]
struct BackupRequest {
    destination: String,
}

async fn create_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BackupRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match backup(&state.store, Path::new(&request.destination)) {
        Ok(path) => Json(serde_json::json!({ "path": path })).into_response(),
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "backup.failed"),
    }
}

async fn restore_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BackupRequest>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    match restore(&state.store, Path::new(&request.destination)) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(_) => feature_error(StatusCode::UNPROCESSABLE_ENTITY, "restore.failed"),
    }
}

async fn mcp_manifest(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    Json(serde_json::json!({
        "name": "loom",
        "tools": [
            "repo", "git", "feature", "candidate", "evidence",
            "events", "token", "project", "app", "maintain"
        ]
    }))
    .into_response()
}

#[derive(Deserialize)]
struct McpCall {
    tool: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

async fn mcp_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(call): Json<McpCall>,
) -> Response {
    if let Err(response) = require_token(&state, &headers) {
        return *response;
    }
    let _ = (call.tool, call.arguments);
    feature_error(StatusCode::NOT_IMPLEMENTED, "mcp.call_unimplemented")
}
