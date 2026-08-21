//! Asynchronous dispatch of candidate reviews to isolated Grid Nero runners.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use thiserror::Error;

use crate::LoomError;
use crate::events::EventLog;
use crate::features::{Feature, FeatureStore};
use crate::grid_runner::{CreateRunnerRequest, GridRepo, GridRunner, GridRunnerError};
use crate::review::{
    CommentCreate, Review, ReviewComplete, ReviewStatus, ReviewStore, ReviewVerdict,
};
use crate::tokens::{Authority, TokenMint, TokenPerm};

const DEFAULT_REVIEW_TIMEOUT_SECS: u64 = 900;
const MAX_REVIEW_TIMEOUT_SECS: u64 = 1800;
const TOKEN_GRACE_SECS: u64 = 300;
const MAX_FAILURE_MESSAGE: usize = 2048;

/// Validated configuration for one dedicated Grid review-Nero backend.
#[derive(Clone)]
pub struct ReviewRunnerConfig {
    grid: GridRunner,
    loom_url: String,
    command: Vec<String>,
    timeout_secs: u64,
}

impl std::fmt::Debug for ReviewRunnerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReviewRunnerConfig")
            .field("grid", &self.grid)
            .field("loom_url", &self.loom_url)
            .field("command", &self.command)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// Invalid review-runner configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReviewRunnerConfigError {
    /// A required service URL or token is empty or malformed.
    #[error("review runner service configuration is invalid")]
    Service,
    /// The command is not a safe, explicit Nero review command.
    #[error("LOOM_REVIEW_COMMAND_JSON must be a safe Nero argv")]
    Command,
    /// The configured timeout exceeds Grid's runner contract.
    #[error("review runner timeout must be between 1 and 1800 seconds")]
    Timeout,
}

impl ReviewRunnerConfig {
    /// Builds an explicit Grid/Nero review contract.
    ///
    /// `command` is an argv, not a shell string. Its executable must be
    /// `nero`; auto-approval and permission-bypass modes are rejected.
    ///
    /// # Errors
    ///
    /// Returns for malformed URLs, empty credentials, unsafe commands, or an
    /// out-of-range timeout.
    pub fn new(
        grid_url: impl Into<String>,
        grid_internal_token: impl Into<String>,
        loom_url: impl Into<String>,
        command: Vec<String>,
        timeout_secs: u64,
    ) -> Result<Self, ReviewRunnerConfigError> {
        let grid_url = normalized_service_url(&grid_url.into())?;
        let loom_url = normalized_service_url(&loom_url.into())?;
        let grid = GridRunner::new(grid_url, grid_internal_token.into())
            .map_err(|_| ReviewRunnerConfigError::Service)?;
        if !safe_review_command(&command) {
            return Err(ReviewRunnerConfigError::Command);
        }
        let timeout_secs = if timeout_secs == 0 {
            DEFAULT_REVIEW_TIMEOUT_SECS
        } else {
            timeout_secs
        };
        if timeout_secs > MAX_REVIEW_TIMEOUT_SECS {
            return Err(ReviewRunnerConfigError::Timeout);
        }
        Ok(Self {
            grid,
            loom_url,
            command,
            timeout_secs,
        })
    }
}

/// Candidate-review dispatcher bound to one Loom dataset and Grid backend.
#[derive(Clone)]
pub struct ReviewDispatcher {
    config: ReviewRunnerConfig,
    authority: Authority,
    features: FeatureStore,
    reviews: ReviewStore,
    events: EventLog,
}

impl ReviewDispatcher {
    /// Creates a dispatcher over the server's shared stores.
    #[must_use]
    pub const fn new(
        config: ReviewRunnerConfig,
        authority: Authority,
        features: FeatureStore,
        reviews: ReviewStore,
        events: EventLog,
    ) -> Self {
        Self {
            config,
            authority,
            features,
            reviews,
            events,
        }
    }

    /// Persists a review, mints its short-lived credential, and dispatches Grid
    /// work without delaying the candidate response.
    ///
    /// Re-submitting the same immutable candidate is idempotent: the existing
    /// review is returned and no duplicate runner is created.
    ///
    /// # Errors
    ///
    /// Returns when the candidate has no exact head, or review/token state
    /// cannot be persisted.
    pub fn queue(&self, feature: &Feature) -> Result<Review, LoomError> {
        let candidate = feature
            .candidate
            .as_ref()
            .ok_or(LoomError::InvalidSourceCommit)?;
        if candidate
            .repositories
            .iter()
            .any(|binding| binding.head.is_none())
        {
            return Err(LoomError::InvalidSourceCommit);
        }
        let (review, created) = self.reviews.start_runner_review(&feature.id)?;
        if !created {
            return Ok(review);
        }

        let job_id = review
            .runner_job_id
            .clone()
            .ok_or(LoomError::InvalidSourceCommit)?;
        self.emit_started(feature, &review, &job_id);
        self.dispatch(feature, &review)?;
        Ok(review)
    }

    /// Resumes monitoring or dispatch for durable automatic reviews left
    /// incomplete by a Loom process restart.
    ///
    /// # Errors
    ///
    /// Returns when durable feature or review state cannot be read.
    pub fn recover(&self) -> Result<usize, LoomError> {
        let mut recovered = 0;
        for feature in self.features.list()? {
            for review in self.reviews.list_for_feature(&feature.id)? {
                if review.status == ReviewStatus::Completed || review.runner_job_id.is_none() {
                    continue;
                }
                self.spawn_recovery(feature.clone(), review);
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    fn dispatch(&self, feature: &Feature, review: &Review) -> Result<(), LoomError> {
        let candidate = feature
            .candidate
            .as_ref()
            .ok_or(LoomError::InvalidSourceCommit)?;
        if candidate.id != review.candidate_id {
            self.finish_failed(feature, review, "review candidate no longer matches");
            return Err(LoomError::InvalidSourceCommit);
        }
        self.revoke_review_tokens(review);
        let repositories = candidate
            .repositories
            .iter()
            .map(|binding| binding.base.repository.clone())
            .collect::<BTreeSet<_>>();
        let minted = match self.authority.tokens().mint(&TokenMint {
            name: format!("review-{}", review.id),
            repositories: repositories.into_iter().collect(),
            perms: vec![TokenPerm::Evidence, TokenPerm::Review],
            feature_id: Some(feature.id.clone()),
            review_id: Some(review.id.clone()),
            expires_at: Some(
                unix_now()
                    .saturating_add(self.config.timeout_secs)
                    .saturating_add(TOKEN_GRACE_SECS),
            ),
        }) {
            Ok(minted) => minted,
            Err(error) => {
                self.finish_failed(feature, review, "review credential mint failed");
                return Err(error);
            }
        };
        let request = match self.runner_request(feature, review, &minted.secret) {
            Ok(request) => request,
            Err(error) => {
                let _ = self.authority.tokens().revoke(&minted.token.id);
                self.finish_failed(feature, review, "review context is invalid");
                return Err(error);
            }
        };
        let dispatcher = self.clone();
        let feature_for_task = feature.clone();
        let review_for_task = review.clone();
        let token_id = minted.token.id.clone();
        let token_id_for_task = token_id.clone();
        std::thread::Builder::new()
            .name(format!("loom-review-{}", review.id))
            .spawn(move || {
                dispatcher.run_job(&feature_for_task, &review_for_task, &request);
                if let Err(error) = dispatcher.authority.tokens().revoke(&token_id_for_task) {
                    eprintln!("loom: review token revoke failed ({token_id_for_task}): {error}");
                }
            })
            .map_err(|_| {
                let _ = self.authority.tokens().revoke(&token_id);
                self.finish_failed(feature, review, "review dispatch thread could not start");
                LoomError::StorageUnavailable
            })?;
        Ok(())
    }

    fn spawn_recovery(&self, feature: Feature, review: Review) {
        let dispatcher = self.clone();
        let thread_name = format!("loom-review-recover-{}", review.id);
        let failure_feature = feature.clone();
        let failure_review = review.clone();
        if std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || dispatcher.recover_one(&feature, &review))
            .is_err()
        {
            self.finish_failed(
                &failure_feature,
                &failure_review,
                "review recovery thread could not start",
            );
        }
    }

    fn recover_one(&self, feature: &Feature, review: &Review) {
        let Some(job_id) = review.runner_job_id.as_deref() else {
            return;
        };
        if feature
            .candidate
            .as_ref()
            .is_none_or(|candidate| candidate.id != review.candidate_id)
        {
            let _ = self.config.grid.cancel(job_id);
            self.finish_failed(feature, review, "review candidate was superseded");
            self.revoke_review_tokens(review);
            return;
        }
        match self.config.grid.get(job_id) {
            Ok(job) if matches!(job.status.as_str(), "passed" | "failed" | "cancelled") => {
                self.handle_job_outcome(feature, review, Ok(job));
                self.revoke_review_tokens(review);
            }
            Ok(_) => {
                let outcome = self.config.grid.wait(
                    job_id,
                    Duration::from_secs(self.config.timeout_secs.saturating_add(90)),
                );
                self.handle_job_outcome(feature, review, outcome);
                self.revoke_review_tokens(review);
            }
            Err(GridRunnerError::Status(404)) => {
                if let Err(error) = self.dispatch(feature, review)
                    && !self.review_completed(review)
                {
                    self.finish_failed(
                        feature,
                        review,
                        &format!("review recovery dispatch failed: {error}"),
                    );
                }
            }
            Err(error) => {
                self.finish_failed(feature, review, &runner_error_message(&error));
                self.revoke_review_tokens(review);
            }
        }
    }

    fn runner_request(
        &self,
        feature: &Feature,
        review: &Review,
        token: &str,
    ) -> Result<CreateRunnerRequest, LoomError> {
        let candidate = feature
            .candidate
            .as_ref()
            .ok_or(LoomError::InvalidSourceCommit)?;
        if candidate.id != review.candidate_id {
            return Err(LoomError::InvalidSourceCommit);
        }
        let repos = candidate
            .repositories
            .iter()
            .map(|binding| {
                let head = binding
                    .head
                    .as_ref()
                    .ok_or(LoomError::InvalidSourceCommit)?;
                Ok(GridRepo {
                    repo: head.repository.clone(),
                    revision: head.revision.clone(),
                })
            })
            .collect::<Result<Vec<_>, LoomError>>()?;
        let context = serde_json::to_string(&json!({
            "schema_version": "v1",
            "feature_id": feature.id,
            "review_id": review.id,
            "candidate_id": candidate.id,
            "repositories": candidate.repositories,
            "insights": candidate.insights,
        }))
        .map_err(|_| LoomError::Serialization)?;
        let env = BTreeMap::from([
            ("LOOM_URL".to_owned(), self.config.loom_url.clone()),
            ("LOOM_TOKEN".to_owned(), token.to_owned()),
            ("FEATURE_ID".to_owned(), feature.id.clone()),
            ("REVIEW_ID".to_owned(), review.id.clone()),
            ("CANDIDATE_ID".to_owned(), candidate.id.clone()),
            ("LOOM_FEATURE_ID".to_owned(), feature.id.clone()),
            ("LOOM_REVIEW_ID".to_owned(), review.id.clone()),
            ("LOOM_CANDIDATE_ID".to_owned(), candidate.id.clone()),
            ("LOOM_REVIEW_CONTEXT".to_owned(), context),
            ("NERO_REVIEW_MODE".to_owned(), "1".to_owned()),
        ]);
        Ok(CreateRunnerRequest {
            job_id: format!("rev-{}", review.id),
            kind: "review".to_owned(),
            repos,
            timeout_secs: self.config.timeout_secs,
            env,
            commands: vec![self.config.command.clone()],
        })
    }

    fn run_job(&self, feature: &Feature, review: &Review, request: &CreateRunnerRequest) {
        let outcome = self.config.grid.create(request).and_then(|created| {
            self.config.grid.wait(
                &created.id,
                Duration::from_secs(self.config.timeout_secs.saturating_add(90)),
            )
        });
        if outcome.is_err() {
            let _ = self.config.grid.cancel(&request.job_id);
        }
        self.handle_job_outcome(feature, review, outcome);
    }

    fn handle_job_outcome(
        &self,
        feature: &Feature,
        review: &Review,
        outcome: Result<crate::grid_runner::GridRunnerJob, GridRunnerError>,
    ) {
        match outcome {
            Ok(job) if job.status == "passed" => {
                if !self.review_completed(review) {
                    self.finish_failed(
                        feature,
                        review,
                        "review runner exited successfully without recording a verdict",
                    );
                }
            }
            Ok(job) => {
                if !self.review_completed(review) {
                    self.finish_failed(
                        feature,
                        review,
                        &format!("review runner finished with status {}", job.status),
                    );
                }
            }
            Err(error) => {
                if !self.review_completed(review) {
                    self.finish_failed(feature, review, &runner_error_message(&error));
                }
            }
        }
    }

    fn revoke_review_tokens(&self, review: &Review) {
        let name = format!("review-{}", review.id);
        let Ok(tokens) = self.authority.tokens().list() else {
            return;
        };
        for token in tokens.into_iter().filter(|token| token.name == name) {
            let _ = self.authority.tokens().revoke(&token.id);
        }
    }

    fn review_completed(&self, review: &Review) -> bool {
        self.reviews
            .get(&review.feature_id, &review.id)
            .is_ok_and(|current| current.status == ReviewStatus::Completed)
    }

    fn finish_failed(&self, feature: &Feature, review: &Review, message: &str) {
        if self.review_completed(review) {
            return;
        }
        let message = truncate_message(message);
        if let Ok(comment) = self.reviews.add_comment(
            &feature.id,
            CommentCreate {
                author: "agent:review-runner".to_owned(),
                body: message.clone(),
                in_reply_to: None,
                finding_id: None,
            },
        ) {
            let _ = self.events.emit(
                "comment.added",
                feature_repositories(feature),
                json!({
                    "id": feature.id,
                    "feature_id": feature.id,
                    "comment_id": comment.id,
                    "author": comment.author,
                }),
            );
        }
        if let Ok(completed) = self.reviews.complete(
            &feature.id,
            &review.id,
            ReviewComplete {
                verdict: ReviewVerdict::Comment,
            },
        ) {
            let _ = self.events.emit(
                "review.completed",
                feature_repositories(feature),
                json!({
                    "id": feature.id,
                    "feature_id": feature.id,
                    "review_id": completed.id,
                    "candidate_id": completed.candidate_id,
                    "verdict": completed.verdict,
                    "runner_status": "failed",
                    "error": message,
                }),
            );
        }
    }

    fn emit_started(&self, feature: &Feature, review: &Review, job_id: &str) {
        let _ = self.events.emit(
            "review.started",
            feature_repositories(feature),
            json!({
                "id": feature.id,
                "feature_id": feature.id,
                "review_id": review.id,
                "candidate_id": review.candidate_id,
                "job_id": job_id,
            }),
        );
    }
}

fn normalized_service_url(value: &str) -> Result<String, ReviewRunnerConfigError> {
    let value = value.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(value).map_err(|_| ReviewRunnerConfigError::Service)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ReviewRunnerConfigError::Service);
    }
    Ok(value.to_owned())
}

fn safe_review_command(command: &[String]) -> bool {
    if command.first().map(String::as_str) != Some("nero")
        || command.iter().any(|arg| arg.contains('\0'))
        || command.iter().any(|arg| {
            matches!(
                arg.split_once('=').map_or(arg.as_str(), |(name, _)| name),
                "--always-approve" | "--yolo" | "--dangerously-skip-permissions"
            )
        })
    {
        return false;
    }
    let mut headless = false;
    let mut default_permissions = false;
    let mut web_disabled = false;
    let mut subagents_disabled = false;
    for (index, arg) in command.iter().enumerate() {
        let name = arg.split_once('=').map_or(arg.as_str(), |(name, _)| name);
        if matches!(
            name,
            "--allow"
                | "--allowedTools"
                | "--allowed-tools"
                | "--agent"
                | "--agents"
                | "--tools"
                | "--cwd"
                | "--worktree"
                | "--worktree-ref"
                | "--restore-code"
                | "--continue"
                | "--resume"
                | "--fork-session"
        ) {
            return false;
        }
        if matches!(
            arg.as_str(),
            "-p" | "--single" | "--prompt-file" | "--prompt-json"
        ) {
            headless = true;
        }
        web_disabled |= arg == "--disable-web-search";
        subagents_disabled |= arg == "--no-subagents";
        let permission_mode = arg.strip_prefix("--permission-mode=").or_else(|| {
            (arg == "--permission-mode")
                .then(|| command.get(index + 1))
                .flatten()
                .map(String::as_str)
        });
        if let Some(mode) = permission_mode {
            if !mode.eq_ignore_ascii_case("default") {
                return false;
            }
            default_permissions = true;
        }
        let sandbox = arg.strip_prefix("--sandbox=").or_else(|| {
            (arg == "--sandbox")
                .then(|| command.get(index + 1))
                .flatten()
                .map(String::as_str)
        });
        if sandbox.is_some_and(|profile| profile.eq_ignore_ascii_case("danger-full-access")) {
            return false;
        }
    }
    headless && default_permissions && web_disabled && subagents_disabled
}

fn feature_repositories(feature: &Feature) -> impl Iterator<Item = String> + '_ {
    feature
        .repositories
        .iter()
        .map(|binding| binding.base.repository.clone())
}

fn runner_error_message(error: &GridRunnerError) -> String {
    format!("review runner dispatch failed: {error}")
}

fn truncate_message(message: &str) -> String {
    let mut out = message
        .trim()
        .chars()
        .take(MAX_FAILURE_MESSAGE)
        .collect::<String>();
    if out.is_empty() {
        "review runner failed".clone_into(&mut out);
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::{ReviewRunnerConfig, ReviewRunnerConfigError, safe_review_command};
    use crate::auth::AccessToken;
    use crate::ci::CiEngine;
    use crate::contracts::RepositoryBinding;
    use crate::events::EventLog;
    use crate::features::{EvidencePolicy, FeatureCreate, FeatureStore, Scenario};
    use crate::grid_runner::{CreateRunnerRequest, CreateRunnerResponse, GridRunnerJob};
    use crate::origin::OriginConfig;
    use crate::review::{ReviewStatus, ReviewStore, ReviewVerdict};
    use crate::server::{LoomApp, ServerConfig};
    use crate::tokens::TokenStore;
    use crate::{NamespaceGrant, PersistentLoomStore};

    #[test]
    fn review_command_rejects_permission_bypass() {
        assert!(safe_review_command(&[
            "nero".to_owned(),
            "--permission-mode".to_owned(),
            "default".to_owned(),
            "--disable-web-search".to_owned(),
            "--no-subagents".to_owned(),
            "--single".to_owned(),
            "Review the feature identified by FEATURE_ID".to_owned(),
        ]));
        for unsafe_args in [
            vec!["nero"],
            vec!["nero", "--always-approve"],
            vec!["nero", "--yolo"],
            vec!["nero", "--dangerously-skip-permissions"],
            vec!["nero", "--permission-mode", "bypassPermissions"],
            vec!["nero", "--permission-mode=always-approve"],
            vec!["nero", "--permission-mode=auto"],
            vec!["nero", "--sandbox", "danger-full-access"],
            vec!["nero", "--allow", "Bash(*)", "--single", "review"],
            vec!["sh", "-c", "nero"],
        ] {
            let command = unsafe_args
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(!safe_review_command(&command));
        }
    }

    #[test]
    fn explicit_config_is_fail_closed() {
        let command = vec![
            "nero".to_owned(),
            "--permission-mode".to_owned(),
            "default".to_owned(),
            "--disable-web-search".to_owned(),
            "--no-subagents".to_owned(),
            "--single".to_owned(),
            "review".to_owned(),
        ];
        assert_eq!(
            ReviewRunnerConfig::new("", "token", "https://loom.test", command.clone(), 60)
                .unwrap_err(),
            ReviewRunnerConfigError::Service
        );
        assert_eq!(
            ReviewRunnerConfig::new(
                "https://user:secret@grid.test",
                "token",
                "https://loom.test",
                command.clone(),
                60,
            )
            .unwrap_err(),
            ReviewRunnerConfigError::Service
        );
        assert_eq!(
            ReviewRunnerConfig::new(
                "https://grid.test",
                "token",
                "https://loom.test",
                command,
                1801,
            )
            .unwrap_err(),
            ReviewRunnerConfigError::Timeout
        );
    }

    #[derive(Clone, Default)]
    struct MockGrid {
        request: Arc<Mutex<Option<CreateRunnerRequest>>>,
        authenticated: Arc<Mutex<bool>>,
    }

    async fn create_runner(
        State(state): State<MockGrid>,
        headers: HeaderMap,
        Json(request): Json<CreateRunnerRequest>,
    ) -> (axum::http::StatusCode, Json<CreateRunnerResponse>) {
        *state.authenticated.lock().unwrap() = headers
            .get("x-grid-internal")
            .and_then(|value| value.to_str().ok())
            == Some("grid-internal");
        *state.request.lock().unwrap() = Some(request.clone());
        (
            axum::http::StatusCode::CREATED,
            Json(CreateRunnerResponse {
                id: request.job_id,
                status: "queued".to_owned(),
                workspace_id: String::new(),
            }),
        )
    }

    async fn get_runner(Path(id): Path<String>) -> Json<GridRunnerJob> {
        Json(GridRunnerJob {
            id,
            status: "passed".to_owned(),
            log: String::new(),
            error: None,
        })
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn dispatches_exact_context_and_fails_closed_without_verdict() {
        let mock = MockGrid::default();
        let app = Router::new()
            .route("/internal/runners", post(create_runner))
            .route("/internal/runners/{id}", get(get_runner))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
        let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
        let base = store
            .commit(
                &grant,
                "demo",
                None,
                BTreeMap::from([
                    ("README.md".to_owned(), b"base\n".to_vec()),
                    (
                        "loom-ci.toml".to_owned(),
                        b"[ci]\ncommands = [[\"true\"]]\n".to_vec(),
                    ),
                ]),
            )
            .unwrap();
        let head = store
            .commit(
                &grant,
                "demo",
                Some(&base),
                BTreeMap::from([("README.md".to_owned(), b"candidate\n".to_vec())]),
            )
            .unwrap();
        let head_revision = head.revision.clone();
        store
            .create_ref(&grant, "demo", "refs/main", &base)
            .unwrap();
        crate::catalog::RepoCatalog::open(store.clone())
            .upsert(crate::catalog::RepoEntry::minimal("demo"))
            .unwrap();
        let features = FeatureStore::new(store.clone());
        let created = features
            .create(FeatureCreate {
                title: "review me".to_owned(),
                repositories: vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned())],
                scenarios: vec![Scenario {
                    name: "review".to_owned(),
                    given: "a candidate".to_owned(),
                    when: "review Nero runs".to_owned(),
                    then: "a verdict is persisted".to_owned(),
                }],
                evidence_policy: EvidencePolicy::minimum(),
            })
            .unwrap();
        features.approve(&created.id).unwrap();
        let config = ReviewRunnerConfig::new(
            format!("http://{address}"),
            "grid-internal",
            "https://loom.test",
            vec![
                "nero".to_owned(),
                "--permission-mode".to_owned(),
                "default".to_owned(),
                "--disable-web-search".to_owned(),
                "--no-subagents".to_owned(),
                "--single".to_owned(),
                "Review the candidate identified by FEATURE_ID".to_owned(),
            ],
            60,
        )
        .unwrap();
        let root = directory.path().join("loom");
        let loom = LoomApp::new(ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            root: root.clone(),
            token: AccessToken::new("owner"),
            deploy_token: None,
            origin: OriginConfig::for_test(directory.path().join("origin"), true),
            git_program: PathBuf::from("/usr/bin/git"),
            hook_program: PathBuf::from("/bin/true"),
            review_runner: Some(config),
        })
        .unwrap();
        let candidate_body = serde_json::json!({
            "repositories": [{
                "base": base,
                "target_ref": "refs/main",
                "head": head,
            }]
        });
        let response = loom
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/features/{}/candidates", created.id))
                    .header("authorization", "Bearer owner")
                    .header("content-type", "application/json")
                    .body(Body::from(candidate_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let feature: crate::features::Feature = serde_json::from_slice(&bytes).unwrap();
        let token_store = TokenStore::new(store.clone());
        let reviews = ReviewStore::new(store.clone());
        let events = EventLog::new(store);
        let mut listed = reviews.list_for_feature(&feature.id).unwrap();
        let review = listed.remove(0);

        for _ in 0..100 {
            let completed = reviews
                .get(&feature.id, &review.id)
                .is_ok_and(|current| current.status == ReviewStatus::Completed);
            if completed && token_store.list().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let completed = reviews.get(&feature.id, &review.id).unwrap();
        assert_eq!(completed.status, ReviewStatus::Completed);
        assert_eq!(completed.verdict, Some(ReviewVerdict::Comment));
        let comments = reviews.list_comments(&feature.id).unwrap();
        assert_eq!(comments.len(), 1);
        assert!(comments[0].body.contains("without recording a verdict"));
        assert!(token_store.list().unwrap().is_empty());

        let request = mock.request.lock().unwrap().clone().unwrap();
        assert!(*mock.authenticated.lock().unwrap());
        assert_eq!(request.kind, "review");
        assert_eq!(request.repos.len(), 1);
        assert_eq!(request.repos[0].repo, "demo");
        assert_eq!(request.repos[0].revision, head_revision);
        assert_eq!(request.env["FEATURE_ID"], feature.id);
        assert_eq!(request.env["REVIEW_ID"], review.id);
        assert_eq!(request.env["CANDIDATE_ID"], review.candidate_id);
        assert_eq!(request.commands[0][0], "nero");
        let context: serde_json::Value =
            serde_json::from_str(&request.env["LOOM_REVIEW_CONTEXT"]).unwrap();
        assert_eq!(
            context["repositories"][0]["head"]["revision"],
            head_revision
        );

        let kinds = events
            .since(None, 20)
            .unwrap()
            .into_iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                "ci.started",
                "ci.finished",
                "insights.ready",
                "candidate.submitted",
                "review.started",
                "comment.added",
                "review.completed",
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn recovers_monitoring_without_dispatching_a_duplicate_grid_job() {
        let mock = MockGrid::default();
        let app = Router::new()
            .route("/internal/runners", post(create_runner))
            .route("/internal/runners/{id}", get(get_runner))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("loom");
        let store = PersistentLoomStore::open(&root).unwrap();
        let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
        let base = store
            .commit(
                &grant,
                "demo",
                None,
                BTreeMap::from([("README.md".to_owned(), b"base\n".to_vec())]),
            )
            .unwrap();
        let head = store
            .commit(
                &grant,
                "demo",
                Some(&base),
                BTreeMap::from([("README.md".to_owned(), b"candidate\n".to_vec())]),
            )
            .unwrap();
        store
            .create_ref(&grant, "demo", "refs/main", &base)
            .unwrap();
        let features = FeatureStore::new(store.clone());
        let feature = features
            .create(FeatureCreate {
                title: "recover review".to_owned(),
                repositories: vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned())],
                scenarios: vec![Scenario {
                    name: "recover".to_owned(),
                    given: "a durable review".to_owned(),
                    when: "Loom restarts".to_owned(),
                    then: "the existing Grid job is monitored".to_owned(),
                }],
                evidence_policy: EvidencePolicy::minimum(),
            })
            .unwrap();
        features.approve(&feature.id).unwrap();
        let bindings = vec![RepositoryBinding::new(base, "refs/main".to_owned()).with_head(head)];
        let ci = CiEngine::new(store.clone());
        let job = ci.run(&feature.id, &bindings).unwrap();
        let candidate = ci.candidate_from_job(&job, bindings).unwrap();
        features.attach_candidate(&feature.id, candidate).unwrap();
        let reviews = ReviewStore::new(store.clone());
        let (review, created) = reviews.start_runner_review(&feature.id).unwrap();
        assert!(created);
        let expected_job_id = format!("rev-{}", review.id);
        assert_eq!(
            review.runner_job_id.as_deref(),
            Some(expected_job_id.as_str())
        );

        let config = ReviewRunnerConfig::new(
            format!("http://{address}"),
            "grid-internal",
            "https://loom.test",
            vec![
                "nero".to_owned(),
                "--permission-mode".to_owned(),
                "default".to_owned(),
                "--disable-web-search".to_owned(),
                "--no-subagents".to_owned(),
                "--single".to_owned(),
                "Review FEATURE_ID".to_owned(),
            ],
            60,
        )
        .unwrap();
        let _loom = LoomApp::new(ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            root,
            token: AccessToken::new("owner"),
            deploy_token: None,
            origin: OriginConfig::for_test(directory.path().join("origin"), true),
            git_program: PathBuf::from("/usr/bin/git"),
            hook_program: PathBuf::from("/bin/true"),
            review_runner: Some(config),
        })
        .unwrap();

        for _ in 0..100 {
            if reviews
                .get(&feature.id, &review.id)
                .is_ok_and(|current| current.status == ReviewStatus::Completed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let completed = reviews.get(&feature.id, &review.id).unwrap();
        assert_eq!(completed.verdict, Some(ReviewVerdict::Comment));
        assert!(mock.request.lock().unwrap().is_none());
        server.abort();
    }
}
