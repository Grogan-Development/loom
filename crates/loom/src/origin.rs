//! Origin SHA CI, evidence lookup, fail-closed deploy, and check-run upsert.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::ci::{CiStatus, execute_command, load_pipeline, truncate_log};
use crate::deploy::apply_release;
use crate::{LoomError, PersistentLoomStore, hex_digest, read_bounded, write_atomic};

const MAX_ORIGIN_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOBS: usize = 10_000;
const ALLOWED_REPOS: [&str; 3] = ["loom", "nero", "grid"];
const DEFAULT_OWNER: &str = "grogan-dev";
const DEFAULT_CLONE_HOST: &str = "origin.cursor.com";
const DEFAULT_API_BASE: &str = "https://api.cursor.com/v1/origin";
const WEBHOOK_SKEW_SECS: u64 = 300;

/// How Origin SHA trees are obtained and tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginCiRunner {
    /// Clone from Origin git over HTTPS and run `loom-ci.toml`.
    Git,
    /// Record a predetermined result. Used by tests.
    Fixed {
        /// Whether required tests passed.
        passed: bool,
        /// Captured log.
        log: String,
    },
}

/// Runtime configuration for Origin clone, checks, webhook verify, and apply.
#[derive(Clone)]
pub struct OriginConfig {
    /// Origin owner slug (`grogan-dev`).
    pub owner: String,
    /// Git HTTPS host (`origin.cursor.com`).
    pub clone_host: String,
    /// Origin REST base including `/v1/origin`.
    pub api_base: String,
    /// HTTPS clone token. Installation tokens are minted when this is empty.
    pub clone_token: Option<String>,
    /// Origin App id used as JWT `iss` / `kid`.
    pub app_id: Option<String>,
    /// PKCS#8 Ed25519 PEM for the Origin App.
    pub app_private_key_pem: Option<String>,
    /// Origin App installation id.
    pub installation_id: Option<String>,
    /// Absolute git executable.
    pub git_program: PathBuf,
    /// Scratch directory for mirrors and worktrees.
    pub workdir: PathBuf,
    /// Local apply script for the Loom VM.
    pub loom_apply: PathBuf,
    /// Remote apply script for Grid.
    pub grid_apply: PathBuf,
    /// Remote apply script for Nero.
    pub nero_apply: PathBuf,
    /// SSH host for Grid and Nero applies.
    pub deploy_ssh_host: Option<String>,
    /// SSH user for Grid and Nero applies.
    pub deploy_ssh_user: Option<String>,
    /// SSH identity file for Grid and Nero applies.
    pub deploy_ssh_key: Option<PathBuf>,
    /// Wall-clock timeout for apply helpers.
    pub apply_timeout: Duration,
    /// Injected webhook verifying keys. Empty means fetch Origin JWKS.
    pub webhook_keys: Vec<[u8; 32]>,
    /// CI runner.
    pub ci_runner: OriginCiRunner,
    /// Skip host apply scripts after evidence checks (tests).
    pub apply_runner_noop: bool,
}

impl std::fmt::Debug for OriginConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginConfig")
            .field("owner", &self.owner)
            .field("clone_host", &self.clone_host)
            .field("api_base", &self.api_base)
            .field("has_clone_token", &self.clone_token.is_some())
            .field("has_app_key", &self.app_private_key_pem.is_some())
            .field("installation_id", &self.installation_id)
            .field("git_program", &self.git_program)
            .field("workdir", &self.workdir)
            .field("ci_runner", &self.ci_runner)
            .field("apply_runner_noop", &self.apply_runner_noop)
            .finish_non_exhaustive()
    }
}

impl OriginConfig {
    /// Production defaults for grogan-dev on Origin.
    #[must_use]
    pub fn production(workdir: PathBuf, git_program: PathBuf) -> Self {
        Self {
            owner: DEFAULT_OWNER.to_owned(),
            clone_host: DEFAULT_CLONE_HOST.to_owned(),
            api_base: DEFAULT_API_BASE.to_owned(),
            clone_token: None,
            app_id: None,
            app_private_key_pem: None,
            installation_id: None,
            git_program,
            workdir,
            loom_apply: PathBuf::from("/opt/loom/scripts/apply.sh"),
            grid_apply: PathBuf::from("/opt/grid/scripts/apply.sh"),
            nero_apply: PathBuf::from("/opt/nero/scripts/apply.sh"),
            deploy_ssh_host: None,
            deploy_ssh_user: Some("root".to_owned()),
            deploy_ssh_key: None,
            apply_timeout: Duration::from_secs(1800),
            webhook_keys: Vec::new(),
            ci_runner: OriginCiRunner::Git,
            apply_runner_noop: false,
        }
    }

    /// Test configuration that never talks to Origin git or SSH.
    #[must_use]
    pub fn for_test(workdir: PathBuf, passed: bool) -> Self {
        Self {
            owner: DEFAULT_OWNER.to_owned(),
            clone_host: DEFAULT_CLONE_HOST.to_owned(),
            api_base: DEFAULT_API_BASE.to_owned(),
            clone_token: None,
            app_id: None,
            app_private_key_pem: None,
            installation_id: None,
            git_program: PathBuf::from("/usr/bin/git"),
            workdir,
            loom_apply: PathBuf::from("/opt/loom/scripts/apply.sh"),
            grid_apply: PathBuf::from("/opt/grid/scripts/apply.sh"),
            nero_apply: PathBuf::from("/opt/nero/scripts/apply.sh"),
            deploy_ssh_host: None,
            deploy_ssh_user: None,
            deploy_ssh_key: None,
            apply_timeout: Duration::from_secs(5),
            webhook_keys: Vec::new(),
            ci_runner: OriginCiRunner::Fixed {
                passed,
                log: "origin.test".to_owned(),
            },
            apply_runner_noop: true,
        }
    }
}

/// Durable Origin SHA job and deploy evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginRelease {
    /// Allowlisted repository name.
    pub repository: String,
    /// Git object id.
    pub git_oid: String,
    /// Durable CI job id.
    pub job_id: String,
    /// CI status.
    pub status: CiStatus,
    /// True only when required tests passed for this exact SHA.
    pub tests_passed: bool,
    /// Truncated command log.
    pub log: String,
    /// Origin check-run id when upsert succeeded.
    pub origin_check_id: Option<String>,
    /// SHA last applied to the host, when deploy succeeded.
    pub deployed_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedReleases {
    schema_version: String,
    releases: Vec<OriginRelease>,
}

/// SHA-keyed Origin CI and deploy gate.
#[derive(Clone)]
pub struct OriginEngine {
    store: PersistentLoomStore,
    config: OriginConfig,
    http: reqwest::Client,
}

impl OriginEngine {
    /// Creates an Origin engine over an existing Loom dataset.
    #[must_use]
    pub fn new(store: PersistentLoomStore, config: OriginConfig) -> Self {
        Self {
            store,
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Shared config used by HTTP handlers and apply helpers.
    #[must_use]
    pub const fn config(&self) -> &OriginConfig {
        &self.config
    }

    /// Reads one SHA-keyed release.
    ///
    /// # Errors
    ///
    /// Returns for lock or durable I/O failure.
    pub fn release(&self, repository: &str, oid: &str) -> Result<Option<OriginRelease>, LoomError> {
        allowlisted(repository)?;
        validate_oid(oid)?;
        let lock = self.store.shared_lock()?;
        let releases = self.load()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(releases.get(&release_key(repository, oid)).cloned())
    }

    /// Records a completed job. Used by tests and by the CI runner.
    ///
    /// # Errors
    ///
    /// Returns for lock, serialization, or durable I/O failure.
    pub fn put_release(&self, release: OriginRelease) -> Result<OriginRelease, LoomError> {
        allowlisted(&release.repository)?;
        validate_oid(&release.git_oid)?;
        self.upsert(release)
    }

    /// Clones the SHA (or uses the test runner), executes `loom-ci.toml`, and stores evidence.
    ///
    /// # Errors
    ///
    /// Returns for an unknown repository, invalid SHA, git failure, or storage failure.
    pub fn run_ci(&self, repository: &str, oid: &str) -> Result<OriginRelease, LoomError> {
        allowlisted(repository)?;
        validate_oid(oid)?;
        if let Some(existing) = self.release(repository, oid)?
            && existing.status == CiStatus::Passed
        {
            return Ok(existing);
        }
        let previous = self.release(repository, oid)?;
        let mut release = OriginRelease {
            repository: repository.to_owned(),
            git_oid: oid.to_owned(),
            job_id: Uuid::now_v7().to_string(),
            status: CiStatus::Running,
            tests_passed: false,
            log: String::new(),
            origin_check_id: None,
            deployed_oid: previous.and_then(|item| item.deployed_oid),
        };
        self.upsert(release.clone())?;
        let (passed, log) = match &self.config.ci_runner {
            OriginCiRunner::Fixed { passed, log } => (*passed, log.clone()),
            OriginCiRunner::Git => match self.run_git_ci(repository, oid) {
                Ok(result) => result,
                Err(error) => (false, error.to_string()),
            },
        };
        release.log = truncate_log(&log);
        release.tests_passed = passed;
        release.status = if passed {
            CiStatus::Passed
        } else {
            CiStatus::Failed
        };
        self.upsert(release)
    }

    /// Fail-closed deploy: requires `tests_passed` for this exact SHA, then apply.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::OriginDeployBlocked`] when evidence is missing or failed.
    pub fn deploy(&self, repository: &str, oid: &str) -> Result<OriginRelease, LoomError> {
        allowlisted(repository)?;
        validate_oid(oid)?;
        let Some(mut release) = self.release(repository, oid)? else {
            return Err(LoomError::OriginDeployBlocked {
                repository: repository.to_owned(),
                oid: oid.to_owned(),
            });
        };
        if !release.tests_passed || release.status != CiStatus::Passed {
            return Err(LoomError::OriginDeployBlocked {
                repository: repository.to_owned(),
                oid: oid.to_owned(),
            });
        }
        if release.deployed_oid.as_deref() == Some(oid) {
            return Ok(release);
        }
        let log = apply_release(&self.config, repository, oid)?;
        release.log = truncate_log(&format!("{}\n{log}", release.log));
        release.deployed_oid = Some(oid.to_owned());
        self.upsert(release)
    }

    /// Verifies an Origin webhook signature fail-closed.
    ///
    /// # Errors
    ///
    /// Returns when the signature, timestamp, or key material is missing or invalid.
    pub async fn verify_webhook(
        &self,
        webhook_id: &str,
        timestamp: &str,
        signature_header: &str,
        body: &[u8],
    ) -> Result<(), LoomError> {
        if webhook_id.is_empty() || timestamp.is_empty() || signature_header.is_empty() {
            return Err(LoomError::OriginUnavailable);
        }
        let ts = timestamp
            .parse::<u64>()
            .map_err(|_| LoomError::OriginUnavailable)?;
        let now = unix_now();
        if now.abs_diff(ts) > WEBHOOK_SKEW_SECS {
            return Err(LoomError::OriginUnavailable);
        }
        let encoded = signature_bytes(signature_header).ok_or(LoomError::OriginUnavailable)?;
        let decoded = Base64::decode_vec(encoded).map_err(|_| LoomError::OriginUnavailable)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| LoomError::OriginUnavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(webhook_id.as_bytes());
        hasher.update(b".");
        hasher.update(timestamp.as_bytes());
        hasher.update(b".");
        hasher.update(body);
        let digest = hex_digest(hasher.finalize().as_slice());
        let keys = self.verifying_keys().await?;
        if keys
            .iter()
            .any(|key| key.verify(digest.as_bytes(), &signature).is_ok())
        {
            Ok(())
        } else {
            Err(LoomError::OriginUnavailable)
        }
    }

    /// Extracts allowlisted CI targets from a verified Origin webhook body.
    #[must_use]
    pub fn targets_from_webhook(body: &[u8]) -> Vec<(String, String)> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Vec::new();
        };
        let event_type = value
            .pointer("/event/type")
            .or_else(|| value.get("type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let payload = value
            .pointer("/event/payload")
            .cloned()
            .or_else(|| value.get("payload").cloned())
            .unwrap_or(value);
        extract_targets(&event_type, &payload)
    }

    /// Best-effort Origin check-run upsert. Missing App credentials no-op.
    pub async fn publish_check(&self, release: &OriginRelease) {
        if self.config.app_id.is_none()
            || self.config.app_private_key_pem.is_none()
            || self.config.installation_id.is_none()
        {
            eprintln!(
                "loom: origin check upsert skipped for {}@{} (Origin App unset)",
                release.repository, release.git_oid
            );
            return;
        }
        if let Err(error) = self.upsert_check(release).await {
            eprintln!(
                "loom: origin check upsert failed for {}@{}: {error}",
                release.repository, release.git_oid
            );
        }
    }

    fn run_git_ci(&self, repository: &str, oid: &str) -> Result<(bool, String), LoomError> {
        let checkout = self.checkout(repository, oid)?;
        let (commands, timeout) = load_pipeline(&checkout);
        let mut log = String::new();
        let mut passed = true;
        for command in commands {
            let (ok, output) = execute_command(&checkout, &command, timeout)?;
            log.push_str("$ ");
            log.push_str(&command.join(" "));
            log.push('\n');
            log.push_str(&output);
            log.push('\n');
            if !ok {
                passed = false;
                break;
            }
        }
        Ok((passed, log))
    }

    fn checkout(&self, repository: &str, oid: &str) -> Result<PathBuf, LoomError> {
        std::fs::create_dir_all(&self.config.workdir).map_err(|_| LoomError::OriginUnavailable)?;
        let mirror = self.config.workdir.join(format!("{repository}.git"));
        let token = self.config.clone_token.clone().unwrap_or_default();
        let url = git_url(&self.config, repository, &token);
        let mirror_str = mirror.to_str().ok_or(LoomError::OriginUnavailable)?;
        if !mirror.exists() {
            git(
                &self.config.git_program,
                &["clone", "--bare", &url, mirror_str],
                &self.config.workdir,
            )?;
            rewrite_remote(&self.config.git_program, &mirror, &self.config, repository)?;
        }
        // Fetch through the token URL, not the named remote: rewrite_remote
        // deliberately strips credentials from the persisted remote.
        git(
            &self.config.git_program,
            &["fetch", "--force", &url, oid],
            &mirror,
        )?;
        let work = self.config.workdir.join(format!("work-{repository}-{oid}"));
        if work.exists() {
            let _ = std::fs::remove_dir_all(&work);
        }
        let work_str = work.to_str().ok_or(LoomError::OriginUnavailable)?;
        git(
            &self.config.git_program,
            &["worktree", "add", "--detach", work_str, oid],
            &mirror,
        )?;
        Ok(work)
    }

    async fn verifying_keys(&self) -> Result<Vec<VerifyingKey>, LoomError> {
        if !self.config.webhook_keys.is_empty() {
            return self
                .config
                .webhook_keys
                .iter()
                .map(|bytes| {
                    VerifyingKey::from_bytes(bytes).map_err(|_| LoomError::OriginUnavailable)
                })
                .collect();
        }
        let url = format!("{}/keys", self.config.api_base.trim_end_matches('/'));
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| LoomError::OriginUnavailable)?;
        if !response.status().is_success() {
            return Err(LoomError::OriginUnavailable);
        }
        let document: Jwks = response
            .json()
            .await
            .map_err(|_| LoomError::OriginUnavailable)?;
        document
            .keys
            .into_iter()
            .filter(|jwk| jwk.kty == "OKP" && jwk.crv == "Ed25519")
            .map(|jwk| decode_verifying_key(&jwk.x))
            .collect()
    }

    async fn upsert_check(&self, release: &OriginRelease) -> Result<(), LoomError> {
        let token = self.installation_token().await?;
        let in_progress = matches!(release.status, CiStatus::Running | CiStatus::Pending);
        let conclusion = if release.tests_passed {
            "success"
        } else if in_progress {
            "neutral"
        } else {
            "failure"
        };
        let status = if in_progress {
            "in_progress"
        } else {
            "completed"
        };
        let body = serde_json::json!({
            "owner": self.config.owner,
            "repo": release.repository,
            "checkRuns": [{
                "headSha": release.git_oid,
                "suiteKey": "loom",
                "key": "ci",
                "name": "Loom",
                "status": status,
                "conclusion": conclusion,
                "externalId": release.job_id,
                "externalUpdatedAt": unix_now().to_string(),
                "output": {
                    "title": "Loom CI",
                    "summary": release.log
                }
            }]
        });
        let url = format!(
            "{}/check-runs:batchUpsert",
            self.config.api_base.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|_| LoomError::OriginUnavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(LoomError::OriginUnavailable)
        }
    }

    async fn installation_token(&self) -> Result<String, LoomError> {
        let app_id = self
            .config
            .app_id
            .as_deref()
            .ok_or(LoomError::OriginUnavailable)?;
        let pem = self
            .config
            .app_private_key_pem
            .as_deref()
            .ok_or(LoomError::OriginUnavailable)?;
        let installation = self
            .config
            .installation_id
            .as_deref()
            .ok_or(LoomError::OriginUnavailable)?;
        let jwt = mint_app_jwt(app_id, pem)?;
        let url = format!(
            "{}/app/installations/{installation}/access_tokens",
            self.config.api_base.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .bearer_auth(jwt)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|_| LoomError::OriginUnavailable)?;
        if !response.status().is_success() {
            return Err(LoomError::OriginUnavailable);
        }
        let body: InstallationToken = response
            .json()
            .await
            .map_err(|_| LoomError::OriginUnavailable)?;
        if body.token.is_empty() {
            Err(LoomError::OriginUnavailable)
        } else {
            Ok(body.token)
        }
    }

    fn upsert(&self, release: OriginRelease) -> Result<OriginRelease, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut releases = self.load()?;
        releases.insert(
            release_key(&release.repository, &release.git_oid),
            release.clone(),
        );
        if releases.len() > MAX_JOBS {
            return Err(LoomError::ResourceLimit);
        }
        let persisted = PersistedReleases {
            schema_version: "v1".to_owned(),
            releases: releases.into_values().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        write_atomic(
            &self.store.root,
            &self.store.root.join("origin-releases.json"),
            &bytes,
            0o600,
        )?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(release)
    }

    fn load(&self) -> Result<BTreeMap<String, OriginRelease>, LoomError> {
        let path = self.store.root.join("origin-releases.json");
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = read_bounded(&path, MAX_ORIGIN_BYTES)?;
        let persisted: PersistedReleases =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(persisted
            .releases
            .into_iter()
            .map(|release| (release_key(&release.repository, &release.git_oid), release))
            .collect())
    }
}

/// Request body for `POST /v1/releases/{repo}/ci`.
#[derive(Debug, Clone, Deserialize)]
pub struct OriginCiRequest {
    /// Git object id to test.
    #[serde(alias = "oid", alias = "sha")]
    pub git_oid: String,
}

/// Public evidence document consumed by Cursor Cloud CD.
#[derive(Debug, Clone, Serialize)]
pub struct OriginEvidence {
    /// CI status.
    pub status: CiStatus,
    /// True only after required tests passed for this SHA.
    pub tests_passed: bool,
    /// Durable job id.
    pub job_id: String,
    /// Truncated log.
    pub log: String,
    /// Origin check-run id when known.
    pub origin_check_id: Option<String>,
}

impl From<&OriginRelease> for OriginEvidence {
    fn from(release: &OriginRelease) -> Self {
        Self {
            status: release.status,
            tests_passed: release.tests_passed,
            job_id: release.job_id.clone(),
            log: release.log.clone(),
            origin_check_id: release.origin_check_id.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
}

#[derive(Debug, Deserialize)]
struct InstallationToken {
    #[serde(default)]
    token: String,
}

fn allowlisted(repository: &str) -> Result<(), LoomError> {
    if ALLOWED_REPOS.contains(&repository) {
        Ok(())
    } else {
        Err(LoomError::OriginRepositoryDenied {
            repository: repository.to_owned(),
        })
    }
}

fn validate_oid(oid: &str) -> Result<(), LoomError> {
    let valid = (7..=64).contains(&oid.len())
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(LoomError::InvalidSourceCommit)
    }
}

fn release_key(repository: &str, oid: &str) -> String {
    format!("{repository}:{oid}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn signature_bytes(header: &str) -> Option<&str> {
    header
        .split_whitespace()
        .find_map(|part| {
            part.strip_prefix("v1ed,")
                .or_else(|| part.strip_prefix("v1ed="))
        })
        .or_else(|| {
            header
                .split(',')
                .nth(1)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

fn git_url(config: &OriginConfig, repository: &str, token: &str) -> String {
    if token.is_empty() {
        format!(
            "https://{}/{}/{repository}.git",
            config.clone_host, config.owner
        )
    } else {
        format!(
            "https://x-access-token:{token}@{}/{}/{repository}.git",
            config.clone_host, config.owner
        )
    }
}

fn rewrite_remote(
    git_program: &Path,
    mirror: &Path,
    config: &OriginConfig,
    repository: &str,
) -> Result<(), LoomError> {
    let clean = format!(
        "https://{}/{}/{repository}.git",
        config.clone_host, config.owner
    );
    git(
        git_program,
        &["remote", "set-url", "origin", &clean],
        mirror,
    )
    .map(|_| ())
}

fn git(program: &Path, args: &[&str], cwd: &Path) -> Result<String, LoomError> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_TERMINAL_PROMPT", "0")
        .spawn()
        .map_err(|_| LoomError::OriginUnavailable)?;
    let started = Instant::now();
    let timeout = Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut stdout);
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
                }
                if status.success() {
                    return Ok(format!("{stdout}{stderr}"));
                }
                return Err(LoomError::OriginUnavailable);
            }
            Ok(None) if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LoomError::OriginUnavailable);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err(LoomError::OriginUnavailable),
        }
    }
}

fn decode_verifying_key(x: &str) -> Result<VerifyingKey, LoomError> {
    let bytes = Base64UrlUnpadded::decode_vec(x).map_err(|_| LoomError::OriginUnavailable)?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| LoomError::OriginUnavailable)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| LoomError::OriginUnavailable)
}

fn mint_app_jwt(app_id: &str, pem: &str) -> Result<String, LoomError> {
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|_| LoomError::OriginUnavailable)?;
    let now = unix_now();
    let header = serde_json::json!({ "alg": "EdDSA", "kid": app_id, "typ": "JWT" });
    let payload = serde_json::json!({
        "iss": app_id,
        "aud": "origin-apps",
        "iat": now,
        "exp": now.saturating_add(300)
    });
    let header_b64 = Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&header).map_err(|_| LoomError::Serialization)?,
    );
    let payload_b64 = Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&payload).map_err(|_| LoomError::Serialization)?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = key.sign(signing_input.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}

fn extract_targets(event_type: &str, payload: &serde_json::Value) -> Vec<(String, String)> {
    let repo = payload
        .pointer("/repository/name")
        .or_else(|| payload.pointer("/repo/name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    if repo.is_empty() || allowlisted(&repo).is_err() {
        return Vec::new();
    }
    let shas: Vec<&str> = match event_type {
        "pull_request.created" | "pull_request.head_ref.pushed" | "pull_request.opened" => payload
            .pointer("/pullRequest/headSha")
            .or_else(|| payload.pointer("/pullRequest/head/sha"))
            .or_else(|| payload.pointer("/pullRequest/version/headSha"))
            .or_else(|| payload.pointer("/pull_request/head/sha"))
            .or_else(|| payload.pointer("/headSha"))
            .and_then(serde_json::Value::as_str)
            .into_iter()
            .collect(),
        "repository.pushed" => main_push_heads(payload),
        _ => payload
            .pointer("/headSha")
            .or_else(|| payload.get("after"))
            .and_then(serde_json::Value::as_str)
            .into_iter()
            .collect(),
    };
    shas.into_iter()
        .filter(|value| validate_oid(value).is_ok())
        .map(|value| (repo.clone(), value.to_owned()))
        .collect()
}

/// Head SHAs pushed to `main`. Origin delivers a `refUpdates` array; the
/// GitHub-style top-level `ref`/`after` pair is kept as a fallback.
fn main_push_heads(payload: &serde_json::Value) -> Vec<&str> {
    if let Some(updates) = payload
        .get("refUpdates")
        .and_then(serde_json::Value::as_array)
    {
        return updates
            .iter()
            .filter(|update| {
                let ref_name = update
                    .get("ref")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let deleted = update
                    .get("deleted")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                !deleted && (ref_name == "refs/heads/main" || ref_name == "main")
            })
            .filter_map(|update| update.get("after").and_then(serde_json::Value::as_str))
            .collect();
    }
    let ref_name = payload
        .get("ref")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if ref_name != "refs/heads/main" && ref_name != "main" {
        return Vec::new();
    }
    payload
        .get("after")
        .and_then(serde_json::Value::as_str)
        .into_iter()
        .collect()
}

/// Builds a signed Origin webhook header set for tests.
#[must_use]
pub fn test_webhook_signature(
    webhook_id: &str,
    timestamp: &str,
    body: &[u8],
    secret: &[u8; 32],
) -> String {
    let key = SigningKey::from_bytes(secret);
    let mut hasher = Sha256::new();
    hasher.update(webhook_id.as_bytes());
    hasher.update(b".");
    hasher.update(timestamp.as_bytes());
    hasher.update(b".");
    hasher.update(body);
    let digest = hex_digest(hasher.finalize().as_slice());
    let signature = key.sign(digest.as_bytes());
    format!("v1ed,{}", Base64::encode_string(&signature.to_bytes()))
}

/// Returns the Origin App verifying key bytes for a seed used in tests.
#[must_use]
pub fn test_verifying_key(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}
