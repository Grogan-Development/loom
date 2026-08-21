//! Origin is a dumb outbound push mirror plus the historical SHA release store.
//!
//! Deploy is keyed to Loom evidence (`record_loom_release`), not Origin CI.
//! Webhooks are verified (when keys are configured) and then ignored.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::catalog::{DeployTarget, RepoCatalog, RepoEntry, seed_entries};
use crate::ci::{CiEngine, CiStatus, truncate_log};
use crate::contracts::RepositoryRevision;
use crate::deploy::apply_release;
use crate::events::EventLog;
use crate::{LoomError, PersistentLoomStore, hex_digest, read_bounded, write_atomic};

const MAX_ORIGIN_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOBS: usize = 10_000;
const DEFAULT_OWNER: &str = "grogan-dev";
const DEFAULT_CLONE_HOST: &str = "origin.cursor.com";
const DEFAULT_API_BASE: &str = "https://api.cursor.com/v1/origin";
const WEBHOOK_SKEW_SECS: u64 = 300;

/// How Origin SHA trees used to be obtained and tested. Kept for config compat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginCiRunner {
    /// Clone from Origin git over HTTPS and run `loom-ci.toml`. Unused (mirror-only).
    Git,
    /// Record a predetermined result. Used by leftover manual-record tests.
    Fixed {
        /// Whether required tests passed.
        passed: bool,
        /// Captured log.
        log: String,
    },
}

/// How outbound Origin mirror pushes are executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginMirrorRunner {
    /// `git push` the projected SHA to the Origin remote.
    Git,
    /// Record a predetermined result. Used by tests; never talks to the network.
    Fixed {
        /// Whether the mirror push is treated as successful.
        ok: bool,
        /// Captured log.
        log: String,
    },
}

/// Runtime configuration for Origin mirror push, webhook verify, and apply.
#[derive(Clone)]
pub struct OriginConfig {
    /// Origin owner slug (`grogan-dev`).
    pub owner: String,
    /// Git HTTPS host (`origin.cursor.com`).
    pub clone_host: String,
    /// Origin REST base including `/v1/origin`.
    pub api_base: String,
    /// HTTPS clone/push token. Installation tokens are unused for mirror push.
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
    /// Injected webhook verifying keys. Empty means skip webhook verification.
    pub webhook_keys: Vec<[u8; 32]>,
    /// Legacy Origin-clone CI runner (`POST /v1/releases/{repo}/ci` now runs
    /// the Loom CI engine against the imported tree instead).
    pub ci_runner: OriginCiRunner,
    /// Skip host apply scripts after evidence checks (tests).
    pub apply_runner_noop: bool,
    /// HTTPS URL template or host for outbound mirror push (`ORIGIN_MIRROR_REMOTE`).
    pub mirror_remote: Option<String>,
    /// Mirror push runner.
    pub mirror_runner: OriginMirrorRunner,
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
            .field("mirror_remote", &self.mirror_remote)
            .field("mirror_runner", &self.mirror_runner)
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
            mirror_remote: None,
            mirror_runner: OriginMirrorRunner::Git,
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
            mirror_remote: None,
            mirror_runner: OriginMirrorRunner::Fixed {
                ok: true,
                log: "origin.mirror.test".to_owned(),
            },
        }
    }
}

/// Durable SHA-keyed release used by fail-closed deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginRelease {
    /// Registered repository name.
    pub repository: String,
    /// Git object id.
    pub git_oid: String,
    /// Durable CI/evidence job id.
    pub job_id: String,
    /// Evidence status (Passed when Loom tests passed).
    pub status: CiStatus,
    /// True only when required tests passed for this exact SHA.
    pub tests_passed: bool,
    /// Truncated command log.
    pub log: String,
    /// Origin check-run id when upsert succeeded (historical).
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

/// Status of one outbound Origin mirror job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorStatus {
    /// Queued, not yet processed.
    Pending,
    /// Push recorded as successful.
    Ok,
    /// Push skipped or failed.
    Error,
}

/// Best-effort Origin mirror job persisted in `mirror_queue.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorJob {
    /// Durable job id.
    pub id: String,
    /// Registered repository name.
    pub repository: String,
    /// Git object id when a mapping exists.
    pub git_oid: Option<String>,
    /// Job outcome.
    pub status: OriginMirrorStatus,
    /// Truncated runner log or error.
    pub log: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedMirrors {
    schema_version: String,
    jobs: Vec<OriginMirrorJob>,
}

#[derive(Debug, Deserialize)]
struct GitRevisionMapping {
    schema_version: String,
    repository: String,
    git_oid: String,
    revision: RepositoryRevision,
}

/// SHA-keyed release store plus outbound Origin mirror queue.
#[derive(Clone)]
pub struct OriginEngine {
    store: PersistentLoomStore,
    config: OriginConfig,
    catalog: RepoCatalog,
    http: reqwest::Client,
}

impl OriginEngine {
    /// Creates an Origin engine over an existing Loom dataset. The repo
    /// catalog defaults to the seeded entries until `repos.json` is written.
    #[must_use]
    pub fn new(store: PersistentLoomStore, config: OriginConfig) -> Self {
        let catalog = RepoCatalog::with_defaults(store.clone(), seed_entries(&config));
        Self {
            store,
            config,
            catalog,
            http: reqwest::Client::new(),
        }
    }

    /// Shared config used by HTTP handlers and apply helpers.
    #[must_use]
    pub const fn config(&self) -> &OriginConfig {
        &self.config
    }

    /// Durable repo catalog gating releases, mirrors, and deploys.
    #[must_use]
    pub const fn catalog(&self) -> &RepoCatalog {
        &self.catalog
    }

    /// Resolves a registered catalog entry, failing closed on storage errors.
    fn registered(&self, repository: &str) -> Result<RepoEntry, LoomError> {
        self.catalog
            .get(repository)?
            .ok_or_else(|| LoomError::OriginRepositoryDenied {
                repository: repository.to_owned(),
            })
    }

    /// True when the repository is registered. Storage failures read as false.
    fn is_registered(&self, repository: &str) -> bool {
        matches!(self.catalog.get(repository), Ok(Some(_)))
    }

    /// Reads one SHA-keyed release.
    ///
    /// # Errors
    ///
    /// Returns for lock or durable I/O failure.
    pub fn release(&self, repository: &str, oid: &str) -> Result<Option<OriginRelease>, LoomError> {
        self.registered(repository)?;
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
        self.registered(&release.repository)?;
        validate_oid(&release.git_oid)?;
        self.upsert(release)
    }

    /// Upserts a release from Loom candidate evidence (not Origin CI).
    ///
    /// # Errors
    ///
    /// Returns for an unknown repository, invalid SHA, or storage failure.
    pub fn record_loom_release(
        &self,
        repository: &str,
        git_oid: &str,
        tests_passed: bool,
    ) -> Result<OriginRelease, LoomError> {
        self.registered(repository)?;
        validate_oid(git_oid)?;
        let previous = self.release(repository, git_oid)?;
        let release = OriginRelease {
            repository: repository.to_owned(),
            git_oid: git_oid.to_owned(),
            job_id: previous
                .as_ref()
                .map_or_else(|| Uuid::now_v7().to_string(), |item| item.job_id.clone()),
            status: if tests_passed {
                CiStatus::Passed
            } else {
                CiStatus::Failed
            },
            tests_passed,
            log: previous
                .as_ref()
                .map(|item| item.log.clone())
                .filter(|log| !log.is_empty())
                .unwrap_or_else(|| "loom.evidence".to_owned()),
            origin_check_id: previous
                .as_ref()
                .and_then(|item| item.origin_check_id.clone()),
            deployed_oid: previous.and_then(|item| item.deployed_oid),
        };
        self.upsert(release)
    }

    /// Executes real CI for one Git-imported SHA and records the honest result.
    ///
    /// The SHA must have been imported through the Git gateway so Loom holds
    /// its exact tree (`git-mappings/`). The mapped revision is materialized
    /// and its `loom-ci.toml` pipeline runs through the same execution path
    /// candidate CI uses, including the configured Grid backend. Without a
    /// mapping there is no execution context: nothing is recorded and
    /// [`LoomError::UnknownRevision`] is returned.
    ///
    /// # Errors
    ///
    /// Returns for an unknown repository, invalid SHA, unmapped SHA, or
    /// storage failure.
    pub fn run_ci(&self, repository: &str, oid: &str) -> Result<OriginRelease, LoomError> {
        self.registered(repository)?;
        validate_oid(oid)?;
        let Some(revision) = self.revision_for_git_oid(repository, oid) else {
            return Err(LoomError::UnknownRevision {
                repository: repository.to_owned(),
                revision: oid.to_owned(),
            });
        };
        let previous = self.release(repository, oid)?;
        let job_id = previous
            .as_ref()
            .map_or_else(|| Uuid::now_v7().to_string(), |item| item.job_id.clone());
        let (passed, log) = CiEngine::new(self.store.clone()).run_revision(&revision, &job_id)?;
        let release = OriginRelease {
            repository: repository.to_owned(),
            git_oid: oid.to_owned(),
            job_id,
            status: if passed {
                CiStatus::Passed
            } else {
                CiStatus::Failed
            },
            tests_passed: passed,
            log: truncate_log(&log),
            origin_check_id: previous
                .as_ref()
                .and_then(|item| item.origin_check_id.clone()),
            deployed_oid: previous.and_then(|item| item.deployed_oid),
        };
        self.upsert(release)
    }

    /// Enqueues a best-effort Origin mirror push and processes it inline.
    ///
    /// Missing `git_oid` skips the push and records `error: "no git mapping"`.
    /// Network is never used when `mirror_runner` is [`OriginMirrorRunner::Fixed`].
    ///
    /// # Errors
    ///
    /// Returns for an unknown repository, invalid SHA, or storage failure.
    pub fn queue_mirror(
        &self,
        repository: &str,
        git_oid: Option<&str>,
    ) -> Result<OriginMirrorJob, LoomError> {
        self.registered(repository)?;
        let oid = git_oid
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if let Some(value) = oid.as_deref() {
            validate_oid(value)?;
        }
        let mut job = OriginMirrorJob {
            id: Uuid::now_v7().to_string(),
            repository: repository.to_owned(),
            git_oid: oid,
            status: OriginMirrorStatus::Pending,
            log: String::new(),
        };
        self.upsert_mirror(&job)?;
        self.process_mirror(&mut job);
        self.upsert_mirror(&job)?;
        Ok(job)
    }

    /// Lists persisted mirror jobs (oldest first).
    ///
    /// # Errors
    ///
    /// Returns for lock or durable I/O failure.
    pub fn mirrors(&self) -> Result<Vec<OriginMirrorJob>, LoomError> {
        let lock = self.store.shared_lock()?;
        let jobs = self.load_mirrors()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(jobs)
    }

    /// Resolves a Loom revision to a git OID via `git-mappings/`, if present.
    #[must_use]
    pub fn git_oid_for_revision(
        &self,
        repository: &str,
        revision: &RepositoryRevision,
    ) -> Option<String> {
        let directory = self.store.root.join("git-mappings").join(repository);
        let entries = std::fs::read_dir(directory).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(bytes) = read_bounded(&path, 4096) else {
                continue;
            };
            let Ok(mapping) = serde_json::from_slice::<GitRevisionMapping>(&bytes) else {
                continue;
            };
            if mapping.schema_version == "v1"
                && mapping.repository == repository
                && mapping.revision == *revision
                && validate_oid(&mapping.git_oid).is_ok()
            {
                return Some(mapping.git_oid);
            }
        }
        None
    }

    /// Resolves a Git-imported SHA to its native revision via `git-mappings/`.
    #[must_use]
    fn revision_for_git_oid(&self, repository: &str, oid: &str) -> Option<RepositoryRevision> {
        let path = self
            .store
            .root
            .join("git-mappings")
            .join(repository)
            .join(format!("{oid}.json"));
        let bytes = read_bounded(&path, 4096).ok()?;
        let mapping = serde_json::from_slice::<GitRevisionMapping>(&bytes).ok()?;
        (mapping.schema_version == "v1"
            && mapping.repository == repository
            && mapping.git_oid == oid
            && mapping.revision.repository == repository)
            .then_some(mapping.revision)
    }

    /// Fail-closed deploy: requires `tests_passed` for this exact SHA, then
    /// applies through the catalog entry's deploy target.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::OriginDeployBlocked`] when evidence is missing or
    /// failed, and [`LoomError::DeployUnconfigured`] when the catalog entry
    /// has no deploy target.
    pub fn deploy(&self, repository: &str, oid: &str) -> Result<OriginRelease, LoomError> {
        let entry = self.registered(repository)?;
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
        let log = apply_release(&self.config, &entry.deploy_target, repository, oid)?;
        let target_kind = match entry.deploy_target {
            DeployTarget::None => "none",
            DeployTarget::LocalApply { .. } => "local_apply",
            DeployTarget::SshApply { .. } => "ssh_apply",
        };
        if let Err(error) = EventLog::new(self.store.clone()).emit(
            "deploy.applied",
            [repository],
            serde_json::json!({
                "repo": repository,
                "git_oid": oid,
                "deploy_target": target_kind,
            }),
        ) {
            eprintln!("loom: event emit failed (deploy.applied): {error}");
        }
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

    /// Extracts registered CI targets from a verified Origin webhook body.
    /// Historical parser retained for tests; the webhook handler no longer runs CI.
    #[must_use]
    pub fn targets_from_webhook(&self, body: &[u8]) -> Vec<(String, String)> {
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
            .into_iter()
            .filter(|(repository, _)| self.is_registered(repository))
            .collect()
    }

    fn process_mirror(&self, job: &mut OriginMirrorJob) {
        let Some(oid) = job.git_oid.as_deref() else {
            job.status = OriginMirrorStatus::Error;
            "no git mapping".clone_into(&mut job.log);
            return;
        };
        match &self.config.mirror_runner {
            OriginMirrorRunner::Fixed { ok, log } => {
                job.status = if *ok {
                    OriginMirrorStatus::Ok
                } else {
                    OriginMirrorStatus::Error
                };
                job.log = truncate_log(log);
            }
            OriginMirrorRunner::Git => match self.push_mirror(&job.repository, oid) {
                Ok(log) => {
                    job.status = OriginMirrorStatus::Ok;
                    job.log = truncate_log(&log);
                }
                Err(error) => {
                    job.status = OriginMirrorStatus::Error;
                    job.log = truncate_log(&error.to_string());
                }
            },
        }
    }

    fn push_mirror(&self, repository: &str, oid: &str) -> Result<String, LoomError> {
        let bare = self
            .store
            .root
            .join("git")
            .join(format!("{repository}.git"));
        if !bare.is_dir() {
            return Err(LoomError::OriginUnavailable);
        }
        let token = self.config.clone_token.clone().unwrap_or_default();
        let url = mirror_push_url(&self.config, repository, &token);
        let spec = format!("{oid}:refs/heads/main");
        git(
            &self.config.git_program,
            &["push", "--force", &url, &spec],
            &bare,
        )
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

    fn upsert_mirror(&self, job: &OriginMirrorJob) -> Result<(), LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut jobs = self.load_mirrors()?;
        if let Some(existing) = jobs.iter_mut().find(|item| item.id == job.id) {
            *existing = job.clone();
        } else {
            jobs.push(job.clone());
        }
        if jobs.len() > MAX_JOBS {
            return Err(LoomError::ResourceLimit);
        }
        let persisted = PersistedMirrors {
            schema_version: "v1".to_owned(),
            jobs,
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        write_atomic(
            &self.store.root,
            &self.store.root.join("mirror_queue.json"),
            &bytes,
            0o600,
        )?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(())
    }

    fn load_mirrors(&self) -> Result<Vec<OriginMirrorJob>, LoomError> {
        let path = self.store.root.join("mirror_queue.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = read_bounded(&path, MAX_ORIGIN_BYTES)?;
        let persisted: PersistedMirrors =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(persisted.jobs)
    }
}

/// Request body for `POST /v1/releases/{repo}/ci`.
#[derive(Debug, Clone, Deserialize)]
pub struct OriginCiRequest {
    /// Git object id to record evidence for.
    #[serde(alias = "oid", alias = "sha")]
    pub git_oid: String,
}

/// Public evidence document consumed by deploy.
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

fn looks_like_host(value: &str) -> bool {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    !rest.is_empty() && !rest.contains('/')
}

fn inject_token(url: &str, token: &str) -> String {
    if token.is_empty() || url.contains('@') {
        return url.to_owned();
    }
    if let Some(rest) = url.strip_prefix("https://") {
        format!("https://x-access-token:{token}@{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("http://x-access-token:{token}@{rest}")
    } else {
        url.to_owned()
    }
}

fn mirror_push_url(config: &OriginConfig, repository: &str, token: &str) -> String {
    let rendered = if let Some(remote) = config
        .mirror_remote
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let with_owner = remote.replace("{owner}", &config.owner);
        if with_owner.contains("{repo}") || with_owner.contains("{repository}") {
            with_owner
                .replace("{repo}", repository)
                .replace("{repository}", repository)
        } else if looks_like_host(&with_owner) {
            let host = with_owner
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            format!("https://{}/{}/{repository}.git", host, config.owner)
        } else {
            let trimmed = with_owner.trim_end_matches('/');
            let has_git_suffix = std::path::Path::new(trimmed)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("git"));
            if has_git_suffix {
                trimmed.to_owned()
            } else {
                format!("{}/{}/{repository}.git", trimmed, config.owner)
            }
        }
    } else {
        format!(
            "https://{}/{}/{repository}.git",
            config.clone_host, config.owner
        )
    };
    inject_token(&rendered, token)
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

fn extract_targets(event_type: &str, payload: &serde_json::Value) -> Vec<(String, String)> {
    let repo = payload
        .pointer("/repository/name")
        .or_else(|| payload.pointer("/repo/name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    if repo.is_empty() {
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
