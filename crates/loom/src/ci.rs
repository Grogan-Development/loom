//! Lightning CI: digest-cached tests bound to candidate heads. No Nero or Restate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::contracts::{ArtifactDigest, RepositoryBinding, RepositoryRevision};
use crate::features::{Candidate, EvidenceBundle, candidate_source_key};
use crate::runner::{LocalProcessRunner, Runner as _};
use crate::{
    CandidateRevisionStatus, LoomError, NamespaceGrant, PersistentLoomStore, SourceFileMode,
    digest_bytes, read_bounded, repository_storage_name, write_atomic,
};

const MAX_CI_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOBS: usize = 10_000;
const MAX_LOG_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Status of one lightning CI job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStatus {
    /// Job is queued.
    Pending,
    /// Tests are running.
    Running,
    /// Required tests passed.
    Passed,
    /// Tests failed or timed out.
    Failed,
}

/// Durable CI job keyed by candidate source digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiJob {
    /// Durable job identifier.
    pub id: String,
    /// Feature that requested the job.
    pub feature_id: String,
    /// Canonical source key (repo:base:head…).
    pub source_key: String,
    /// Current status.
    pub status: CiStatus,
    /// Combined command log, truncated.
    pub log: String,
    /// Evidence digest when the job finished.
    pub evidence_digest: Option<ArtifactDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedJobs {
    schema_version: String,
    jobs: Vec<CiJob>,
}

#[derive(Debug, Clone, Deserialize)]
struct LoomCiFile {
    #[serde(default)]
    ci: CiSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CiSection {
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    commands: Vec<Vec<String>>,
}

const fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

/// Digest-cached test runner rooted in the Loom dataset.
#[derive(Debug, Clone)]
pub struct CiEngine {
    store: PersistentLoomStore,
}

impl CiEngine {
    /// Creates a CI engine over an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Verifies candidate reachability and protected-ref-at-base.
    #[must_use]
    pub fn verify(&self, bindings: &[RepositoryBinding]) -> CandidateRevisionStatus {
        if bindings.is_empty() || bindings.len() > 128 {
            return CandidateRevisionStatus {
                ready: false,
                failures: vec!["loom.bindings_invalid".to_owned()],
            };
        }
        let grant = NamespaceGrant::new(
            bindings
                .iter()
                .map(|binding| binding.base.repository.clone())
                .collect(),
        );
        let mut failures = BTreeSet::new();
        for binding in bindings {
            let Some(head) = &binding.head else {
                failures.insert("loom.head_missing".to_owned());
                continue;
            };
            if self.store.has_revision(&grant, &binding.base).is_err()
                || self.store.has_revision(&grant, head).is_err()
            {
                failures.insert("loom.revision_unavailable".to_owned());
                continue;
            }
            if self
                .store
                .resolve_ref(&grant, &binding.base.repository, &binding.target_ref)
                .as_ref()
                != Ok(&binding.base)
            {
                failures.insert("loom.ref_not_at_base".to_owned());
            }
        }
        let failures = failures.into_iter().collect::<Vec<_>>();
        CandidateRevisionStatus {
            ready: failures.is_empty(),
            failures,
        }
    }

    /// Runs or replays lightning CI for one approved feature candidate.
    ///
    /// # Errors
    ///
    /// Returns when the candidate is not ready, materialization fails, or storage fails.
    pub fn run(
        &self,
        feature_id: &str,
        bindings: &[RepositoryBinding],
    ) -> Result<CiJob, LoomError> {
        let source_key = candidate_source_key(bindings).ok_or(LoomError::InvalidSourceCommit)?;
        let status = self.verify(bindings);
        if !status.ready {
            return Err(LoomError::UnknownRevision {
                repository: bindings.first().map_or_else(
                    || "unknown".to_owned(),
                    |binding| binding.base.repository.clone(),
                ),
                revision: status.failures.join(","),
            });
        }
        if let Some(cached) = self.cached_pass(&source_key)? {
            return Ok(cached);
        }
        let mut job = CiJob {
            id: Uuid::now_v7().to_string(),
            feature_id: feature_id.to_owned(),
            source_key: source_key.clone(),
            status: CiStatus::Running,
            log: String::new(),
            evidence_digest: None,
        };
        self.upsert(&job)?;
        match self.execute(bindings, &job.id) {
            Ok((passed, log)) => {
                job.log = truncate_log(&log);
                job.status = if passed {
                    CiStatus::Passed
                } else {
                    CiStatus::Failed
                };
                job.evidence_digest = Some(digest_bytes(job.log.as_bytes()));
            }
            Err(error) => {
                job.status = CiStatus::Failed;
                job.log = truncate_log(&error.to_string());
            }
        }
        self.upsert(&job)?;
        Ok(job)
    }

    /// Materializes one already-imported revision and runs its CI pipeline,
    /// through the exact execution path candidate CI uses (including the
    /// configured Grid backend). Returns whether the pipeline passed and the
    /// combined command log.
    ///
    /// # Errors
    ///
    /// Returns when the revision cannot be materialized or a command cannot
    /// be spawned.
    pub fn run_revision(
        &self,
        revision: &RepositoryRevision,
        job_id: &str,
    ) -> Result<(bool, String), LoomError> {
        let binding = RepositoryBinding {
            base: revision.clone(),
            head: Some(revision.clone()),
            target_ref: "refs/main".to_owned(),
        };
        self.execute(std::slice::from_ref(&binding), job_id)
    }

    /// Converts a passing job into a candidate evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns unless the job passed and produced an evidence digest.
    pub fn candidate_from_job(
        &self,
        job: &CiJob,
        bindings: Vec<RepositoryBinding>,
    ) -> Result<Candidate, LoomError> {
        if job.status != CiStatus::Passed {
            return Err(LoomError::InvalidSourceCommit);
        }
        let digest = job
            .evidence_digest
            .clone()
            .ok_or(LoomError::InvalidSourceCommit)?;
        Ok(Candidate {
            id: job.id.clone(),
            repositories: bindings,
            evidence: EvidenceBundle {
                digest,
                tests_passed: true,
                job_id: job.id.clone(),
                log: job.log.clone(),
            },
            insights: None, // insights-slice
        })
    }

    fn cached_pass(&self, source_key: &str) -> Result<Option<CiJob>, LoomError> {
        let lock = self.store.shared_lock()?;
        let jobs = self.load()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(jobs
            .into_values()
            .find(|job| job.source_key == source_key && job.status == CiStatus::Passed))
    }

    fn execute(
        &self,
        bindings: &[RepositoryBinding],
        _job_id: &str,
    ) -> Result<(bool, String), LoomError> {
        let grant = NamespaceGrant::new(
            bindings
                .iter()
                .map(|binding| binding.base.repository.clone())
                .collect(),
        );
        let workspace = tempfile::tempdir().map_err(|_| LoomError::StorageUnavailable)?;
        let mut log = String::new();
        let mut all_passed = true;
        let runner = LocalProcessRunner;
        for binding in bindings {
            let head = binding
                .head
                .as_ref()
                .ok_or(LoomError::InvalidSourceCommit)?;
            let files = self.store.materialize_source(&grant, head)?;
            let repo_root = workspace
                .path()
                .join(repository_storage_name(&binding.base.repository));
            fs::create_dir_all(&repo_root).map_err(|_| LoomError::StorageUnavailable)?;
            write_tree(&repo_root, &files)?;
            let (commands, timeout) = pipeline_for(&repo_root);
            for command in commands {
                let (passed, output) = runner.run(&repo_root, &command, timeout)?;
                log.push('$');
                log.push(' ');
                log.push_str(&command.join(" "));
                log.push('\n');
                log.push_str(&output);
                log.push('\n');
                all_passed &= passed;
                if !passed {
                    break;
                }
            }
        }
        Ok((all_passed, log))
    }

    fn upsert(&self, job: &CiJob) -> Result<(), LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut jobs = self.load()?;
        jobs.insert(job.id.clone(), job.clone());
        if jobs.len() > MAX_JOBS {
            return Err(LoomError::ResourceLimit);
        }
        let persisted = PersistedJobs {
            schema_version: "v1".to_owned(),
            jobs: jobs.into_values().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        write_atomic(
            &self.store.root,
            &self.store.root.join("ci-jobs.json"),
            &bytes,
            0o600,
        )?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    fn load(&self) -> Result<BTreeMap<String, CiJob>, LoomError> {
        let path = self.store.root.join("ci-jobs.json");
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = read_bounded(&path, MAX_CI_BYTES)?;
        let persisted: PersistedJobs =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(persisted
            .jobs
            .into_iter()
            .map(|job| (job.id.clone(), job))
            .collect())
    }
}

fn write_tree(
    root: &Path,
    files: &BTreeMap<String, crate::MaterializedSourceFile>,
) -> Result<(), LoomError> {
    for (path, file) in files {
        let destination = root.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|_| LoomError::StorageUnavailable)?;
        }
        match file.mode {
            SourceFileMode::Symlink => {
                let target = std::str::from_utf8(&file.contents)
                    .map_err(|_| LoomError::InvalidSourceCommit)?;
                std::os::unix::fs::symlink(target, &destination)
                    .map_err(|_| LoomError::StorageUnavailable)?;
            }
            SourceFileMode::Regular | SourceFileMode::Executable => {
                let mut output =
                    File::create(&destination).map_err(|_| LoomError::StorageUnavailable)?;
                output
                    .write_all(&file.contents)
                    .map_err(|_| LoomError::StorageUnavailable)?;
                if file.mode == SourceFileMode::Executable {
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
                        .map_err(|_| LoomError::StorageUnavailable)?;
                }
            }
        }
    }
    Ok(())
}

/// Loads `loom-ci.toml` from `root`, or the language-default pipeline.
#[must_use]
pub fn load_pipeline(root: &Path) -> (Vec<Vec<String>>, Duration) {
    pipeline_for(root)
}

/// Runs one CI argv with a wall-clock timeout. The program name cannot contain `/`.
///
/// # Errors
///
/// Returns when the argv is empty, the program path is unsafe, or the process cannot be spawned.
pub fn execute_command(
    cwd: &Path,
    command: &[String],
    timeout: Duration,
) -> Result<(bool, String), LoomError> {
    LocalProcessRunner.run(cwd, command, timeout)
}

pub(crate) fn pipeline_for(root: &Path) -> (Vec<Vec<String>>, Duration) {
    let config_path = root.join("loom-ci.toml");
    if let Ok(bytes) = fs::read(&config_path)
        && let Ok(parsed) = toml::from_slice::<LoomCiFile>(&bytes)
        && !parsed.ci.commands.is_empty()
    {
        return (
            parsed.ci.commands,
            Duration::from_secs(parsed.ci.timeout_seconds.max(1)),
        );
    }
    let commands = if root.join("Cargo.toml").exists() {
        vec![vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "--offline".to_owned(),
            "--quiet".to_owned(),
        ]]
    } else if root.join("go.mod").exists() {
        vec![vec!["go".to_owned(), "test".to_owned(), "./...".to_owned()]]
    } else if root.join("pyproject.toml").exists()
        || root.join("requirements.txt").exists()
        || root.join("setup.py").exists()
    {
        vec![vec![
            "python".to_owned(),
            "-m".to_owned(),
            "unittest".to_owned(),
            "discover".to_owned(),
        ]]
    } else if root.join("package.json").exists() {
        vec![vec!["npm".to_owned(), "test".to_owned()]]
    } else {
        vec![vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "test -n \"$(ls -A)\"".to_owned(),
        ]]
    };
    (commands, Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

pub(crate) fn truncate_log(log: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(log.as_bytes());
    if log.len() <= MAX_LOG_BYTES {
        log.to_owned()
    } else {
        format!(
            "{}\n… truncated {} bytes",
            &log[..MAX_LOG_BYTES],
            log.len() - MAX_LOG_BYTES
        )
    }
}

/// Absolute workspace helper used by tests.
#[must_use]
pub fn workspace_path(root: &Path, repository: &str) -> PathBuf {
    root.join(repository)
}
