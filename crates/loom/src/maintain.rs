//! Maintain queue: wakes, dedup, policy, and LTS cutover bookkeeping.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::ControlStore;
use crate::features::{FeatureClass, FeatureCreate, FeatureStore, Scenario};
use crate::project::Project;
use crate::{LoomError, PersistentLoomStore};

/// One queued or running maintain job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainJob {
    /// Durable id.
    pub id: String,
    /// Catalog repo.
    pub repo: String,
    /// Subclass (`deps`, `security`, `runtime`, `lint`).
    pub subclass: String,
    /// Dedup fingerprint.
    pub fingerprint: String,
    /// `queued`, `running`, `blocked`, `done`, `failed`.
    pub status: String,
    /// Optional block reason (`agent_unconfigured`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// Linked feature id when created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_id: Option<String>,
}

/// Queue status for the dashboard and CLI.
#[derive(Debug, Clone, Serialize)]
pub struct MaintainStatus {
    /// True when `LOOM_AGENT_API_KEY` is set.
    pub agent_configured: bool,
    /// Open jobs.
    pub jobs: Vec<MaintainJob>,
}

/// Enqueues a job if no open duplicate exists.
///
/// # Errors
///
/// Returns for control I/O failure.
pub fn enqueue(
    control: &ControlStore,
    repo: &str,
    subclass: &str,
    fingerprint: &str,
    agent_configured: bool,
) -> Result<MaintainJob, LoomError> {
    for job in control.list_jobs()? {
        if job.repo == repo
            && job.subclass == subclass
            && job.fingerprint == fingerprint
            && matches!(job.status.as_str(), "queued" | "running" | "blocked")
        {
            return Ok(job);
        }
    }
    let mut job = MaintainJob {
        id: format!("job_{}", Uuid::now_v7()),
        repo: repo.to_owned(),
        subclass: subclass.to_owned(),
        fingerprint: fingerprint.to_owned(),
        status: "queued".to_owned(),
        blocked: None,
        feature_id: None,
    };
    if !agent_configured {
        "blocked".clone_into(&mut job.status);
        job.blocked = Some("agent_unconfigured".to_owned());
    }
    control.upsert_job(job)
}

/// Creates a born-approved maintenance feature for a job.
///
/// # Errors
///
/// Returns for feature I/O failure.
pub fn open_feature(
    features: &FeatureStore,
    job: &MaintainJob,
    title: String,
    repositories: Vec<crate::contracts::RepositoryBinding>,
) -> Result<crate::features::Feature, LoomError> {
    features.create_with_authority(
        FeatureCreate {
            title,
            repositories,
            scenarios: vec![Scenario {
                name: job.subclass.clone(),
                given: "the catalog repo is registered".to_owned(),
                when: format!("{} {}", job.subclass, job.fingerprint),
                then: "tests, smoke, and health pass".to_owned(),
            }],
            evidence_policy: crate::features::EvidencePolicy::minimum(),
            class: FeatureClass::Maintenance,
            subclass: Some(job.subclass.clone()),
            fingerprint: Some(job.fingerprint.clone()),
        },
        true,
    )
}

/// True when a project is paused.
#[must_use]
pub fn paused(project: &Project) -> bool {
    project.maintain_policy.paused
}

/// First-boot helper: mint a maintain bot if `maintain.token` is absent.
///
/// # Errors
///
/// Returns for token or I/O failure.
pub fn ensure_maintain_bot(
    store: &PersistentLoomStore,
    tokens: &crate::tokens::TokenStore,
) -> Result<Option<String>, LoomError> {
    let path = store.root.join("maintain.token");
    if path.exists() {
        return Ok(None);
    }
    let minted = tokens.mint(&crate::tokens::TokenMint {
        name: "maintain-bot".to_owned(),
        repositories: vec!["loom".to_owned()],
        perms: vec![
            crate::tokens::TokenPerm::Maintain,
            crate::tokens::TokenPerm::Features,
            crate::tokens::TokenPerm::Evidence,
            crate::tokens::TokenPerm::Events,
        ],
        feature_id: None,
        review_id: None,
        expires_at: None,
    })?;
    crate::write_atomic(&store.root, &path, minted.secret.as_bytes(), 0o600)?;
    Ok(Some(path.display().to_string()))
}
