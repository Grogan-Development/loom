//! Feature contracts: the PR replacement. No Nero, Restate, or Kiln.

use std::collections::BTreeMap;
use std::fs::File;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::contracts::{
    ArtifactDigest, RepositoryBinding, RepositoryRevision, validate_repository_ref,
};
use crate::{LoomError, PersistentLoomStore, RefCasUpdate};

const MAX_FEATURE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FEATURES: usize = 10_000;

/// Two-gate feature lifecycle. Gate 1 authorizes work; Gate 2 promotes source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureGate {
    /// Awaiting owner approval to run CI against a candidate.
    Draft,
    /// Approved; candidate heads may be submitted and verified.
    Approved,
    /// Candidate accepted and protected refs promoted.
    Accepted,
    /// Candidate retained for diagnosis; refs unchanged.
    Rejected,
}

/// Human-observable behavior a feature must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Short scenario name.
    pub name: String,
    /// Required starting state.
    pub given: String,
    /// Owner or system action.
    pub when: String,
    /// Observable expected result.
    pub then: String,
}

/// Evidence required before Gate 2 promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    /// Automated tests must pass against the candidate heads.
    pub require_automated_tests: bool,
    /// Promotion must retain an exact reverse compare-and-swap.
    pub require_rollback_proof: bool,
}

impl EvidencePolicy {
    /// Smallest acceptable policy for a standalone Loom.
    #[must_use]
    pub const fn minimum() -> Self {
        Self {
            require_automated_tests: true,
            require_rollback_proof: true,
        }
    }
}

/// Digest-bound CI evidence pinned to one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// SHA-256 of the canonical evidence document.
    pub digest: ArtifactDigest,
    /// True only when required tests passed.
    pub tests_passed: bool,
    /// CI job that produced this bundle.
    pub job_id: String,
    /// Truncated command log.
    pub log: String,
}

/// Immutable candidate assembled after CI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Durable candidate identifier.
    pub id: String,
    /// Exact heads under test, with protected target refs.
    pub repositories: Vec<RepositoryBinding>,
    /// CI evidence required by the feature policy.
    pub evidence: EvidenceBundle,
}

/// Owner-approved execution contract that replaces a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feature {
    /// Contract schema version.
    pub schema_version: String,
    /// Durable feature identifier.
    pub id: String,
    /// Owner-facing outcome.
    pub title: String,
    /// Target repository bindings.
    pub repositories: Vec<RepositoryBinding>,
    /// Acceptance scenarios.
    pub scenarios: Vec<Scenario>,
    /// Evidence required for Gate 2.
    pub evidence_policy: EvidencePolicy,
    /// Current two-gate state.
    pub gate: FeatureGate,
    /// Submitted candidate, if any.
    pub candidate: Option<Candidate>,
    /// Exact reverse CAS captured at promotion.
    pub rollback: Option<Vec<RefCasUpdate>>,
}

/// Create-feature request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureCreate {
    /// Owner-facing outcome.
    pub title: String,
    /// Target repository bindings.
    pub repositories: Vec<RepositoryBinding>,
    /// Acceptance scenarios.
    pub scenarios: Vec<Scenario>,
    /// Evidence required for Gate 2.
    #[serde(default = "EvidencePolicy::minimum")]
    pub evidence_policy: EvidencePolicy,
}

/// Submit a candidate against an approved feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSubmit {
    /// Exact heads to verify and test.
    pub repositories: Vec<RepositoryBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedFeatures {
    schema_version: String,
    features: Vec<Feature>,
}

/// Durable feature catalog stored beside the Loom CAS.
#[derive(Debug, Clone)]
pub struct FeatureStore {
    store: PersistentLoomStore,
}

impl FeatureStore {
    /// Opens the feature catalog inside an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Shared Loom store used for verify, materialize, and CAS.
    #[must_use]
    pub const fn loom(&self) -> &PersistentLoomStore {
        &self.store
    }

    /// Creates a Gate 1 draft.
    ///
    /// # Errors
    ///
    /// Returns for empty titles, invalid refs, or durable I/O failure.
    pub fn create(&self, request: FeatureCreate) -> Result<Feature, LoomError> {
        validate_create(&request)?;
        let feature = Feature {
            schema_version: "v1".to_owned(),
            id: Uuid::now_v7().to_string(),
            title: request.title,
            repositories: request.repositories,
            scenarios: request.scenarios,
            evidence_policy: request.evidence_policy,
            gate: FeatureGate::Draft,
            candidate: None,
            rollback: None,
        };
        let lock = self.store.exclusive_lock()?;
        let mut features = self.load()?;
        features.insert(feature.id.clone(), feature.clone());
        self.write(&features)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(feature)
    }

    /// Reads one feature by id.
    ///
    /// # Errors
    ///
    /// Returns `UnknownRevision` when the feature is absent.
    pub fn get(&self, id: &str) -> Result<Feature, LoomError> {
        let lock = self.store.shared_lock()?;
        let features = self.load()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        features.get(id).cloned().ok_or_else(|| unknown_feature(id))
    }

    /// Lists features newest-id first.
    ///
    /// # Errors
    ///
    /// Returns for durable I/O failure.
    pub fn list(&self) -> Result<Vec<Feature>, LoomError> {
        let lock = self.store.shared_lock()?;
        let mut features = self.load()?.into_values().collect::<Vec<_>>();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        features.sort_by(|left, right| right.id.cmp(&left.id));
        Ok(features)
    }

    /// Approves Gate 1. Work and CI may proceed.
    ///
    /// # Errors
    ///
    /// Returns unless the feature is a draft.
    pub fn approve(&self, id: &str) -> Result<Feature, LoomError> {
        self.transition(id, |feature| {
            if feature.gate != FeatureGate::Draft {
                return Err(LoomError::InvalidSourceCommit);
            }
            feature.gate = FeatureGate::Approved;
            Ok(())
        })
    }

    /// Attaches a verified candidate after CI.
    ///
    /// # Errors
    ///
    /// Returns unless the feature is approved and has no candidate.
    pub fn attach_candidate(&self, id: &str, candidate: Candidate) -> Result<Feature, LoomError> {
        self.transition(id, |feature| {
            if feature.gate != FeatureGate::Approved || feature.candidate.is_some() {
                return Err(LoomError::InvalidSourceCommit);
            }
            feature.repositories.clone_from(&candidate.repositories);
            feature.candidate = Some(candidate);
            Ok(())
        })
    }

    /// Accepts Gate 2 after protected-ref promotion.
    ///
    /// # Errors
    ///
    /// Returns unless a passing candidate is attached.
    pub fn accept(&self, id: &str, rollback: Vec<RefCasUpdate>) -> Result<Feature, LoomError> {
        self.transition(id, |feature| {
            let Some(candidate) = feature.candidate.as_ref() else {
                return Err(LoomError::InvalidSourceCommit);
            };
            if feature.gate != FeatureGate::Approved || !candidate.evidence.tests_passed {
                return Err(LoomError::InvalidSourceCommit);
            }
            feature.gate = FeatureGate::Accepted;
            feature.rollback = Some(rollback);
            Ok(())
        })
    }

    /// Rejects Gate 2 and retains the candidate.
    ///
    /// # Errors
    ///
    /// Returns unless the feature is approved with a candidate.
    pub fn reject(&self, id: &str) -> Result<Feature, LoomError> {
        self.transition(id, |feature| {
            if feature.gate != FeatureGate::Approved || feature.candidate.is_none() {
                return Err(LoomError::InvalidSourceCommit);
            }
            feature.gate = FeatureGate::Rejected;
            Ok(())
        })
    }

    fn transition(
        &self,
        id: &str,
        mutate: impl FnOnce(&mut Feature) -> Result<(), LoomError>,
    ) -> Result<Feature, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut features = self.load()?;
        let feature = features.get_mut(id).ok_or_else(|| unknown_feature(id))?;
        mutate(feature)?;
        let result = feature.clone();
        self.write(&features)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(result)
    }

    fn load(&self) -> Result<BTreeMap<String, Feature>, LoomError> {
        let path = self.store.root.join("features.json");
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = crate::read_bounded(&path, MAX_FEATURE_BYTES)?;
        let persisted: PersistedFeatures =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" || persisted.features.len() > MAX_FEATURES {
            return Err(LoomError::CorruptState);
        }
        let mut features = BTreeMap::new();
        for feature in persisted.features {
            if features.insert(feature.id.clone(), feature).is_some() {
                return Err(LoomError::CorruptState);
            }
        }
        Ok(features)
    }

    fn write(&self, features: &BTreeMap<String, Feature>) -> Result<(), LoomError> {
        let persisted = PersistedFeatures {
            schema_version: "v1".to_owned(),
            features: features.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_FEATURE_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        crate::write_atomic(
            &self.store.root,
            &self.store.root.join("features.json"),
            &bytes,
            0o600,
        )
    }
}

fn validate_create(request: &FeatureCreate) -> Result<(), LoomError> {
    if request.title.trim().is_empty() {
        return Err(LoomError::InvalidSourceCommit);
    }
    if request.repositories.is_empty() || request.repositories.len() > 128 {
        return Err(LoomError::ResourceLimit);
    }
    for binding in &request.repositories {
        binding
            .base
            .validate()
            .map_err(|_| LoomError::InvalidSourceCommit)?;
        if let Some(head) = &binding.head {
            head.validate()
                .map_err(|_| LoomError::InvalidSourceCommit)?;
            if head.repository != binding.base.repository {
                return Err(LoomError::InvalidSourceCommit);
            }
        }
        validate_repository_ref(&binding.target_ref).map_err(|_| LoomError::InvalidRef {
            ref_name: binding.target_ref.clone(),
        })?;
    }
    for scenario in &request.scenarios {
        if scenario.name.trim().is_empty()
            || scenario.given.trim().is_empty()
            || scenario.when.trim().is_empty()
            || scenario.then.trim().is_empty()
        {
            return Err(LoomError::InvalidSourceCommit);
        }
    }
    Ok(())
}

fn unknown_feature(id: &str) -> LoomError {
    LoomError::UnknownRevision {
        repository: "features".to_owned(),
        revision: id.to_owned(),
    }
}

/// Builds the protected-ref CAS batch for one candidate.
#[must_use]
pub fn promotion_updates(bindings: &[RepositoryBinding]) -> Option<Vec<RefCasUpdate>> {
    let mut updates = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let head = binding.head.as_ref()?;
        updates.push(RefCasUpdate::new(
            binding.base.repository.clone(),
            binding.target_ref.clone(),
            binding.base.clone(),
            head.clone(),
        ));
    }
    Some(updates)
}

/// Source-digest cache key for lightning CI replay.
#[must_use]
pub fn candidate_source_key(bindings: &[RepositoryBinding]) -> Option<String> {
    let mut parts = Vec::new();
    for binding in bindings {
        let head = binding.head.as_ref()?;
        parts.push(format!(
            "{}:{}:{}",
            binding.base.repository, binding.base.revision, head.revision
        ));
    }
    parts.sort();
    Some(parts.join("|"))
}

/// Unused import keeper for revision type in docs/tests.
#[must_use]
pub fn revision_repository(revision: &RepositoryRevision) -> &str {
    &revision.repository
}
