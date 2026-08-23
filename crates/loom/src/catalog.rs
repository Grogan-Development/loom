//! Typed, durable repository catalog.
//!
//! The catalog lives in `repos.json` under the store lock. First start writes
//! an empty catalog ([`seed_entries`]); afterwards the owner CRUD API is the
//! single source of truth. Repository names may be a legacy identifier or
//! `project/repo`.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::contracts::validate_repository_ref;
use crate::origin::OriginConfig;
use crate::{LoomError, PersistentLoomStore, read_bounded, validate_repository, write_atomic};

const MAX_CATALOG_BYTES: u64 = 1024 * 1024;
const MAX_REPOS: usize = 1024;
const MAX_DESCRIPTION_CHARS: usize = 512;

/// Default protected ref for catalog entries.
pub const DEFAULT_PROTECTED_REF: &str = "refs/main";

/// How releases for a repository are applied to their runtime host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeployTarget {
    /// The repository has no deploy path; deploy requests are refused.
    None,
    /// Run an apply script locally on the Loom host.
    LocalApply {
        /// Absolute apply script path on the Loom host.
        script: PathBuf,
    },
    /// Run an apply script on a remote host over SSH.
    SshApply {
        /// SSH host. `None` falls back to the configured deploy SSH host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// Absolute apply script path on the remote host.
        script: PathBuf,
    },
}

/// CI policy for a repository.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiPolicy {
    /// Run the repository's `loom-ci.toml` (or the language-default pipeline).
    #[default]
    LoomCi,
}

/// One durable catalog entry describing a repository Loom serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    /// Repository namespace, validated like every other Loom namespace.
    pub name: String,
    /// Protected ref promoted on acceptance and created by bootstrap.
    pub protected_ref: String,
    /// Absolute deploy checkout path on the target host, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout_path: Option<PathBuf>,
    /// CI policy applied to candidates and release evidence.
    #[serde(default)]
    pub ci: CiPolicy,
    /// Deploy target consulted by the release apply path.
    pub deploy_target: DeployTarget,
    /// Owner-facing description.
    #[serde(default)]
    pub description: String,
}

impl RepoEntry {
    /// Minimal entry: protected at [`DEFAULT_PROTECTED_REF`], default CI
    /// policy, and no deploy target.
    #[must_use]
    pub fn minimal(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protected_ref: DEFAULT_PROTECTED_REF.to_owned(),
            checkout_path: None,
            ci: CiPolicy::default(),
            deploy_target: DeployTarget::None,
            description: String::new(),
        }
    }
}

/// Owner request to create or replace one catalog entry.
///
/// Only `name` is required; everything else defaults to a non-deployable
/// entry protected at [`DEFAULT_PROTECTED_REF`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoUpsert {
    /// Repository namespace.
    pub name: String,
    /// Protected ref. Defaults to `refs/main`.
    #[serde(default)]
    pub protected_ref: Option<String>,
    /// Absolute deploy checkout path.
    #[serde(default)]
    pub checkout_path: Option<PathBuf>,
    /// CI policy. Defaults to `loom_ci`.
    #[serde(default)]
    pub ci: Option<CiPolicy>,
    /// Deploy target. Defaults to `none`.
    #[serde(default)]
    pub deploy_target: Option<DeployTarget>,
    /// Owner-facing description.
    #[serde(default)]
    pub description: Option<String>,
}

impl RepoUpsert {
    /// Applies defaults and validates the request into a durable entry.
    ///
    /// # Errors
    ///
    /// Returns for an invalid name, ref, path, host, or description.
    pub fn into_entry(self) -> Result<RepoEntry, LoomError> {
        let entry = RepoEntry {
            name: self.name,
            protected_ref: self
                .protected_ref
                .unwrap_or_else(|| DEFAULT_PROTECTED_REF.to_owned()),
            checkout_path: self.checkout_path,
            ci: self.ci.unwrap_or_default(),
            deploy_target: self.deploy_target.unwrap_or(DeployTarget::None),
            description: self.description.unwrap_or_default(),
        };
        validate_entry(&entry)?;
        Ok(entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRepos {
    schema_version: String,
    repos: Vec<RepoEntry>,
}

/// Durable repository catalog stored beside the Loom CAS.
#[derive(Debug, Clone)]
pub struct RepoCatalog {
    store: PersistentLoomStore,
    defaults: Arc<BTreeMap<String, RepoEntry>>,
}

impl RepoCatalog {
    /// Opens the catalog without in-memory defaults; only `repos.json` counts.
    #[must_use]
    pub fn open(store: PersistentLoomStore) -> Self {
        Self {
            store,
            defaults: Arc::new(BTreeMap::new()),
        }
    }

    /// Opens the catalog with defaults visible until `repos.json` exists.
    #[must_use]
    pub fn with_defaults(store: PersistentLoomStore, defaults: Vec<RepoEntry>) -> Self {
        Self {
            store,
            defaults: Arc::new(
                defaults
                    .into_iter()
                    .map(|entry| (entry.name.clone(), entry))
                    .collect(),
            ),
        }
    }

    /// Persists the defaults on first load. A present `repos.json` is kept
    /// verbatim so owner edits (including deletions) survive restarts.
    ///
    /// # Errors
    ///
    /// Returns for lock, serialization, or durable I/O failure.
    pub fn ensure_seeded(&self) -> Result<(), LoomError> {
        let lock = self.store.exclusive_lock()?;
        if !self.path().exists() {
            self.write(&self.defaults.as_ref().clone())?;
        }
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    /// Lists catalog entries sorted by name.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or durable I/O failure.
    pub fn list(&self) -> Result<Vec<RepoEntry>, LoomError> {
        let lock = self.store.shared_lock()?;
        let entries = self.load()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(entries.into_values().collect())
    }

    /// Reads one catalog entry by repository name.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or durable I/O failure.
    pub fn get(&self, name: &str) -> Result<Option<RepoEntry>, LoomError> {
        let lock = self.store.shared_lock()?;
        let entry = self.load()?.remove(name);
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(entry)
    }

    /// Creates or replaces one catalog entry.
    ///
    /// # Errors
    ///
    /// Returns for an invalid entry, resource bounds, lock, or I/O failure.
    pub fn upsert(&self, entry: RepoEntry) -> Result<RepoEntry, LoomError> {
        validate_entry(&entry)?;
        let lock = self.store.exclusive_lock()?;
        let mut entries = self.load()?;
        entries.insert(entry.name.clone(), entry.clone());
        if entries.len() > MAX_REPOS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&entries)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(entry)
    }

    /// Removes one catalog entry by name.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::UnknownRepo`] when absent, or for lock/I/O failure.
    pub fn remove(&self, name: &str) -> Result<RepoEntry, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut entries = self.load()?;
        let removed = entries.remove(name).ok_or_else(|| LoomError::UnknownRepo {
            repository: name.to_owned(),
        })?;
        self.write(&entries)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(removed)
    }

    fn path(&self) -> PathBuf {
        self.store.root.join("repos.json")
    }

    /// Loads the durable catalog, or the defaults before first seed.
    /// The caller must hold the store lock.
    fn load(&self) -> Result<BTreeMap<String, RepoEntry>, LoomError> {
        let path = self.path();
        if !path.exists() {
            return Ok(self.defaults.as_ref().clone());
        }
        let bytes = read_bounded(&path, MAX_CATALOG_BYTES)?;
        let persisted: PersistedRepos =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" || persisted.repos.len() > MAX_REPOS {
            return Err(LoomError::CorruptState);
        }
        let mut entries = BTreeMap::new();
        for entry in persisted.repos {
            validate_entry(&entry).map_err(|_| LoomError::CorruptState)?;
            if entries.insert(entry.name.clone(), entry).is_some() {
                return Err(LoomError::CorruptState);
            }
        }
        Ok(entries)
    }

    fn write(&self, entries: &BTreeMap<String, RepoEntry>) -> Result<(), LoomError> {
        let persisted = PersistedRepos {
            schema_version: "v1".to_owned(),
            repos: entries.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        write_atomic(&self.store.root, &self.path(), &bytes, 0o600)
    }
}

/// Catalog defaults. Grogan platform siblings are not seeded; an empty
/// catalog is the standalone product. `config` is unused and kept so call
/// sites that pass Origin apply paths still compile during the disconnect.
#[must_use]
pub fn seed_entries(_config: &OriginConfig) -> Vec<RepoEntry> {
    Vec::new()
}

fn validate_entry(entry: &RepoEntry) -> Result<(), LoomError> {
    validate_repository(&entry.name)?;
    validate_repository_ref(&entry.protected_ref).map_err(|_| LoomError::InvalidRef {
        ref_name: entry.protected_ref.clone(),
    })?;
    if let Some(path) = &entry.checkout_path {
        validate_absolute_path(path)?;
    }
    match &entry.deploy_target {
        DeployTarget::None => {}
        DeployTarget::LocalApply { script } => validate_absolute_path(script)?,
        DeployTarget::SshApply { host, script } => {
            validate_absolute_path(script)?;
            if let Some(host) = host
                && !valid_host(host)
            {
                return Err(LoomError::InvalidRepository {
                    repository: entry.name.clone(),
                });
            }
        }
    }
    if entry.description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(LoomError::ResourceLimit);
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), LoomError> {
    if path.is_absolute()
        && !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
    {
        Ok(())
    } else {
        Err(LoomError::InvalidPath {
            path: path.display().to_string(),
        })
    }
}

fn valid_host(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':'))
}
