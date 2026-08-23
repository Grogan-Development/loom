//! JSON control plane for projects, apps, maintain jobs, and outbound webhooks.
//!
//! CAS, git, features, and tokens stay on their existing files. Surreal is an
//! optional later projection; this store is the source of truth for new objects
//! so unit tests never require Docker.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::app::AppRecord;
use crate::maintain::MaintainJob;
use crate::project::Project;
use crate::webhook::WebhookEndpoint;
use crate::{LoomError, PersistentLoomStore, read_bounded, write_atomic};

const MAX_CONTROL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PROJECTS: usize = 1024;
const MAX_APPS: usize = 4096;
const MAX_JOBS: usize = 10_000;
const MAX_HOOKS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedControl {
    schema_version: String,
    projects: Vec<Project>,
    apps: Vec<AppRecord>,
    maintain_jobs: Vec<MaintainJob>,
    webhooks: Vec<WebhookEndpoint>,
}

/// Durable JSON control plane rooted in `LOOM_ROOT`.
#[derive(Debug, Clone)]
pub struct ControlStore {
    store: PersistentLoomStore,
}

impl ControlStore {
    /// Opens the control plane beside an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Lists projects newest-name last (sorted).
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn list_projects(&self) -> Result<Vec<Project>, LoomError> {
        Ok(self.load()?.projects.into_values().collect())
    }

    /// Reads one project.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn get_project(&self, name: &str) -> Result<Option<Project>, LoomError> {
        Ok(self.load()?.projects.get(name).cloned())
    }

    /// Creates or replaces one project.
    ///
    /// # Errors
    ///
    /// Returns for bounds, lock, or I/O failure.
    pub fn upsert_project(&self, project: Project) -> Result<Project, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut state = self.load()?;
        state.projects.insert(project.name.clone(), project.clone());
        if state.projects.len() > MAX_PROJECTS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&state)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(project)
    }

    /// Deletes one project and its apps.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::UnknownProject`] when absent.
    pub fn delete_project(&self, name: &str) -> Result<Project, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut state = self.load()?;
        let removed = state
            .projects
            .remove(name)
            .ok_or_else(|| LoomError::UnknownProject {
                name: name.to_owned(),
            })?;
        state.apps.retain(|_, app| app.project != name);
        self.write(&state)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(removed)
    }

    /// Lists app records.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn list_apps(&self) -> Result<Vec<AppRecord>, LoomError> {
        Ok(self.load()?.apps.into_values().collect())
    }

    /// Reads one app by service id.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn get_app(&self, id: &str) -> Result<Option<AppRecord>, LoomError> {
        Ok(self.load()?.apps.get(id).cloned())
    }

    /// Creates or replaces one app record.
    ///
    /// # Errors
    ///
    /// Returns for bounds, lock, or I/O failure.
    pub fn upsert_app(&self, app: AppRecord) -> Result<AppRecord, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut state = self.load()?;
        state.apps.insert(app.id.clone(), app.clone());
        if state.apps.len() > MAX_APPS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&state)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(app)
    }

    /// Lists maintain jobs newest-id first.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn list_jobs(&self) -> Result<Vec<MaintainJob>, LoomError> {
        let mut jobs = self.load()?.maintain_jobs.into_values().collect::<Vec<_>>();
        jobs.sort_by(|left, right| right.id.cmp(&left.id));
        Ok(jobs)
    }

    /// Inserts a maintain job.
    ///
    /// # Errors
    ///
    /// Returns for bounds, lock, or I/O failure.
    pub fn upsert_job(&self, job: MaintainJob) -> Result<MaintainJob, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut state = self.load()?;
        state.maintain_jobs.insert(job.id.clone(), job.clone());
        if state.maintain_jobs.len() > MAX_JOBS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&state)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(job)
    }

    /// Lists outbound webhooks.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn list_webhooks(&self) -> Result<Vec<WebhookEndpoint>, LoomError> {
        Ok(self.load()?.webhooks.into_values().collect())
    }

    /// Creates or replaces one webhook.
    ///
    /// # Errors
    ///
    /// Returns for bounds, lock, or I/O failure.
    pub fn upsert_webhook(&self, hook: WebhookEndpoint) -> Result<WebhookEndpoint, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut state = self.load()?;
        state.webhooks.insert(hook.id.clone(), hook.clone());
        if state.webhooks.len() > MAX_HOOKS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&state)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(hook)
    }

    fn path(&self) -> PathBuf {
        self.store.root.join("control.json")
    }

    fn load(&self) -> Result<ControlState, LoomError> {
        let path = self.path();
        if !path.exists() {
            return Ok(ControlState::default());
        }
        let bytes = read_bounded(&path, MAX_CONTROL_BYTES)?;
        let persisted: PersistedControl =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(ControlState {
            projects: persisted
                .projects
                .into_iter()
                .map(|project| (project.name.clone(), project))
                .collect(),
            apps: persisted
                .apps
                .into_iter()
                .map(|app| (app.id.clone(), app))
                .collect(),
            maintain_jobs: persisted
                .maintain_jobs
                .into_iter()
                .map(|job| (job.id.clone(), job))
                .collect(),
            webhooks: persisted
                .webhooks
                .into_iter()
                .map(|hook| (hook.id.clone(), hook))
                .collect(),
        })
    }

    fn write(&self, state: &ControlState) -> Result<(), LoomError> {
        let persisted = PersistedControl {
            schema_version: "v1".to_owned(),
            projects: state.projects.values().cloned().collect(),
            apps: state.apps.values().cloned().collect(),
            maintain_jobs: state.maintain_jobs.values().cloned().collect(),
            webhooks: state.webhooks.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_CONTROL_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        write_atomic(&self.store.root, &self.path(), &bytes, 0o600)
    }
}

#[derive(Debug, Clone, Default)]
struct ControlState {
    projects: BTreeMap<String, Project>,
    apps: BTreeMap<String, AppRecord>,
    maintain_jobs: BTreeMap<String, MaintainJob>,
    webhooks: BTreeMap<String, WebhookEndpoint>,
}
