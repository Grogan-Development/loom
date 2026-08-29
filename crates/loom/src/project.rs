//! First-class Loom projects: plain grouping for `project/repo` catalog names.

use std::collections::BTreeMap;
use std::fs::File;

use serde::{Deserialize, Serialize};

use crate::{LoomError, PersistentLoomStore, read_bounded, validate_repository, write_atomic};

const MAX_PROJECT_BYTES: u64 = 1024 * 1024;
const MAX_PROJECTS: usize = 1024;

/// Project grouping `project/repo` catalog names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Project identifier (`billing`).
    pub name: String,
    /// Catalog repo names bound to this project.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Owner-facing description.
    #[serde(default)]
    pub description: String,
}

/// Owner request to create or replace a project.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUpsert {
    /// Project identifier.
    pub name: String,
    /// Bound catalog names.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Description.
    #[serde(default)]
    pub description: Option<String>,
}

impl ProjectUpsert {
    /// Validates and applies defaults.
    ///
    /// # Errors
    ///
    /// Returns for an invalid project or repo name.
    pub fn into_project(self) -> Result<Project, LoomError> {
        validate_project_name(&self.name)?;
        for repo in &self.repos {
            validate_repository(repo)?;
            let Some((project, _)) = repo.split_once('/') else {
                continue;
            };
            if project != self.name {
                return Err(LoomError::InvalidControl);
            }
        }
        Ok(Project {
            name: self.name,
            repos: self.repos,
            description: self.description.unwrap_or_default(),
        })
    }
}

/// Durable project catalog stored beside the Loom CAS.
#[derive(Debug, Clone)]
pub struct ProjectStore {
    store: PersistentLoomStore,
}

impl ProjectStore {
    /// Opens the project catalog inside an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Lists projects sorted by name.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn list(&self) -> Result<Vec<Project>, LoomError> {
        let lock = self.store.shared_lock()?;
        let projects = self.load()?.into_values().collect();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(projects)
    }

    /// Reads one project.
    ///
    /// # Errors
    ///
    /// Returns for lock, corruption, or I/O failure.
    pub fn get(&self, name: &str) -> Result<Option<Project>, LoomError> {
        let lock = self.store.shared_lock()?;
        let project = self.load()?.get(name).cloned();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(project)
    }

    /// Creates or replaces one project.
    ///
    /// # Errors
    ///
    /// Returns for bounds, lock, or I/O failure.
    pub fn upsert(&self, project: Project) -> Result<Project, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut projects = self.load()?;
        projects.insert(project.name.clone(), project.clone());
        if projects.len() > MAX_PROJECTS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&projects)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(project)
    }

    /// Deletes one project.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::UnknownProject`] when absent.
    pub fn delete(&self, name: &str) -> Result<Project, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut projects = self.load()?;
        let removed = projects
            .remove(name)
            .ok_or_else(|| LoomError::UnknownProject {
                name: name.to_owned(),
            })?;
        self.write(&projects)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(removed)
    }

    fn path(&self) -> std::path::PathBuf {
        self.store.root.join("projects.json")
    }

    fn load(&self) -> Result<BTreeMap<String, Project>, LoomError> {
        let path = self.path();
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = read_bounded(&path, MAX_PROJECT_BYTES)?;
        let persisted: PersistedProjects =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" || persisted.projects.len() > MAX_PROJECTS {
            return Err(LoomError::CorruptState);
        }
        let mut projects = BTreeMap::new();
        for project in persisted.projects {
            if projects.insert(project.name.clone(), project).is_some() {
                return Err(LoomError::CorruptState);
            }
        }
        Ok(projects)
    }

    fn write(&self, projects: &BTreeMap<String, Project>) -> Result<(), LoomError> {
        let persisted = PersistedProjects {
            schema_version: "v1".to_owned(),
            projects: projects.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_PROJECT_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        write_atomic(&self.store.root, &self.path(), &bytes, 0o600)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedProjects {
    schema_version: String,
    projects: Vec<Project>,
}

/// Validates a project identifier (one lowercase segment).
///
/// # Errors
///
/// Returns [`LoomError::InvalidControl`] when the name is not a project segment.
pub fn validate_project_name(name: &str) -> Result<(), LoomError> {
    if (1..=63).contains(&name.len())
        && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.contains('/')
    {
        Ok(())
    } else {
        Err(LoomError::InvalidControl)
    }
}
