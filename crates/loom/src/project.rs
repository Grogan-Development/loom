//! First-class Loom projects: grouping for blast radius, secrets, and maintain.

use serde::{Deserialize, Serialize};

use crate::{LoomError, validate_repository};

/// Maintain policy stored on a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainPolicy {
    /// Cron expression in local time (five-field). Empty disables cron wake.
    #[serde(default)]
    pub cron: String,
    /// Pause the maintain queue for every repo in this project.
    #[serde(default)]
    pub paused: bool,
}

impl Default for MaintainPolicy {
    fn default() -> Self {
        Self {
            cron: "17 3 * * *".to_owned(),
            paused: false,
        }
    }
}

/// Project grouping `project/repo` catalog names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Project identifier (`billing`).
    pub name: String,
    /// Catalog repo names bound to this project.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Default runtime environment name.
    #[serde(default = "default_environment")]
    pub default_environment: String,
    /// Maintain policy for this project.
    #[serde(default)]
    pub maintain_policy: MaintainPolicy,
    /// Owner-facing description.
    #[serde(default)]
    pub description: String,
}

fn default_environment() -> String {
    "staging".to_owned()
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
    /// Default environment. Defaults to `staging`.
    #[serde(default)]
    pub default_environment: Option<String>,
    /// Maintain policy.
    #[serde(default)]
    pub maintain_policy: Option<MaintainPolicy>,
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
            default_environment: self
                .default_environment
                .filter(|value| !value.is_empty())
                .unwrap_or_else(default_environment),
            maintain_policy: self.maintain_policy.unwrap_or_default(),
            description: self.description.unwrap_or_default(),
        })
    }
}

/// Pause request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseRequest {
    /// Whether the maintain queue is paused.
    pub paused: bool,
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
