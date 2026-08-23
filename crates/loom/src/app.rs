//! App records: services, environments, rollback, promote.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::pack::{PackKind, looks_like_app, plan};
use crate::{LoomError, validate_repository};

/// Kind of running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// HTTP service.
    Web,
    /// Long-running worker.
    Worker,
    /// Scheduled one-shot.
    Clock,
    /// Managed Postgres.
    Postgres,
    /// Managed Redis.
    Redis,
}

/// One environment pinning an image digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// `staging`, `production`, `legacy`, or `preview:{feature}`.
    pub name: String,
    /// Image digest currently serving (or empty if never deployed).
    #[serde(default)]
    pub image_digest: String,
    /// Last healthy digest for rollback.
    #[serde(default)]
    pub last_healthy_digest: String,
    /// Replica count.
    #[serde(default = "one")]
    pub replicas: u32,
    /// Generated hostname.
    #[serde(default)]
    pub hostname: String,
    /// True when this env is scale-to-zero.
    #[serde(default)]
    pub scale_to_zero: bool,
}

const fn one() -> u32 {
    1
}

/// Durable app/service record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRecord {
    /// `{project}/{service}`.
    pub id: String,
    /// Project name.
    pub project: String,
    /// Service name.
    pub name: String,
    /// Source catalog repo, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Process kind.
    pub kind: ServiceKind,
    /// Start argv.
    #[serde(default)]
    pub start: Vec<String>,
    /// Health path for web.
    #[serde(default)]
    pub health_path: String,
    /// Optional worker health command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_command: Option<Vec<String>>,
    /// Clock cron.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    /// Detected pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<PackKind>,
    /// Environments.
    #[serde(default)]
    pub environments: BTreeMap<String, Environment>,
}

/// Create-app request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppCreate {
    /// Project.
    pub project: String,
    /// Service name.
    pub name: String,
    /// Optional source repo.
    #[serde(default)]
    pub repo: Option<String>,
    /// Kind. Defaults to web.
    #[serde(default)]
    pub kind: Option<ServiceKind>,
    /// Start argv.
    #[serde(default)]
    pub start: Vec<String>,
}

impl AppCreate {
    /// Validates and fills defaults.
    ///
    /// # Errors
    ///
    /// Returns for invalid names.
    pub fn into_record(self, files: &BTreeMap<String, Vec<u8>>) -> Result<AppRecord, LoomError> {
        crate::project::validate_project_name(&self.project)?;
        crate::project::validate_project_name(&self.name)?;
        if let Some(repo) = &self.repo {
            validate_repository(repo)?;
        }
        let detected = plan(files);
        let kind = self.kind.unwrap_or(ServiceKind::Web);
        let start = if self.start.is_empty() {
            detected.start_command.clone()
        } else {
            self.start
        };
        let id = format!("{}/{}", self.project, self.name);
        let mut environments = BTreeMap::new();
        environments.insert(
            "staging".to_owned(),
            Environment {
                name: "staging".to_owned(),
                image_digest: String::new(),
                last_healthy_digest: String::new(),
                replicas: 1,
                hostname: hostname(&id, "staging"),
                scale_to_zero: false,
            },
        );
        environments.insert(
            "production".to_owned(),
            Environment {
                name: "production".to_owned(),
                image_digest: String::new(),
                last_healthy_digest: String::new(),
                replicas: 1,
                hostname: hostname(&id, "production"),
                scale_to_zero: false,
            },
        );
        if detected.needs_legacy {
            environments.insert(
                "legacy".to_owned(),
                Environment {
                    name: "legacy".to_owned(),
                    image_digest: String::new(),
                    last_healthy_digest: String::new(),
                    replicas: 1,
                    hostname: hostname(&id, "legacy"),
                    scale_to_zero: true,
                },
            );
        }
        Ok(AppRecord {
            id,
            project: self.project,
            name: self.name,
            repo: self.repo,
            kind,
            start,
            health_path: detected.health_path,
            health_command: None,
            cron: None,
            pack: Some(detected.kind),
            environments,
        })
    }
}

/// Promote / rollback body. `id` is `project/service` because catch-all
/// path params cannot sit in the middle of a route.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvAction {
    /// App id (`project/service`).
    pub id: String,
    /// Environment name.
    pub environment: String,
}

/// Pins an image onto an environment and records last-healthy.
pub fn pin_environment(app: &mut AppRecord, environment: &str, digest: &str, healthy: bool) {
    let hostname = hostname(&app.id, environment);
    let env = app
        .environments
        .entry(environment.to_owned())
        .or_insert_with(|| Environment {
            name: environment.to_owned(),
            image_digest: String::new(),
            last_healthy_digest: String::new(),
            replicas: 1,
            hostname,
            scale_to_zero: environment == "legacy" || environment.starts_with("preview:"),
        });
    if healthy && !env.image_digest.is_empty() && env.image_digest != digest {
        env.last_healthy_digest.clone_from(&env.image_digest);
    }
    digest.clone_into(&mut env.image_digest);
    if healthy && env.last_healthy_digest.is_empty() {
        digest.clone_into(&mut env.last_healthy_digest);
    }
}

/// Rolls an environment back to last healthy digest.
///
/// # Errors
///
/// Returns [`LoomError::ImageMissing`] when no healthy digest exists.
pub fn rollback_environment(app: &mut AppRecord, environment: &str) -> Result<String, LoomError> {
    let env = app
        .environments
        .get_mut(environment)
        .ok_or(LoomError::InvalidControl)?;
    if env.last_healthy_digest.is_empty() {
        return Err(LoomError::ImageMissing);
    }
    env.image_digest.clone_from(&env.last_healthy_digest);
    Ok(env.image_digest.clone())
}

/// Generated hostname for a service environment.
#[must_use]
pub fn hostname(id: &str, environment: &str) -> String {
    let slug = id.replace('/', "-");
    format!("{slug}-{environment}.apps.grogan.dev")
}

/// Preview hostname.
#[must_use]
pub fn preview_hostname(feature: &str, id: &str) -> String {
    let slug = id.replace('/', "-");
    format!("{feature}--{slug}.apps.grogan.dev")
}

/// True if import should create an app by default.
#[must_use]
pub fn should_create_app(files: &BTreeMap<String, Vec<u8>>) -> bool {
    looks_like_app(files)
}
