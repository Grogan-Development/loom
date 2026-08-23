//! Read-only HTML dashboard served from loomd.

use std::fmt::Write as _;

use crate::LoomError;
use crate::app::AppRecord;
use crate::control::ControlStore;
use crate::events::EventLog;
use crate::maintain::MaintainJob;
use crate::project::Project;

/// Dashboard snapshot.
#[derive(Debug, Clone)]
pub struct StatusPage {
    /// Projects.
    pub projects: Vec<Project>,
    /// Apps.
    pub apps: Vec<AppRecord>,
    /// Recent events (kinds only).
    pub events: Vec<String>,
    /// Maintain jobs.
    pub jobs: Vec<MaintainJob>,
    /// Agent configured.
    pub agent_configured: bool,
}

impl StatusPage {
    /// Loads a snapshot.
    ///
    /// # Errors
    ///
    /// Returns for control or event I/O failure.
    pub fn load(
        control: &ControlStore,
        events: &EventLog,
        agent_configured: bool,
    ) -> Result<Self, LoomError> {
        let event_kinds = events
            .since(None, 20)?
            .into_iter()
            .map(|event| format!("{} {}", event.kind, event.id))
            .collect();
        Ok(Self {
            projects: control.list_projects()?,
            apps: control.list_apps()?,
            events: event_kinds,
            jobs: control.list_jobs()?,
            agent_configured,
        })
    }

    /// Renders HTML. Writes are 405 elsewhere; this page is read-only.
    #[must_use]
    pub fn render(&self) -> String {
        let mut html =
            String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Loom</title>");
        html.push_str(
            "<style>body{font-family:ui-sans-serif,system-ui;margin:2rem;max-width:72rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.4rem;text-align:left}code{font-size:.9em}</style></head><body>",
        );
        html.push_str("<h1>Loom</h1><p>Read-only status. Writes: <code>loom</code> CLI / MCP.</p>");
        if !self.agent_configured {
            html.push_str(
                "<p><strong>maintain blocked:</strong> <code>agent_unconfigured</code></p>",
            );
        }
        html.push_str(
            "<h2>Projects</h2><table><tr><th>name</th><th>repos</th><th>paused</th></tr>",
        );
        for project in &self.projects {
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&project.name),
                escape(&project.repos.join(", ")),
                project.maintain_policy.paused
            );
        }
        html.push_str("</table><h2>Apps</h2><table><tr><th>id</th><th>kind</th><th>envs</th></tr>");
        for app in &self.apps {
            let envs = app
                .environments
                .values()
                .map(|env| format!("{}@{}", env.name, truncate(&env.image_digest)))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{:?}</td><td>{}</td></tr>",
                escape(&app.id),
                app.kind,
                escape(&envs)
            );
        }
        html.push_str(
            "</table><h2>Maintain</h2><table><tr><th>id</th><th>repo</th><th>status</th></tr>",
        );
        for job in &self.jobs {
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&job.id),
                escape(&job.repo),
                escape(job.blocked.as_deref().unwrap_or(&job.status))
            );
        }
        html.push_str("</table><h2>Events</h2><ul>");
        for event in &self.events {
            let _ = write!(html, "<li><code>{}</code></li>", escape(event));
        }
        html.push_str("</ul></body></html>");
        html
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn truncate(value: &str) -> &str {
    if value.len() > 12 {
        &value[..12]
    } else {
        value
    }
}
