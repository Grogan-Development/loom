//! Claude Messages planner. Tools are Loom HTTP only.

use serde::{Deserialize, Serialize};

use crate::LoomError;

/// Planner configuration from the host environment.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// API key. Empty means unconfigured.
    pub api_key: String,
    /// Model id (`LOOM_AGENT_MODEL`).
    pub model: String,
}

impl AgentConfig {
    /// Reads `LOOM_AGENT_API_KEY` and `LOOM_AGENT_MODEL`.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("LOOM_AGENT_API_KEY").unwrap_or_default(),
            model: std::env::var("LOOM_AGENT_MODEL")
                .unwrap_or_else(|_| "claude-opus-4-6".to_owned()),
        }
    }

    /// True when a key is present.
    #[must_use]
    pub fn configured(&self) -> bool {
        !self.api_key.is_empty()
    }
}

/// Tool names the planner may call. Never `SurrealQL`, never a host shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTool {
    /// Native source commit.
    SourceCommit,
    /// Submit a candidate.
    CandidateSubmit,
    /// Comment on a feature.
    Comment,
    /// Read evidence.
    Evidence,
    /// Read blast-radius / graphs.
    GraphRead,
}

/// Allowed tool list.
#[must_use]
pub fn tool_allowlist() -> &'static [AgentTool] {
    &[
        AgentTool::SourceCommit,
        AgentTool::CandidateSubmit,
        AgentTool::Comment,
        AgentTool::Evidence,
        AgentTool::GraphRead,
    ]
}

/// Fail-closed when the planner is missing.
///
/// # Errors
///
/// Returns [`LoomError::AgentUnconfigured`].
pub fn require_configured(config: &AgentConfig) -> Result<(), LoomError> {
    if config.configured() {
        Ok(())
    } else {
        Err(LoomError::AgentUnconfigured)
    }
}
