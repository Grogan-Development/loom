//! Blocking HTTP client for Grid's internal system-runner API.

use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Configured Grid runner backend.
#[derive(Clone, PartialEq, Eq)]
pub struct GridRunner {
    base_url: String,
    token: String,
}

impl std::fmt::Debug for GridRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GridRunner")
            .field("base_url", &self.base_url)
            .field("token", &"[redacted]")
            .finish()
    }
}

/// One repository revision to materialize inside the runner VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridRepo {
    /// Loom repository namespace.
    pub repo: String,
    /// Immutable revision digest.
    pub revision: String,
}

/// `POST /internal/runners` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRunnerRequest {
    /// Caller job id; Grid stores this as the primary key.
    pub job_id: String,
    /// `ci`, `insights`, or `review`.
    pub kind: String,
    /// Source bindings.
    pub repos: Vec<GridRepo>,
    /// Wall-clock budget in seconds.
    pub timeout_secs: u64,
    /// Optional environment injected into command exec.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional argv list; Grid detects `loom-ci.toml` when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<Vec<String>>,
}

/// `201` create acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRunnerResponse {
    /// Job id.
    pub id: String,
    /// `queued` or `running`.
    pub status: String,
    /// System workspace id when allocated.
    #[serde(default)]
    pub workspace_id: String,
}

/// Job record returned by `GET /internal/runners/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridRunnerJob {
    /// Job id.
    pub id: String,
    /// Current status.
    pub status: String,
    /// Combined command log.
    #[serde(default)]
    pub log: String,
    /// Failure detail.
    #[serde(default)]
    pub error: Option<String>,
}

/// Client failures talking to Grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GridRunnerError {
    /// `LOOM_GRID_URL` / `LOOM_GRID_INTERNAL_TOKEN` missing or invalid.
    NotConfigured,
    /// HTTP transport failed.
    Transport,
    /// Grid rejected the request.
    Status(u16),
    /// Response JSON did not match the contract.
    InvalidResponse,
}

impl std::error::Error for GridRunnerError {}

impl std::fmt::Display for GridRunnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => {
                write!(
                    formatter,
                    "grid runner is not configured (LOOM_GRID_URL / LOOM_GRID_INTERNAL_TOKEN)"
                )
            }
            Self::Transport => write!(formatter, "grid runner transport failed"),
            Self::Status(code) => write!(formatter, "grid runner returned HTTP {code}"),
            Self::InvalidResponse => write!(formatter, "grid runner response is invalid"),
        }
    }
}

impl GridRunner {
    /// Creates a Grid runner client from an explicit service URL and internal token.
    ///
    /// # Errors
    ///
    /// Returns when either value is empty.
    pub fn new(
        base_url: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, GridRunnerError> {
        let base_url = base_url.into();
        let token = token.into();
        if base_url.trim().is_empty() || token.is_empty() {
            return Err(GridRunnerError::NotConfigured);
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
        })
    }

    /// Reads `LOOM_GRID_URL` and `LOOM_GRID_INTERNAL_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns when either variable is missing or empty.
    pub fn from_env() -> Result<Self, GridRunnerError> {
        let base_url =
            std::env::var("LOOM_GRID_URL").map_err(|_| GridRunnerError::NotConfigured)?;
        let token = std::env::var("LOOM_GRID_INTERNAL_TOKEN")
            .map_err(|_| GridRunnerError::NotConfigured)?;
        Self::new(base_url, token)
    }

    /// Submits a runner job.
    ///
    /// # Errors
    ///
    /// Returns for transport, HTTP, or response-contract failures.
    pub fn create(
        &self,
        request: &CreateRunnerRequest,
    ) -> Result<CreateRunnerResponse, GridRunnerError> {
        let body = serde_json::to_vec(request).map_err(|_| GridRunnerError::InvalidResponse)?;
        let (status, bytes) = self.request("POST", "/internal/runners", Some(&body))?;
        if status != 201 {
            return Err(GridRunnerError::Status(status));
        }
        serde_json::from_slice(&bytes).map_err(|_| GridRunnerError::InvalidResponse)
    }

    /// Loads one job including its log.
    ///
    /// # Errors
    ///
    /// Returns for transport, HTTP, or response-contract failures.
    pub fn get(&self, id: &str) -> Result<GridRunnerJob, GridRunnerError> {
        let path = format!("/internal/runners/{id}");
        let (status, bytes) = self.request("GET", &path, None)?;
        if status != 200 {
            return Err(GridRunnerError::Status(status));
        }
        serde_json::from_slice(&bytes).map_err(|_| GridRunnerError::InvalidResponse)
    }

    /// Cancels a queued or running Grid job.
    ///
    /// # Errors
    ///
    /// Returns when Grid cannot durably record cancellation.
    pub fn cancel(&self, id: &str) -> Result<(), GridRunnerError> {
        let path = format!("/internal/runners/{id}/cancel");
        let (status, _) = self.request("POST", &path, None)?;
        if status != 200 {
            return Err(GridRunnerError::Status(status));
        }
        Ok(())
    }

    /// Polls until the job is terminal or `timeout` elapses.
    ///
    /// # Errors
    ///
    /// Returns when Grid is unreachable, the job never finishes, or the body is invalid.
    pub fn wait(&self, id: &str, timeout: Duration) -> Result<GridRunnerJob, GridRunnerError> {
        let deadline = Instant::now() + timeout;
        loop {
            let job = self.get(id)?;
            if matches!(job.status.as_str(), "passed" | "failed" | "cancelled") {
                return Ok(job);
            }
            if Instant::now() >= deadline {
                return Err(GridRunnerError::Status(504));
            }
            thread::sleep(Duration::from_millis(750));
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), GridRunnerError> {
        let url = format!("{}{path}", self.base_url);
        let token = self.token.clone();
        let method = method.to_owned();
        let body = body.map(<[u8]>::to_vec);
        thread::Builder::new()
            .name("loom-grid-runner".to_owned())
            .spawn(move || request_on_thread(&method, &url, &token, body.as_deref()))
            .map_err(|_| GridRunnerError::Transport)?
            .join()
            .map_err(|_| GridRunnerError::Transport)?
    }
}

fn request_on_thread(
    method: &str,
    url: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), GridRunnerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|_| GridRunnerError::Transport)?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|_| GridRunnerError::Transport)?;
        let mut request = client
            .request(
                method
                    .parse()
                    .map_err(|_| GridRunnerError::InvalidResponse)?,
                url,
            )
            .header("X-Grid-Internal", token);
        if let Some(bytes) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(bytes.to_vec());
        }
        let response = request
            .send()
            .await
            .map_err(|_| GridRunnerError::Transport)?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| GridRunnerError::Transport)?;
        Ok((status, bytes.to_vec()))
    })
}

/// True when `LOOM_CI_BACKEND=grid`. Missing URL/token still selects Grid (fail closed).
#[must_use]
pub fn grid_backend_requested() -> bool {
    std::env::var("LOOM_CI_BACKEND").is_ok_and(|value| value.eq_ignore_ascii_case("grid"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CreateRunnerRequest, GridRepo};

    #[test]
    fn create_request_json_shape() {
        let request = CreateRunnerRequest {
            job_id: "run-ab12cd34".to_owned(),
            kind: "ci".to_owned(),
            repos: vec![GridRepo {
                repo: "loom".to_owned(),
                revision: "a".repeat(64),
            }],
            timeout_secs: 120,
            env: std::collections::BTreeMap::new(),
            commands: vec![vec!["true".to_owned()]],
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["job_id"], "run-ab12cd34");
        assert_eq!(value["kind"], "ci");
        assert_eq!(value["timeout_secs"], 120);
        assert_eq!(value["repos"][0]["repo"], "loom");
        assert_eq!(value["repos"][0]["revision"], "a".repeat(64));
        assert_eq!(value["commands"][0][0], "true");
        assert!(value.get("env").is_none());
    }
}
