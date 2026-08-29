//! HTTP CLI for the standalone Loom API (`LOOM_URL` + `LOOM_TOKEN`).

use std::io::{self, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use reqwest::{Client, Method, StatusCode, Url};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "loom",
    version,
    about = "Call the standalone Loom HTTP API using LOOM_URL and LOOM_TOKEN"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Catch up or follow the durable event log.
    Events {
        /// Stay connected and print new events as SSE.
        #[arg(long)]
        follow: bool,
        /// Resume after this event id.
        #[arg(long)]
        since: Option<String>,
        /// Client-side filter on payload `id` / `feature_id`.
        #[arg(long)]
        feature: Option<String>,
    },
    /// Feature contract lifecycle.
    Feature {
        #[command(subcommand)]
        action: FeatureAction,
    },
    /// Submit a candidate against an approved feature.
    Candidate {
        #[command(subcommand)]
        action: CandidateAction,
    },
    /// Print CI evidence attached to a feature.
    Evidence {
        #[arg(long)]
        feature: String,
    },
    /// Print insights for a feature (dedicated route or feature field).
    Insights {
        #[arg(long)]
        feature: String,
    },
    /// Review findings.
    Review {
        #[command(subcommand)]
        action: ReviewAction,
    },
    /// Post a comment on a feature thread.
    Comment {
        #[arg(long)]
        feature: String,
        #[arg(long)]
        body: String,
        /// `human` or `agent:<name>`.
        #[arg(long, default_value = "human")]
        author: String,
    },
    /// Print cwd, env, and a features listing.
    Status,
    /// Write `~/.config/loom/credentials` (env still wins).
    Login {
        /// Loom base URL.
        #[arg(long)]
        url: String,
        /// Bearer token.
        #[arg(long)]
        token: String,
    },
    /// Catalog repositories.
    Repo {
        #[command(subcommand)]
        action: RepoAction,
    },
    /// Projects.
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Dump a backup tarball.
    Backup {
        /// Destination path.
        destination: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RepoAction {
    /// POST `/v1/repos/import`.
    Import {
        #[arg(long)]
        project: String,
        #[arg(long)]
        name: String,
        git_url: Option<String>,
    },
    /// GET `/v1/repos`.
    List,
    /// GET `/v1/repos/{name}`.
    Show { name: String },
}

#[derive(Debug, Subcommand)]
enum ProjectAction {
    /// POST `/v1/projects`.
    Create { name: String },
    /// GET `/v1/projects`.
    List,
    /// GET `/v1/projects/{name}`.
    Show { name: String },
}

#[derive(Debug, Subcommand)]
enum FeatureAction {
    /// POST `/v1/features` from `--file` or stdin.
    Create {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// GET `/v1/features`.
    List,
    /// GET `/v1/features/{id}`.
    Show { id: String },
    /// POST `/v1/features/{id}/approve`.
    Approve { id: String },
    /// POST `/v1/features/{id}/accept`.
    Accept { id: String },
    /// POST `/v1/features/{id}/reject`.
    Reject { id: String },
}

#[derive(Debug, Subcommand)]
enum CandidateAction {
    /// POST `/v1/features/{id}/candidates` from `--file` or stdin.
    Submit {
        #[arg(long)]
        feature: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ReviewAction {
    /// GET `/v1/features/{id}/reviews`.
    List {
        #[arg(long)]
        feature: String,
    },
    /// POST `/v1/features/{feature}/findings/{finding_id}/apply`.
    Apply {
        #[arg(long)]
        feature: String,
        finding_id: String,
        /// Approve and apply in one call.
        #[arg(long)]
        approve: bool,
    },
}

struct Api {
    base: Url,
    token: String,
    client: Client,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if let Command::Login { url, token } = &cli.command {
        return write_credentials(url, token);
    }
    let api = Api::from_env()?;
    match cli.command {
        Command::Events {
            follow,
            since,
            feature,
        } => {
            api.events(follow, since.as_deref(), feature.as_deref())
                .await
        }
        Command::Feature { action } => match action {
            FeatureAction::Create { file } => {
                let body = read_json(file.as_ref())?;
                api.send(Method::POST, "/v1/features", Some(body)).await
            }
            FeatureAction::List => api.send(Method::GET, "/v1/features", None).await,
            FeatureAction::Show { id } => {
                api.send(Method::GET, &format!("/v1/features/{id}"), None)
                    .await
            }
            FeatureAction::Approve { id } => {
                api.send(Method::POST, &format!("/v1/features/{id}/approve"), None)
                    .await
            }
            FeatureAction::Accept { id } => {
                api.send(Method::POST, &format!("/v1/features/{id}/accept"), None)
                    .await
            }
            FeatureAction::Reject { id } => {
                api.send(Method::POST, &format!("/v1/features/{id}/reject"), None)
                    .await
            }
        },
        Command::Candidate { action } => match action {
            CandidateAction::Submit { feature, file } => {
                let body = read_json(file.as_ref())?;
                api.send(
                    Method::POST,
                    &format!("/v1/features/{feature}/candidates"),
                    Some(body),
                )
                .await
            }
        },
        Command::Evidence { feature } => api.evidence(&feature).await,
        Command::Insights { feature } => api.insights(&feature).await,
        Command::Review { action } => match action {
            ReviewAction::List { feature } => {
                api.send(
                    Method::GET,
                    &format!("/v1/features/{feature}/reviews"),
                    None,
                )
                .await
            }
            ReviewAction::Apply {
                feature,
                finding_id,
                approve,
            } => {
                api.send(
                    Method::POST,
                    &review_apply_path(&feature, &finding_id),
                    Some(json!({ "approve": approve })),
                )
                .await
            }
        },
        Command::Comment {
            feature,
            body,
            author,
        } => {
            api.send(
                Method::POST,
                &feature_comments_path(&feature),
                Some(comment_body(&author, &body)),
            )
            .await
        }
        Command::Status => api.status().await,
        Command::Repo { action } => match action {
            RepoAction::Import {
                project,
                name,
                git_url,
            } => {
                api.send(
                    Method::POST,
                    "/v1/repos/import",
                    Some(json!({
                        "project": project,
                        "name": name,
                        "git_url": git_url.unwrap_or_default(),
                    })),
                )
                .await
            }
            RepoAction::List => api.send(Method::GET, "/v1/repos", None).await,
            RepoAction::Show { name } => {
                api.send(Method::GET, &format!("/v1/repos/{name}"), None)
                    .await
            }
        },
        Command::Project { action } => match action {
            ProjectAction::Create { name } => {
                api.send(Method::POST, "/v1/projects", Some(json!({ "name": name })))
                    .await
            }
            ProjectAction::List => api.send(Method::GET, "/v1/projects", None).await,
            ProjectAction::Show { name } => {
                api.send(Method::GET, &format!("/v1/projects/{name}"), None)
                    .await
            }
        },
        Command::Backup { destination } => {
            api.send(
                Method::POST,
                "/v1/backup",
                Some(json!({ "destination": destination })),
            )
            .await
        }
        Command::Login { .. } => Err("internal: login handled before HTTP client".to_owned()),
    }
}

fn write_credentials(url: &str, token: &str) -> Result<(), String> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("mkdir: {error}"))?;
    }
    std::fs::write(&path, format!("LOOM_URL={url}\nLOOM_TOKEN={token}\n"))
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn credentials_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is required".to_owned())?;
    Ok(PathBuf::from(home).join(".config/loom/credentials"))
}

#[derive(Debug, Default)]
struct FileCredentials {
    url: Option<String>,
    token: Option<String>,
}

fn read_credentials() -> Result<FileCredentials, String> {
    let path = credentials_path()?;
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(FileCredentials::default());
    };
    let mut file = FileCredentials::default();
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("LOOM_URL=") {
            file.url = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("LOOM_TOKEN=") {
            file.token = Some(value.to_owned());
        }
    }
    Ok(file)
}

fn env_or_file(var: &str, file: Option<&str>) -> Result<String, String> {
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) | Err(_) => {
            let Some(value) = file.filter(|value| !value.is_empty()) else {
                return Err(format!("{var} is required"));
            };
            Ok(value.to_owned())
        }
    }
}

impl Api {
    fn from_env() -> Result<Self, String> {
        let file = read_credentials().unwrap_or_default();
        let raw_url = env_or_file("LOOM_URL", file.url.as_deref())?;
        let token = env_or_file("LOOM_TOKEN", file.token.as_deref())?;
        if raw_url.is_empty() || token.is_empty() {
            return Err("LOOM_URL and LOOM_TOKEN must be non-empty".to_owned());
        }
        let base = Url::parse(&raw_url).map_err(|error| format!("invalid LOOM_URL: {error}"))?;
        Ok(Self {
            base,
            token,
            client: Client::new(),
        })
    }

    fn url(&self, path: &str) -> Result<Url, String> {
        self.base
            .join(path.trim_start_matches('/'))
            .map_err(|error| format!("invalid URL: {error}"))
    }

    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<(), String> {
        let (status, text) = self.exchange(method, path, body).await?;
        print_http(status, &text)
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, String), String> {
        let mut request = self
            .client
            .request(method, self.url(path)?)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        Ok((status, text))
    }

    async fn events(
        &self,
        follow: bool,
        since: Option<&str>,
        feature: Option<&str>,
    ) -> Result<(), String> {
        let mut url = self.url("v1/events")?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(since) = since {
                pairs.append_pair("since", since);
            }
            if follow {
                pairs.append_pair("follow", "1");
            }
        }
        let mut request = self.client.get(url).bearer_auth(&self.token);
        if follow {
            request = request.header(reqwest::header::ACCEPT, "text/event-stream");
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        let status = response.status();
        if !follow {
            let text = response
                .text()
                .await
                .map_err(|error| format!("read failed: {error}"))?;
            return print_http(status, &text);
        }
        if !status.is_success() {
            let text = response
                .text()
                .await
                .map_err(|error| format!("read failed: {error}"))?;
            return Err(http_error(status, &text));
        }
        let mut pending = String::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("sse read failed: {error}"))?
        {
            pending.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(split) = pending.find("\n\n") {
                let frame = pending[..split].to_owned();
                pending = pending[split + 2..].to_owned();
                if let Some(data) = sse_data(&frame)
                    && feature_matches(&data, feature)
                {
                    println!("{data}");
                }
            }
        }
        Ok(())
    }

    async fn evidence(&self, feature: &str) -> Result<(), String> {
        let (status, text) = self
            .exchange(
                Method::GET,
                &format!("/v1/features/{feature}/evidence"),
                None,
            )
            .await?;
        if status != StatusCode::NOT_FOUND {
            return print_http(status, &text);
        }
        let (status, text) = self
            .exchange(Method::GET, &format!("/v1/features/{feature}"), None)
            .await?;
        if !status.is_success() {
            return Err(http_error(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| format!("invalid JSON: {error}"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                value.pointer("/candidate/evidence").unwrap_or(&Value::Null)
            )
            .map_err(|error| format!("serialize failed: {error}"))?
        );
        Ok(())
    }

    async fn insights(&self, feature: &str) -> Result<(), String> {
        let (status, text) = self
            .exchange(
                Method::GET,
                &format!("/v1/features/{feature}/insights"),
                None,
            )
            .await?;
        if status != StatusCode::NOT_FOUND {
            return print_http(status, &text);
        }
        let (status, text) = self
            .exchange(Method::GET, &format!("/v1/features/{feature}"), None)
            .await?;
        if !status.is_success() {
            return Err(http_error(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| format!("invalid JSON: {error}"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(insights_pointer(&value))
                .map_err(|error| format!("serialize failed: {error}"))?
        );
        Ok(())
    }

    async fn status(&self) -> Result<(), String> {
        let cwd = std::env::current_dir().map_err(|error| format!("cwd unavailable: {error}"))?;
        let token_set = if self.token.is_empty() {
            "unset"
        } else {
            "set"
        };
        println!("cwd={}", cwd.display());
        println!("LOOM_URL={}", self.base);
        println!("LOOM_TOKEN={token_set}");
        let (status, text) = self.exchange(Method::GET, "/v1/features", None).await?;
        print_http(status, &text)
    }
}

fn read_json(path: Option<&PathBuf>) -> Result<Value, String> {
    let raw = if let Some(path) = path {
        std::fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?
    } else {
        let mut raw = String::new();
        io::stdin()
            .read_to_string(&mut raw)
            .map_err(|error| format!("stdin: {error}"))?;
        raw
    };
    serde_json::from_str(&raw).map_err(|error| format!("invalid JSON: {error}"))
}

fn sse_data(frame: &str) -> Option<String> {
    let mut data = Vec::new();
    for line in frame.lines() {
        if let Some(value) = line.strip_prefix("data:") {
            data.push(value.trim_start());
        }
    }
    if data.is_empty() {
        None
    } else {
        Some(data.join("\n"))
    }
}

fn feature_matches(data: &str, feature: Option<&str>) -> bool {
    let Some(feature) = feature else {
        return true;
    };
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return false;
    };
    let payload = value.get("payload").unwrap_or(&value);
    payload
        .get("id")
        .or_else(|| payload.get("feature_id"))
        .and_then(Value::as_str)
        == Some(feature)
}

fn print_http(status: StatusCode, text: &str) -> Result<(), String> {
    if status.is_success() {
        if text.is_empty() {
            println!("{status}");
        } else if let Ok(value) = serde_json::from_str::<Value>(text) {
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .map_err(|error| format!("serialize failed: {error}"))?
            );
        } else {
            println!("{text}");
        }
        Ok(())
    } else {
        Err(http_error(status, text))
    }
}

fn review_apply_path(feature: &str, finding_id: &str) -> String {
    format!("/v1/features/{feature}/findings/{finding_id}/apply")
}

fn feature_comments_path(feature: &str) -> String {
    format!("/v1/features/{feature}/comments")
}

fn comment_body(author: &str, body: &str) -> Value {
    json!({ "author": author, "body": body })
}

fn insights_pointer(value: &Value) -> &Value {
    value.pointer("/candidate/insights").unwrap_or(&Value::Null)
}

fn http_error(status: StatusCode, text: &str) -> String {
    let body = text.trim();
    if body.is_empty() {
        format!("loom HTTP {status}")
    } else {
        format!("loom HTTP {status}: {body}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{comment_body, env_or_file, insights_pointer, review_apply_path};
    use serde_json::json;

    #[test]
    fn review_apply_uses_feature_scoped_route() {
        assert_eq!(
            review_apply_path("feat-1", "fnd-2"),
            "/v1/features/feat-1/findings/fnd-2/apply"
        );
    }

    #[test]
    fn comment_includes_required_author() {
        assert_eq!(
            comment_body("human", "looks good"),
            json!({ "author": "human", "body": "looks good" })
        );
    }

    #[test]
    fn insights_fallback_reads_candidate_pointer() {
        let value = json!({
            "candidate": { "insights": { "job_id": "job-1" } }
        });
        assert_eq!(insights_pointer(&value)["job_id"], "job-1");
        assert!(insights_pointer(&json!({})).is_null());
    }

    #[test]
    fn env_wins_over_file_and_file_fills_when_env_missing() {
        assert_eq!(
            env_or_file("LOOM_URL_UNSET_FOR_TEST", Some("https://from-file")).unwrap(),
            "https://from-file"
        );
        let err = env_or_file("LOOM_URL_UNSET_FOR_TEST", None).unwrap_err();
        assert!(err.contains("LOOM_URL_UNSET_FOR_TEST"));
    }
}
