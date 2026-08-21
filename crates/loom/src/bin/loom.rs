//! Standalone Loom server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use loom::auth::AccessToken;
use loom::origin::OriginConfig;
use loom::review_runner::ReviewRunnerConfig;
use loom::server::{LoomApp, ServerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "loom",
    version,
    about = "Standalone Loom smart repository",
    long_about = "Owner token (LOOM_TOKEN) authorizes /v1/releases/*/ci, GET evidence, features, CAS RPC, and Git.\n\
Deploy token (LOOM_DEPLOY_TOKEN) authorizes only POST /v1/releases/{repo}/{oid}/deploy.\n\
Origin webhooks are authenticated by Origin App signatures, not bearer tokens."
)]
struct Cli {
    /// Listen address. Docker images default to `0.0.0.0:8080`.
    #[arg(long, env = "LOOM_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// Absolute private dataset root.
    #[arg(long, env = "LOOM_ROOT")]
    root: PathBuf,
    /// Owner bearer token (`Authorization: Bearer`). CI start and evidence GET.
    #[arg(long, env = "LOOM_TOKEN")]
    token: String,
    /// Deploy-only bearer token. Required for POST /v1/releases/{repo}/{oid}/deploy.
    #[arg(long, env = "LOOM_DEPLOY_TOKEN")]
    deploy_token: Option<String>,
    /// Absolute Git executable.
    #[arg(long, env = "LOOM_GIT_PROGRAM", default_value = "/usr/bin/git")]
    git_program: PathBuf,
    /// Absolute Loom pre-receive hook.
    #[arg(
        long,
        env = "LOOM_HOOK_PROGRAM",
        default_value = "/usr/local/bin/loom-git-hook"
    )]
    hook_program: PathBuf,
    /// Scratch directory for Origin mirrors and worktrees.
    #[arg(long, env = "ORIGIN_WORKDIR")]
    origin_workdir: Option<PathBuf>,
    /// Origin owner slug. Defaults to grogan-dev.
    #[arg(long, env = "ORIGIN_OWNER")]
    origin_owner: Option<String>,
    /// Origin git HTTPS host. Defaults to origin.cursor.com.
    #[arg(long, env = "ORIGIN_CLONE_HOST")]
    origin_clone_host: Option<String>,
    /// Origin REST base including `/v1/origin`.
    #[arg(long, env = "ORIGIN_API_BASE")]
    origin_api_base: Option<String>,
    /// HTTPS clone token (`x-access-token`). Installation tokens are used when empty.
    #[arg(long, env = "ORIGIN_CLONE_TOKEN")]
    origin_clone_token: Option<String>,
    /// Origin App id (`iss` / `kid` for check-run JWTs).
    #[arg(long, env = "ORIGIN_APP_ID")]
    origin_app_id: Option<String>,
    /// PKCS#8 Ed25519 PEM for the Origin App (not committed).
    #[arg(long, env = "ORIGIN_APP_PRIVATE_KEY")]
    origin_app_private_key: Option<String>,
    /// File containing the Origin App PKCS#8 Ed25519 PEM.
    #[arg(long, env = "ORIGIN_APP_PRIVATE_KEY_FILE")]
    origin_app_private_key_file: Option<PathBuf>,
    /// Origin App installation id.
    #[arg(long, env = "ORIGIN_INSTALLATION_ID")]
    origin_installation_id: Option<String>,
    /// Local apply script for the Loom VM.
    #[arg(long, env = "ORIGIN_LOOM_APPLY")]
    origin_loom_apply: Option<PathBuf>,
    /// Remote apply script for Grid.
    #[arg(long, env = "ORIGIN_GRID_APPLY")]
    origin_grid_apply: Option<PathBuf>,
    /// Remote apply script for Nero.
    #[arg(long, env = "ORIGIN_NERO_APPLY")]
    origin_nero_apply: Option<PathBuf>,
    /// SSH host for Grid and Nero applies (typically grid-01).
    #[arg(long, env = "ORIGIN_DEPLOY_SSH_HOST")]
    origin_deploy_ssh_host: Option<String>,
    /// SSH user for Grid and Nero applies.
    #[arg(long, env = "ORIGIN_DEPLOY_SSH_USER")]
    origin_deploy_ssh_user: Option<String>,
    /// SSH identity file for Grid and Nero applies.
    #[arg(long, env = "ORIGIN_DEPLOY_SSH_KEY")]
    origin_deploy_ssh_key: Option<PathBuf>,
    /// Wall-clock timeout in seconds for apply helpers.
    #[arg(long, env = "ORIGIN_APPLY_TIMEOUT_SECS")]
    origin_apply_timeout_secs: Option<u64>,
    /// HTTPS URL template or host for outbound Origin mirror push.
    /// `{owner}` / `{repo}` are substituted; a bare host uses `https://{host}/{owner}/{repo}.git`.
    #[arg(long, env = "ORIGIN_MIRROR_REMOTE")]
    origin_mirror_remote: Option<String>,
    /// Candidate review backend. Set to `grid` to enable asynchronous review Nero.
    #[arg(long, env = "LOOM_REVIEW_BACKEND")]
    review_backend: Option<String>,
    /// Loom URL reachable from Grid runner VMs.
    #[arg(long, env = "LOOM_PUBLIC_URL")]
    public_url: Option<String>,
    /// Grid internal API base used for CI and review runners.
    #[arg(long, env = "LOOM_GRID_URL")]
    grid_url: Option<String>,
    /// Grid internal runner credential.
    #[arg(long, env = "LOOM_GRID_INTERNAL_TOKEN")]
    grid_internal_token: Option<String>,
    /// JSON argv for review Nero (for example `["nero","--single","Review FEATURE_ID"]`).
    #[arg(long, env = "LOOM_REVIEW_COMMAND_JSON")]
    review_command_json: Option<String>,
    /// Wall-clock timeout for a review Nero runner.
    #[arg(long, env = "LOOM_REVIEW_TIMEOUT_SECS", default_value_t = 900)]
    review_timeout_secs: u64,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("loom: {error}");
        std::process::exit(2);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.token.is_empty() {
        return Err("LOOM_TOKEN is required".into());
    }
    let review_runner = review_runner_config(&cli)?;
    let origin = origin_config(&cli)?;
    let deploy_token = cli
        .deploy_token
        .filter(|value| !value.is_empty())
        .map(AccessToken::new);
    let app = LoomApp::new(ServerConfig {
        bind: cli.bind,
        root: cli.root,
        token: AccessToken::new(cli.token),
        deploy_token,
        origin,
        git_program: cli.git_program,
        hook_program: cli.hook_program,
        review_runner,
    })?;
    let listener = tokio::net::TcpListener::bind(app.bind()).await?;
    axum::serve(listener, app.router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn review_runner_config(
    cli: &Cli,
) -> Result<Option<ReviewRunnerConfig>, Box<dyn std::error::Error>> {
    let Some(backend) = non_empty(cli.review_backend.as_ref()) else {
        return Ok(None);
    };
    if !backend.eq_ignore_ascii_case("grid") {
        return Err("LOOM_REVIEW_BACKEND must be grid when set".into());
    }
    let public_url =
        non_empty(cli.public_url.as_ref()).ok_or("LOOM_PUBLIC_URL is required for Grid reviews")?;
    let grid_url =
        non_empty(cli.grid_url.as_ref()).ok_or("LOOM_GRID_URL is required for Grid reviews")?;
    let grid_token = non_empty(cli.grid_internal_token.as_ref())
        .ok_or("LOOM_GRID_INTERNAL_TOKEN is required for Grid reviews")?;
    let command_json = non_empty(cli.review_command_json.as_ref())
        .ok_or("LOOM_REVIEW_COMMAND_JSON is required for Grid reviews")?;
    let command = serde_json::from_str::<Vec<String>>(command_json)
        .map_err(|_| "LOOM_REVIEW_COMMAND_JSON must be a JSON argv")?;
    let config = ReviewRunnerConfig::new(
        grid_url,
        grid_token,
        public_url,
        command,
        cli.review_timeout_secs,
    )?;
    Ok(Some(config))
}

/// Empty environment values (e.g. `ORIGIN_APP_ID=` in an `EnvironmentFile`)
/// must behave exactly like unset ones.
fn non_empty(value: Option<&String>) -> Option<&String> {
    value.filter(|item| !item.is_empty())
}

fn origin_config(cli: &Cli) -> Result<OriginConfig, Box<dyn std::error::Error>> {
    let workdir = cli
        .origin_workdir
        .clone()
        .unwrap_or_else(|| cli.root.join("origin-work"));
    let mut origin = OriginConfig::production(workdir, cli.git_program.clone());
    if let Some(owner) = non_empty(cli.origin_owner.as_ref()) {
        origin.owner.clone_from(owner);
    }
    if let Some(host) = non_empty(cli.origin_clone_host.as_ref()) {
        origin.clone_host.clone_from(host);
    }
    if let Some(api_base) = non_empty(cli.origin_api_base.as_ref()) {
        origin.api_base.clone_from(api_base);
    }
    if let Some(token) = non_empty(cli.origin_clone_token.as_ref()) {
        origin.clone_token = Some(token.clone());
    }
    if let Some(app_id) = non_empty(cli.origin_app_id.as_ref()) {
        origin.app_id = Some(app_id.clone());
    }
    if let Some(path) = &cli.origin_app_private_key_file {
        let pem = std::fs::read_to_string(path)?;
        if !pem.trim().is_empty() {
            origin.app_private_key_pem = Some(pem);
        }
    }
    if origin.app_private_key_pem.is_none()
        && let Some(pem) = non_empty(cli.origin_app_private_key.as_ref())
    {
        origin.app_private_key_pem = Some(pem.clone());
    }
    if let Some(installation_id) = non_empty(cli.origin_installation_id.as_ref()) {
        origin.installation_id = Some(installation_id.clone());
    }
    if let Some(path) = &cli.origin_loom_apply {
        origin.loom_apply.clone_from(path);
    }
    if let Some(path) = &cli.origin_grid_apply {
        origin.grid_apply.clone_from(path);
    }
    if let Some(path) = &cli.origin_nero_apply {
        origin.nero_apply.clone_from(path);
    }
    if let Some(host) = non_empty(cli.origin_deploy_ssh_host.as_ref()) {
        origin.deploy_ssh_host = Some(host.clone());
    }
    if let Some(user) = non_empty(cli.origin_deploy_ssh_user.as_ref()) {
        origin.deploy_ssh_user = Some(user.clone());
    }
    if let Some(key) = &cli.origin_deploy_ssh_key {
        origin.deploy_ssh_key = Some(key.clone());
    }
    if let Some(seconds) = cli.origin_apply_timeout_secs {
        origin.apply_timeout = Duration::from_secs(seconds);
    }
    if let Some(remote) = non_empty(cli.origin_mirror_remote.as_ref()) {
        origin.mirror_remote = Some(remote.clone());
    }
    Ok(origin)
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            std::future::pending::<()>().await;
            return;
        };
        signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
