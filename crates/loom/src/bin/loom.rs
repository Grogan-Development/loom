//! Standalone Loom server.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use loom::auth::AccessToken;
use loom::server::{LoomApp, ServerConfig};

#[derive(Debug, Parser)]
#[command(name = "loom", version, about = "Standalone Loom smart repository")]
struct Cli {
    /// Listen address. Docker images default to `0.0.0.0:8080`.
    #[arg(long, env = "LOOM_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// Absolute private dataset root.
    #[arg(long, env = "LOOM_ROOT")]
    root: PathBuf,
    /// Owner bearer token.
    #[arg(long, env = "LOOM_TOKEN")]
    token: String,
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
    let app = LoomApp::new(ServerConfig {
        bind: cli.bind,
        root: cli.root,
        token: AccessToken::new(cli.token),
        git_program: cli.git_program,
        hook_program: cli.hook_program,
    })?;
    let listener = tokio::net::TcpListener::bind(app.bind()).await?;
    axum::serve(listener, app.router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
