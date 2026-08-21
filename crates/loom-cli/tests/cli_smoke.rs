//! Smoke the loom-cli binary against a live Loom router.
#![allow(clippy::unwrap_used, missing_docs)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use loom::auth::AccessToken;
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};

const OWNER: &str = "owner-token";
const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn test_app() -> (tempfile::TempDir, axum::Router) {
    let directory = tempfile::tempdir().unwrap();
    let origin = OriginConfig::for_test(directory.path().join("origin-work"), true);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root: directory.path().join("loom"),
        token: AccessToken::new(OWNER),
        deploy_token: None,
        origin,
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/bin/true"),
    })
    .unwrap();
    (directory, app.router())
}

fn loom_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_loom-cli"))
}

async fn run_cli(url: &str, args: &[&str]) -> (bool, String) {
    let url = url.to_owned();
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        let output = loom_cli()
            .env("LOOM_URL", url)
            .env("LOOM_TOKEN", OWNER)
            .args(&args)
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.success(), text)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn comment_and_review_apply_hit_real_routes() {
    let (_directory, router) = test_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let url = format!("http://{addr}");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let created = client
        .post(format!("{url}/v1/features"))
        .bearer_auth(OWNER)
        .json(&serde_json::json!({
            "title": "cli smoke",
            "repositories": [{
                "base": { "repository": "demo", "revision": REVISION },
                "target_ref": "refs/main",
            }],
            "scenarios": [{
                "name": "s", "given": "g", "when": "w", "then": "t",
            }],
        }))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success(), "{}", created.status());
    let feature: serde_json::Value = created.json().await.unwrap();
    let feature_id = feature["id"].as_str().unwrap();

    let (ok, text) = run_cli(
        &url,
        &["comment", "--feature", feature_id, "--body", "looks good"],
    )
    .await;
    assert!(ok, "comment should succeed: {text}");
    assert!(text.contains("looks good"), "{text}");

    let (ok, text) = run_cli(
        &url,
        &[
            "review",
            "apply",
            "--feature",
            feature_id,
            "00000000-0000-0000-0000-000000000000",
        ],
    )
    .await;
    assert!(!ok, "apply without a live finding should fail: {text}");
    assert!(
        text.contains("review.conflict") || text.contains("review.finding_not_found"),
        "apply must hit /v1/features/{{id}}/findings/{{fid}}/apply, not a missing route: {text}"
    );
}
