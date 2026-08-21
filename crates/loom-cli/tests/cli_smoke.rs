//! Smoke the user-facing `loom` command against a live Loom router.
#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use loom::auth::AccessToken;
use loom::catalog::{RepoCatalog, RepoEntry};
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};

const OWNER: &str = "owner-token";
fn test_app() -> (tempfile::TempDir, axum::Router, String, String) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let store = PersistentLoomStore::open(&root).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    let base = store
        .commit(
            &grant,
            "demo",
            None,
            BTreeMap::from([("README.md".to_owned(), b"base\n".to_vec())]),
        )
        .unwrap();
    let head = store
        .commit(
            &grant,
            "demo",
            Some(&base),
            BTreeMap::from([("README.md".to_owned(), b"candidate\n".to_vec())]),
        )
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();
    RepoCatalog::open(store.clone())
        .upsert(RepoEntry::minimal("demo"))
        .unwrap();
    let origin = OriginConfig::for_test(directory.path().join("origin-work"), true);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root,
        token: AccessToken::new(OWNER),
        deploy_token: None,
        origin,
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/bin/true"),
        review_runner: None,
    })
    .unwrap();
    (directory, app.router(), base.revision, head.revision)
}

fn loom_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_loom-cli"))
}

fn write_json(directory: &tempfile::TempDir, name: &str, value: &serde_json::Value) -> PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

async fn submit_candidate(url: &str, feature: &str, file: &Path) -> String {
    let (ok, text) = run_cli(
        url,
        &[
            "candidate",
            "submit",
            "--feature",
            feature,
            "--file",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ok, "candidate submit should succeed: {text}");
    text
}

fn run_help(args: &[&str]) -> (bool, String) {
    let output = loom_cli()
        .env_remove("LOOM_URL")
        .env_remove("LOOM_TOKEN")
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
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

#[test]
fn documented_command_shapes_parse_and_use_the_stable_name() {
    let (ok, top_level) = run_help(&[]);
    assert!(ok, "top-level help should succeed: {top_level}");
    assert!(top_level.contains("Usage: loom <COMMAND>"), "{top_level}");

    // These are the high-value command forms baked into Grid's Nero skills.
    // Appending --help validates Clap's exact option/argument grammar without
    // requiring credentials or making an HTTP request.
    let cases: &[&[&str]] = &[
        &["feature", "create", "--file", "/tmp/feature.json"],
        &["feature", "list"],
        &["feature", "show", "feature-id"],
        &["feature", "approve", "feature-id"],
        &["feature", "accept", "feature-id"],
        &["feature", "reject", "feature-id"],
        &[
            "candidate",
            "submit",
            "--feature",
            "feature-id",
            "--file",
            "/tmp/candidate.json",
        ],
        &["evidence", "--feature", "feature-id"],
        &["insights", "--feature", "feature-id"],
        &["review", "list", "--feature", "feature-id"],
        &["review", "apply", "--feature", "feature-id", "finding-id"],
        &["comment", "--feature", "feature-id", "--body", "looks good"],
        &["events", "--follow", "--feature", "feature-id"],
        &["status"],
    ];
    for args in cases {
        let (ok, text) = run_help(args);
        assert!(ok, "`loom {}` should parse: {text}", args.join(" "));
    }
}

#[tokio::test]
async fn documented_reads_comments_and_review_apply_hit_real_routes() {
    let (directory, router, base_revision, head_revision) = test_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let url = format!("http://{addr}");

    let feature_file = write_json(
        &directory,
        "feature.json",
        &serde_json::json!({
            "title": "cli smoke",
            "repositories": [{
                "base": { "repository": "demo", "revision": base_revision },
                "head": null,
                "target_ref": "refs/main",
            }],
            "scenarios": [{
                "name": "s", "given": "g", "when": "w", "then": "t",
            }],
        }),
    );
    let (ok, text) = run_cli(
        &url,
        &[
            "feature",
            "create",
            "--file",
            feature_file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ok, "feature create should succeed: {text}");
    let feature: serde_json::Value = serde_json::from_str(&text).unwrap();
    let feature_id = feature["id"].as_str().unwrap();

    let candidate_file = write_json(
        &directory,
        "candidate.json",
        &serde_json::json!({
            "repositories": [{
                "base": { "repository": "demo", "revision": base_revision },
                "head": { "repository": "demo", "revision": head_revision },
                "target_ref": "refs/main",
            }]
        }),
    );

    let (ok, text) = run_cli(&url, &["feature", "approve", feature_id]).await;
    assert!(ok, "feature approve should succeed: {text}");
    let text = submit_candidate(&url, feature_id, &candidate_file).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["candidate"]["repositories"][0]["head"]
            ["revision"],
        head_revision
    );

    for args in [
        vec!["feature", "list"],
        vec!["feature", "show", feature_id],
        vec!["evidence", "--feature", feature_id],
        vec!["insights", "--feature", feature_id],
        vec!["review", "list", "--feature", feature_id],
        vec!["events", "--feature", feature_id],
        vec!["status"],
    ] {
        let (ok, text) = run_cli(&url, &args).await;
        assert!(ok, "`loom {}` should succeed: {text}", args.join(" "));
    }

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
