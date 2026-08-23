//! Projects, packs, import, apps, maintain queue, dashboard.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::PersistentLoomStore;
use loom::app::{AppCreate, pin_environment, rollback_environment};
use loom::auth::AccessToken;
use loom::control::ControlStore;
use loom::maintain::enqueue;
use loom::origin::OriginConfig;
use loom::pack::{PackKind, detect, plan};
use loom::secrets::{SecretStore, SecretUpsert};
use loom::server::{LoomApp, ServerConfig};
use loom::webhook;
use tower::ServiceExt as _;

const OWNER: &str = "owner-token";

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
        hook_program: PathBuf::from("/usr/bin/true"),
        review_runner: None,
    })
    .unwrap();
    (directory, app.router())
}

async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {OWNER}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[test]
fn pack_detects_node_python_go_rust() {
    let mut files = BTreeMap::new();
    files.insert(
        "package.json".to_owned(),
        br#"{"engines":{"node":"18"}}"#.to_vec(),
    );
    assert_eq!(detect(&files), PackKind::Node);
    let node = plan(&files);
    assert!(node.needs_legacy);
    assert!(node.runtime_image.contains("22"));

    files.clear();
    files.insert(
        "pyproject.toml".to_owned(),
        b"requires-python = \">=3.9\"\n".to_vec(),
    );
    assert_eq!(detect(&files), PackKind::Python);
    assert!(plan(&files).needs_legacy);

    files.clear();
    files.insert("go.mod".to_owned(), b"module x\n".to_vec());
    assert_eq!(detect(&files), PackKind::Go);

    files.clear();
    files.insert("Cargo.toml".to_owned(), b"[package]\nname=\"x\"\n".to_vec());
    assert_eq!(detect(&files), PackKind::Rust);
}

#[test]
fn app_rollback_restores_last_healthy_digest() {
    let files = BTreeMap::new();
    let mut app = AppCreate {
        project: "billing".to_owned(),
        name: "api".to_owned(),
        repo: None,
        kind: None,
        start: vec!["node".to_owned(), "server.js".to_owned()],
    }
    .into_record(&files)
    .unwrap();
    pin_environment(&mut app, "production", "digest-a", true);
    pin_environment(&mut app, "production", "digest-b", true);
    let restored = rollback_environment(&mut app, "production").unwrap();
    assert_eq!(restored, "digest-a");
}

#[tokio::test]
async fn project_crud_and_dashboard_are_owner_only() {
    let (_directory, router) = test_app();
    let (status, created) = send(
        &router,
        json_request(
            "POST",
            "/v1/projects",
            serde_json::json!({ "name": "billing", "repos": ["billing/api"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "billing");
    let (status, listed) = send(
        &router,
        json_request("GET", "/v1/projects", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let unauth = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(json_request("GET", "/status", serde_json::Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Loom"), "{html}");
}

#[tokio::test]
async fn empty_import_registers_slash_repo() {
    let (_directory, router) = test_app();
    let (status, body) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos/import",
            serde_json::json!({
                "project": "billing",
                "name": "api",
                "git_url": "",
                "app": false,
                "maintain": false,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["repo"], "billing/api");
    let (status, fetched) = send(
        &router,
        json_request("GET", "/v1/repos/billing/api", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["name"], "billing/api");
}

#[tokio::test]
async fn maintain_status_reports_agent_unconfigured_without_key() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let control = ControlStore::new(store);
    let job = enqueue(&control, "billing/api", "deps", "npm:lodash", false).unwrap();
    assert_eq!(job.status, "blocked");
    assert_eq!(job.blocked.as_deref(), Some("agent_unconfigured"));
    let again = enqueue(&control, "billing/api", "deps", "npm:lodash", false).unwrap();
    assert_eq!(again.id, job.id);
}

#[tokio::test]
async fn mcp_manifest_lists_verb_table() {
    let (_directory, router) = test_app();
    let (status, body) = send(
        &router,
        json_request("GET", "/v1/mcp", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tools = body["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool == "app"));
    assert!(tools.iter().any(|tool| tool == "maintain"));
    assert!(!tools.iter().any(|tool| tool == "pr"));
    let (status, body) = send(
        &router,
        json_request(
            "POST",
            "/v1/mcp",
            serde_json::json!({ "tool": "app", "arguments": {} }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["code"], "mcp.call_unimplemented");
}

#[test]
fn secrets_round_trip_aes_gcm_and_omit_secret_values() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let secrets = SecretStore::new(store, "test-secrets-key");
    secrets
        .upsert(SecretUpsert {
            project: "billing".to_owned(),
            environment: "staging".to_owned(),
            key: "DATABASE_URL".to_owned(),
            value: "postgres://x".to_owned(),
            secret: true,
        })
        .unwrap();
    let listed = secrets.list("billing").unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].secret);
    assert!(listed[0].value.is_none());
    let injected = secrets.inject("billing", "staging").unwrap();
    assert_eq!(
        injected.get("DATABASE_URL").map(String::as_str),
        Some("postgres://x")
    );
}

#[test]
fn webhook_sign_is_keyed_hmac_not_concat_hash() {
    let a = webhook::sign("secret-a", b"body");
    let b = webhook::sign("secret-b", b"body");
    assert_ne!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn import_tree_walk_rejects_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(root.join("ok.txt"), b"ok").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("stolen")).unwrap();
    let error = loom::import::read_tree_for_test(root).unwrap_err();
    assert!(matches!(error, loom::LoomError::InvalidPath { .. }));
}
