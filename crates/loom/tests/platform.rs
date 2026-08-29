//! Projects, import, and import tree-walk safety.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
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

#[allow(clippy::needless_pass_by_value)]
fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {OWNER}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn project_crud_is_owner_only() {
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
                .uri("/v1/projects")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let (status, deleted) = send(
        &router,
        json_request("DELETE", "/v1/projects/billing", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, _) = send(
        &router,
        json_request("GET", "/v1/projects/billing", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

#[test]
fn import_tree_walk_rejects_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(root.join("ok.txt"), b"ok").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("stolen")).unwrap();
    let error = loom::import::read_tree_for_test(root).unwrap_err();
    assert!(matches!(error, loom::LoomError::InvalidPath { .. }));
}
