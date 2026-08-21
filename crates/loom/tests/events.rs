//! Durable event log, scoped-token filtering, and live SSE tail.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::PersistentLoomStore;
use loom::auth::AccessToken;
use loom::events::EventLog;
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use tower::ServiceExt as _;

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

fn json_request(method: &str, uri: &str, bearer: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn mint(
    router: &axum::Router,
    name: &str,
    repositories: &[&str],
    perms: &[&str],
) -> (String, String) {
    let (status, body) = send(
        router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": name,
                "repositories": repositories,
                "perms": perms,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = body["secret"].as_str().unwrap().to_owned();
    let id = body["token"]["id"].as_str().unwrap().to_owned();
    (id, secret)
}

fn feature_create_body(repository: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "scoped feature",
        "repositories": [{
            "base": { "repository": repository, "revision": REVISION },
            "target_ref": "refs/main",
        }],
        "scenarios": [{
            "name": "s", "given": "g", "when": "w", "then": "t",
        }],
    })
}

#[test]
fn emit_then_since_returns_catch_up() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let log = EventLog::new(store);
    let first = log
        .emit(
            "feature.created",
            ["demo"],
            serde_json::json!({ "id": "one" }),
        )
        .unwrap();
    let second = log
        .emit(
            "feature.approved",
            ["demo"],
            serde_json::json!({ "id": "one" }),
        )
        .unwrap();
    assert!(first.id.starts_with("evt_"));
    assert!(first.id < second.id);

    let all = log.since(None, 200).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].id, first.id);
    assert_eq!(all[1].id, second.id);

    let after = log.since(Some(&first.id), 200).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, second.id);
    assert_eq!(after[0].kind, "feature.approved");
}

#[tokio::test]
async fn scoped_token_without_events_is_forbidden_and_scope_filters() {
    let (_directory, router) = test_app();

    let (status, _) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("other")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_id, no_events) = mint(&router, "ws-git", &["demo"], &["git"]).await;
    let (status, _) = send(
        &router,
        json_request("GET", "/v1/events", &no_events, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_id, secret) = mint(&router, "ws-events", &["demo"], &["events"]).await;
    let (status, page) = send(
        &router,
        json_request("GET", "/v1/events", &secret, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["kind"].as_str().unwrap(), "feature.created");
    assert_eq!(events[0]["repos"][0].as_str().unwrap(), "demo");
}

#[tokio::test]
async fn cursor_advances_past_a_window_of_invisible_events() {
    let (_directory, router) = test_app();

    // Two "other" events the scoped token cannot see, then one "demo" event.
    for _ in 0..2 {
        let (status, _) = send(
            &router,
            json_request("POST", "/v1/features", OWNER, feature_create_body("other")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_id, secret) = mint(&router, "ws-events", &["demo"], &["events"]).await;

    // limit=2 scans only the two invisible events: zero visible results, but
    // the cursor must still advance so the next page reaches the demo event.
    let (status, page) = send(
        &router,
        json_request(
            "GET",
            "/v1/events?limit=2",
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page["events"].as_array().unwrap().is_empty());
    let cursor = page["cursor"].as_str().unwrap().to_owned();
    assert!(
        !cursor.is_empty(),
        "cursor must advance past invisible page"
    );

    let (status, page) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/events?limit=2&since={cursor}"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["repos"][0].as_str().unwrap(), "demo");
}

#[tokio::test]
async fn follow_receives_event_emitted_after_connect() {
    let (_directory, router) = test_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let client = reqwest::Client::new();
    let request = client
        .get(format!("http://{addr}/v1/events?follow=1"))
        .header("authorization", format!("Bearer {OWNER}"))
        .send();
    let mut response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .unwrap()
        .unwrap();
    assert!(response.status().is_success());

    let create = client
        .post(format!("http://{addr}/v1/features"))
        .header("authorization", format!("Bearer {OWNER}"))
        .json(&feature_create_body("demo"))
        .send();
    tokio::spawn(async move {
        let _ = create.await;
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut buf = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timeout waiting for SSE feature.created"
        );
        let chunk = tokio::time::timeout(remaining, response.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        buf.push_str(&String::from_utf8_lossy(&chunk));
        if buf.contains("feature.created") {
            break;
        }
    }
}
