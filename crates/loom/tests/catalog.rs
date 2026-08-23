//! Typed repo catalog: seeding, owner CRUD, and unknown-repo gating.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::catalog::{RepoCatalog, seed_entries};
use loom::origin::{OriginConfig, OriginEngine};
use loom::server::{LoomApp, ServerConfig};
use loom::{LoomError, PersistentLoomStore};
use tower::ServiceExt as _;

const OWNER: &str = "owner-token";
const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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

fn json_request(method: &str, uri: &str, bearer: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn feature_create_body(repository: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "catalog feature",
        "repositories": [{
            "base": { "repository": repository, "revision": REVISION },
            "target_ref": "refs/main",
        }],
        "scenarios": [{
            "name": "s", "given": "g", "when": "w", "then": "t",
        }],
    })
}

#[tokio::test]
async fn catalog_starts_empty_without_platform_siblings() {
    let (_directory, router) = test_app();
    let (status, listed) = send(
        &router,
        json_request("GET", "/v1/repos", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed, serde_json::json!([]));
}

#[tokio::test]
async fn catalog_crud_is_owner_only_and_round_trips() {
    let (_directory, router) = test_app();

    // Non-owner bearers cannot touch the catalog.
    let (status, _) = send(
        &router,
        json_request("GET", "/v1/repos", "wrong", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            "wrong",
            serde_json::json!({"name": "x"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Defaults: refs/main, loom_ci, deploy_target none.
    let (status, created) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": "demo", "description": "demo repo" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["protected_ref"], "refs/main");
    assert_eq!(created["deploy_target"]["kind"], "none");
    assert_eq!(created["description"], "demo repo");

    let (status, fetched) = send(
        &router,
        json_request("GET", "/v1/repos/demo", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, created);

    // Invalid names and refs are rejected. A single `/` is a project/repo name.
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": "bad/name/extra" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, slashed) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": "billing/api" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(slashed["name"], "billing/api");
    let (status, fetched) = send(
        &router,
        json_request(
            "GET",
            "/v1/repos/billing/api",
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["name"], "billing/api");
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": "demo", "protected_ref": "main" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, removed) = send(
        &router,
        json_request("DELETE", "/v1/repos/demo", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["name"], "demo");
    let (status, body) = send(
        &router,
        json_request("DELETE", "/v1/repos/demo", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "repo.unknown");
    let (status, _) = send(
        &router,
        json_request("GET", "/v1/repos/demo", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unregistered_repositories_read_as_not_found() {
    let (_directory, router) = test_app();

    // Feature creation on an unregistered repository is a clear 404.
    let (status, body) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "repo.unknown");

    // The Git gateway refuses unregistered repositories after authentication.
    let unregistered = Request::builder()
        .method("GET")
        .uri("/git/demo.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Bearer {OWNER}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, unregistered).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Registering the repository opens both routes.
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": "demo" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let registered = Request::builder()
        .method("GET")
        .uri("/git/demo.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Bearer {OWNER}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, registered).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Deleting a registered entry closes its routes again.
    let (status, _) = send(
        &router,
        json_request("DELETE", "/v1/repos/demo", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "repo.unknown");
}

#[test]
fn deploy_without_target_is_refused_even_with_passing_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let config = OriginConfig::for_test(directory.path().join("work"), true);
    let origin = OriginEngine::new(store, config);
    origin
        .catalog()
        .upsert(loom::catalog::RepoEntry::minimal("demo"))
        .unwrap();
    origin.record_loom_release("demo", OID, true).unwrap();
    let denied = origin.deploy("demo", OID).unwrap_err();
    assert!(matches!(
        denied,
        LoomError::DeployUnconfigured { repository } if repository == "demo"
    ));
}

#[test]
fn catalog_persists_owner_edits_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let config = OriginConfig::for_test(directory.path().join("work"), true);
    let catalog = RepoCatalog::with_defaults(store.clone(), seed_entries(&config));
    catalog.ensure_seeded().unwrap();
    catalog
        .upsert(loom::catalog::RepoEntry::minimal("demo"))
        .unwrap();
    catalog.remove("demo").unwrap();

    // A fresh handle still sees the owner's deletion, not resurrected defaults.
    let reopened = RepoCatalog::with_defaults(store.clone(), seed_entries(&config));
    assert!(reopened.get("demo").unwrap().is_none());
    assert!(reopened.list().unwrap().is_empty());

    // Unknown repositories cannot mint releases or queue mirrors.
    let origin = OriginEngine::new(store, config);
    let denied = origin.record_loom_release("demo", OID, true).unwrap_err();
    assert!(matches!(
        denied,
        LoomError::OriginRepositoryDenied { repository } if repository == "demo"
    ));
}

#[test]
fn slash_repository_names_store_as_a_single_filesystem_component() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = loom::NamespaceGrant::new(["billing/api".to_owned()].into_iter().collect());
    let revision = store
        .commit(
            &grant,
            "billing/api",
            None,
            [("README.md".to_owned(), b"ok".to_vec())]
                .into_iter()
                .collect(),
        )
        .unwrap();
    assert_eq!(revision.repository, "billing/api");
    let encoded = directory
        .path()
        .join("loom")
        .join("snapshots")
        .join("billing%2Fapi")
        .join(format!("{}.json", revision.revision));
    assert!(encoded.is_file(), "{}", encoded.display());
    let nested = directory.path().join("loom/snapshots/billing/api");
    assert!(!nested.exists(), "{}", nested.display());
}
