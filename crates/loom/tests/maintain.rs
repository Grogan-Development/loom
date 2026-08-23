//! Maintenance class: born approved, HTTP cannot spoof it, accept is gated.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::contracts::{RepositoryBinding, RepositoryRevision};
use loom::features::{
    EvidencePolicy, FeatureClass, FeatureCreate, FeatureGate, FeatureStore, Scenario,
};
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};
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

fn scenario() -> Scenario {
    Scenario {
        name: "green".to_owned(),
        given: "a repo".to_owned(),
        when: "deps bump".to_owned(),
        then: "tests pass".to_owned(),
    }
}

#[test]
fn scheduler_maintenance_is_born_approved() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    let base = store
        .commit(
            &grant,
            "demo",
            None,
            [("README.md".to_owned(), b"ok".to_vec())]
                .into_iter()
                .collect(),
        )
        .unwrap();
    let features = FeatureStore::new(store);
    let feature = features
        .create_with_authority(
            FeatureCreate {
                title: "bump lodash".to_owned(),
                repositories: vec![RepositoryBinding::new(base, "refs/main".to_owned())],
                scenarios: vec![scenario()],
                evidence_policy: EvidencePolicy::minimum(),
                class: FeatureClass::Maintenance,
                subclass: Some("deps".to_owned()),
                fingerprint: Some("npm:lodash:4.17.21->4.17.22".to_owned()),
            },
            true,
        )
        .unwrap();
    assert_eq!(feature.gate, FeatureGate::Approved);
    assert_eq!(feature.class, FeatureClass::Maintenance);
}

#[test]
fn human_create_cannot_spoof_maintenance_class() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let revision = RepositoryRevision::new("demo", REVISION).unwrap();
    let features = FeatureStore::new(store);
    let denied = features.create(FeatureCreate {
        title: "spoof".to_owned(),
        repositories: vec![RepositoryBinding::new(revision, "refs/main".to_owned())],
        scenarios: vec![scenario()],
        evidence_policy: EvidencePolicy::minimum(),
        class: FeatureClass::Maintenance,
        subclass: Some("deps".to_owned()),
        fingerprint: Some("npm:lodash".to_owned()),
    });
    assert!(denied.is_err());
}

#[tokio::test]
async fn http_rejects_maintenance_class_on_create() {
    let (_directory, router) = test_app();
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
    let (status, body) = send(
        &router,
        json_request(
            "POST",
            "/v1/features",
            OWNER,
            serde_json::json!({
                "title": "spoof",
                "class": "maintenance",
                "subclass": "deps",
                "fingerprint": "npm:lodash",
                "repositories": [{
                    "base": { "repository": "demo", "revision": REVISION },
                    "target_ref": "refs/main",
                }],
                "scenarios": [{
                    "name": "s", "given": "g", "when": "w", "then": "t",
                }],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "feature.invalid");
}

#[tokio::test]
async fn maintain_token_cannot_accept_product_features() {
    let (_directory, router) = test_app();
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
    let (status, minted) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "bot",
                "repositories": ["demo"],
                "perms": ["maintain", "features"],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = minted["secret"].as_str().unwrap();
    let (status, created) = send(
        &router,
        json_request(
            "POST",
            "/v1/features",
            OWNER,
            serde_json::json!({
                "title": "product work",
                "repositories": [{
                    "base": { "repository": "demo", "revision": REVISION },
                    "target_ref": "refs/main",
                }],
                "scenarios": [{
                    "name": "s", "given": "g", "when": "w", "then": "t",
                }],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap();
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{id}/approve"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{id}/accept"),
            secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
