//! Insights pre-flight: digest-cached static analysis before review.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::contracts::RepositoryBinding;
use loom::features::{EvidencePolicy, FeatureCreate, FeatureStore, Scenario};
use loom::insights::InsightsEngine;
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};
use tower::ServiceExt as _;

const OWNER: &str = "owner-token";

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

fn rust_base() -> BTreeMap<String, Vec<u8>> {
    files(&[
        (
            "Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/lib.rs", b"use crate::util;\nfn greet() {}\n"),
        (
            "loom-ci.toml",
            b"[ci]\ntimeout_seconds = 5\ncommands = [[\"true\"]]\n",
        ),
    ])
}

fn rust_head() -> BTreeMap<String, Vec<u8>> {
    files(&[
        (
            "Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "src/lib.rs",
            b"use crate::util;\nuse crate::extra;\nfn greet() {}\nfn farewell() {}\n",
        ),
        (
            "loom-ci.toml",
            b"[ci]\ntimeout_seconds = 5\ncommands = [[\"true\"]]\n",
        ),
    ])
}

#[test]
fn insights_engine_diffs_rust_tree_and_replays_from_cache() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    let base = store.commit(&grant, "demo", None, rust_base()).unwrap();
    let head = store
        .commit(&grant, "demo", Some(&base), rust_head())
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();
    let bindings = vec![RepositoryBinding::new(base, "refs/main".to_owned()).with_head(head)];

    let engine = InsightsEngine::new(store);
    let first = engine.run("feature-insights", &bindings).unwrap();
    assert_eq!(first.schema_version, "v1");
    assert_eq!(first.repos.len(), 1);
    let repo = &first.repos[0];
    assert_eq!(repo.toolchain, "cargo");
    assert!(
        repo.diffstat.files_changed + repo.diffstat.files_added + repo.diffstat.files_removed > 0
    );
    assert!(
        !repo.graph_delta.nodes_added.is_empty() || repo.graph_delta.edges_added > 0,
        "expected graph delta, got {:?}",
        repo.graph_delta
    );
    first.digest.validate().unwrap();

    let second = engine.run("feature-insights", &bindings).unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(
        engine.ref_for(&first).unwrap().job_id,
        engine.ref_for(&second).unwrap().job_id
    );
}

fn test_app(root: PathBuf) -> axum::Router {
    let origin = OriginConfig::for_test(root.parent().unwrap().join("origin-work"), true);
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
    app.router()
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    bearer: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
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

#[tokio::test]
async fn insights_get_after_candidate_submit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let store = PersistentLoomStore::open(&root).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    let base = store.commit(&grant, "demo", None, rust_base()).unwrap();
    let head = store
        .commit(&grant, "demo", Some(&base), rust_head())
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();
    let features = FeatureStore::new(store);
    let feature = features
        .create(FeatureCreate {
            title: "insights candidate".to_owned(),
            repositories: vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned())],
            scenarios: vec![Scenario {
                name: "diff".to_owned(),
                given: "a rust tree".to_owned(),
                when: "a candidate is submitted".to_owned(),
                then: "insights exist".to_owned(),
            }],
            evidence_policy: EvidencePolicy::minimum(),
        })
        .unwrap();
    features.approve(&feature.id).unwrap();

    let router = test_app(root);
    let (status, submitted) = send(
        &router,
        "POST",
        &format!("/v1/features/{}/candidates", feature.id),
        OWNER,
        serde_json::json!({
            "repositories": [{
                "base": { "repository": "demo", "revision": base.revision },
                "head": { "repository": "demo", "revision": head.revision },
                "target_ref": "refs/main",
            }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{submitted}");
    assert!(
        submitted["candidate"]["insights"]["digest"]["value"]
            .as_str()
            .is_some()
    );

    let (status, bundle) = send(
        &router,
        "GET",
        &format!("/v1/features/{}/insights", feature.id),
        OWNER,
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["schema_version"], "v1");
    assert_eq!(bundle["repos"][0]["toolchain"], "cargo");
    assert!(
        bundle["repos"][0]["diffstat"]["files_changed"]
            .as_u64()
            .unwrap()
            > 0
            || bundle["repos"][0]["diffstat"]["files_added"]
                .as_u64()
                .unwrap()
                > 0
    );

    let (status, minted) = send(
        &router,
        "POST",
        "/v1/tokens",
        OWNER,
        serde_json::json!({
            "name": "evidence-reader",
            "repositories": ["demo"],
            "perms": ["evidence"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let evidence = minted["secret"].as_str().unwrap();
    let (status, _) = send(
        &router,
        "GET",
        &format!("/v1/features/{}/insights", feature.id),
        evidence,
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, minted) = send(
        &router,
        "POST",
        "/v1/tokens",
        OWNER,
        serde_json::json!({
            "name": "features-only",
            "repositories": ["demo"],
            "perms": ["features"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let features_only = minted["secret"].as_str().unwrap();
    let (status, _) = send(
        &router,
        "GET",
        &format!("/v1/features/{}/insights", feature.id),
        features_only,
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
