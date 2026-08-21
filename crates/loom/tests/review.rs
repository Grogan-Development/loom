//! Review findings, HITL apply, comments, and scoped-token isolation.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64ct::{Base64, Encoding as _};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::ci::CiEngine;
use loom::contracts::{ArtifactDigest, RepositoryBinding};
use loom::features::{EvidencePolicy, FeatureCreate, FeatureStore, Scenario};
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;

const OWNER: &str = "owner-token";

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

fn test_app() -> (tempfile::TempDir, PathBuf, axum::Router) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let origin = OriginConfig::for_test(directory.path().join("origin-work"), true);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root: root.clone(),
        token: AccessToken::new(OWNER),
        deploy_token: None,
        origin,
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/bin/true"),
    })
    .unwrap();
    (directory, root, app.router())
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

fn seed_feature(root: &Path) -> (PersistentLoomStore, NamespaceGrant, String) {
    let store = PersistentLoomStore::open(root).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    let base = store
        .commit(
            &grant,
            "demo",
            None,
            files(&[
                ("README.md", b"# demo\n"),
                (
                    "loom-ci.toml",
                    b"[ci]\ntimeout_seconds = 5\ncommands = [[\"true\"]]\n",
                ),
            ]),
        )
        .unwrap();
    let head = store
        .commit(
            &grant,
            "demo",
            Some(&base),
            files(&[("README.md", b"# demo candidate\n")]),
        )
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();
    let features = FeatureStore::new(store.clone());
    let feature = features
        .create(FeatureCreate {
            title: "review candidate".to_owned(),
            repositories: vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned())],
            scenarios: vec![Scenario {
                name: "readme exists".to_owned(),
                given: "a repository".to_owned(),
                when: "the candidate is reviewed".to_owned(),
                then: "findings can be applied".to_owned(),
            }],
            evidence_policy: EvidencePolicy::minimum(),
        })
        .unwrap();
    features.approve(&feature.id).unwrap();
    let bindings = vec![RepositoryBinding::new(base, "refs/main".to_owned()).with_head(head)];
    let ci = CiEngine::new(store.clone());
    let job = ci.run(&feature.id, &bindings).unwrap();
    let candidate = ci.candidate_from_job(&job, bindings).unwrap();
    features.attach_candidate(&feature.id, candidate).unwrap();
    (store, grant, feature.id)
}

fn upsert_patch(path: &str, contents: &[u8]) -> serde_json::Value {
    let digest = ArtifactDigest::sha256(sha256_hex(contents)).unwrap();
    serde_json::json!({
        "operation": "upsert",
        "path": path,
        "mode": "regular",
        "digest": { "algorithm": digest.algorithm, "value": digest.value },
        "contents_base64": Base64::encode_string(contents),
    })
}

#[tokio::test]
async fn start_review_for_current_candidate() {
    let (_directory, root, router) = test_app();
    let (_store, _grant, feature_id) = seed_feature(&root);

    let (status, created) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["status"].as_str().unwrap(), "pending");
    assert!(created["findings"].as_array().unwrap().is_empty());

    let (status, listed) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/features/{feature_id}/reviews"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], created["id"]);
}

#[tokio::test]
async fn apply_requires_approve_then_materializes_patch() {
    let (_directory, root, router) = test_app();
    let (store, grant, feature_id) = seed_feature(&root);
    let contents = b"applied by review\n";

    let (status, review) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let review_id = review["id"].as_str().unwrap();

    let (status, review) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews/{review_id}/findings"),
            OWNER,
            serde_json::json!({
                "findings": [{
                    "severity": "warning",
                    "repo": "demo",
                    "path": "README.md",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "add a note file",
                    "suggested_patch": [upsert_patch("NOTE.md", contents)],
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let finding_id = review["findings"][0]["id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/findings/{finding_id}/apply"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, approved) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/findings/{finding_id}/approve"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(approved["approved"].as_bool().unwrap());

    let (status, applied) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/findings/{finding_id}/apply"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let revision = applied["applied"]["revision"].as_str().unwrap();
    assert!(!revision.is_empty());
    assert_eq!(applied["applied"]["repository"].as_str().unwrap(), "demo");

    let head = loom::contracts::RepositoryRevision::new("demo", revision).unwrap();
    let materialized = store.materialize(&grant, &head).unwrap();
    assert_eq!(materialized.get("NOTE.md").unwrap(), contents);

    let (status, feature) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/features/{feature_id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        feature["candidate"]["repositories"][0]["head"]["revision"].as_str(),
        Some(revision)
    );
}

#[tokio::test]
async fn applied_patch_invalidates_evidence_until_ci_reruns() {
    let (_directory, root, router) = test_app();
    let (store, _grant, feature_id) = seed_feature(&root);
    let contents = b"applied by review\n";

    let (status, review) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews"),
            OWNER,
            serde_json::json!({
                "findings": [{
                    "severity": "warning",
                    "repo": "demo",
                    "path": "README.md",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "add a note file",
                    "suggested_patch": [upsert_patch("NOTE.md", contents)],
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let finding_id = review["findings"][0]["id"].as_str().unwrap().to_owned();

    let (status, applied) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/findings/{finding_id}/apply"),
            OWNER,
            serde_json::json!({ "approve": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let patched_revision = applied["applied"]["revision"].as_str().unwrap().to_owned();

    // The old evidence bundle no longer describes the candidate head.
    let (status, feature) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/features/{feature_id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(feature["candidate"]["evidence"]["tests_passed"], false);

    // Gate 2 must fail closed on the stale evidence.
    let (status, body) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/accept"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"].as_str().unwrap(), "ci.failed");

    // Re-running CI on the patched head replaces the candidate and unblocks.
    let features = FeatureStore::new(store.clone());
    let base = {
        let feature = features.get(&feature_id).unwrap();
        feature.candidate.unwrap().repositories[0].base.clone()
    };
    let head = loom::contracts::RepositoryRevision::new("demo", patched_revision).unwrap();
    let bindings = vec![RepositoryBinding::new(base, "refs/main".to_owned()).with_head(head)];
    let ci = CiEngine::new(store.clone());
    let job = ci.run(&feature_id, &bindings).unwrap();
    let candidate = ci.candidate_from_job(&job, bindings).unwrap();
    features.attach_candidate(&feature_id, candidate).unwrap();

    let (status, accepted) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/accept"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accepted["feature"]["gate"].as_str().unwrap(), "accepted");
}

#[tokio::test]
async fn comments_thread_round_trip() {
    let (_directory, root, router) = test_app();
    let (_store, _grant, feature_id) = seed_feature(&root);

    let (status, parent) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/comments"),
            OWNER,
            serde_json::json!({
                "author": "human",
                "body": "please add a note",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let parent_id = parent["id"].as_str().unwrap();

    let (status, reply) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/comments"),
            OWNER,
            serde_json::json!({
                "author": "agent:review",
                "body": "posted a finding",
                "in_reply_to": parent_id,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(reply["in_reply_to"].as_str().unwrap(), parent_id);

    let (status, listed) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/features/{feature_id}/comments"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["body"].as_str().unwrap(), "please add a note");
    assert_eq!(listed[1]["author"].as_str().unwrap(), "agent:review");
}

#[tokio::test]
async fn scoped_token_for_other_repo_cannot_post_findings() {
    let (_directory, root, router) = test_app();
    let (_store, _grant, feature_id) = seed_feature(&root);

    let (status, review) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews"),
            OWNER,
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let review_id = review["id"].as_str().unwrap();

    let (status, minted) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "other-ws",
                "repositories": ["other"],
                "perms": ["features"],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = minted["secret"].as_str().unwrap();

    let (status, body) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/reviews/{review_id}/findings"),
            secret,
            serde_json::json!({
                "findings": [{
                    "severity": "note",
                    "repo": "demo",
                    "path": "README.md",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "should be forbidden",
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"].as_str().unwrap(), "loom.forbidden");
}
