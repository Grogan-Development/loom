//! Private Loom RPC revision verification and atomic-ref acceptance.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64ct::{Base64, Encoding as _};
use http_body_util::BodyExt as _;
use loom::contracts::{ArtifactDigest, RepositoryBinding, RepositoryRevision};
use loom::{
    AtomicRefRequest, CandidateRevisionCheck, LoomHealth, LoomRpc, LoomRpcClient, NamespaceGrant,
    PersistentLoomStore, RefCasUpdate, SoftwareEdge, SoftwareGraph, SoftwareNode,
    SourceCommitMutation, SourceCommitRequest, SourceCommitResult, SourceFileMode,
};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

fn digest(bytes: &[u8]) -> ArtifactDigest {
    let value = Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        });
    ArtifactDigest::sha256(value).unwrap()
}

fn upsert(path: &str, mode: SourceFileMode, contents: &[u8]) -> SourceCommitMutation {
    SourceCommitMutation::Upsert {
        path: path.to_owned(),
        mode,
        digest: digest(contents),
        contents_base64: Base64::encode_string(contents),
    }
}

async fn post_source_commit(api: &axum::Router, request: serde_json::Value) -> StatusCode {
    api.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/loom/v1/source/commit")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn rpc_verifies_reachable_candidate_revisions_and_ref_base() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = store
        .commit(&grant, "grid", None, files(&[("a", b"base")]))
        .unwrap();
    let head = store
        .commit(&grant, "grid", Some(&base), files(&[("a", b"head")]))
        .unwrap();
    store
        .create_ref(&grant, "grid", "refs/main", &base)
        .unwrap();
    let api = LoomRpc::new(store).router();
    let request = CandidateRevisionCheck {
        repositories: vec![
            RepositoryBinding::new(base.clone(), "refs/main".to_owned()).with_head(head.clone()),
        ],
    };
    let response = api
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/loom/v1/candidates/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status: loom::CandidateRevisionStatus =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(status.ready);
    assert!(status.failures.is_empty());
}

#[tokio::test]
async fn rpc_health_checks_persistent_state_and_client_contract() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, LoomRpc::new(store).router())
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    assert_eq!(
        client.health().await.unwrap(),
        LoomHealth {
            schema_version: "v1".to_owned(),
            persistent_state_ready: true,
        }
    );
}

#[tokio::test]
async fn rpc_atomically_promotes_reads_back_and_returns_exact_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = store
        .commit(&grant, "grid", None, files(&[("a", b"base")]))
        .unwrap();
    let head = store
        .commit(&grant, "grid", Some(&base), files(&[("a", b"head")]))
        .unwrap();
    store
        .create_ref(&grant, "grid", "refs/main", &base)
        .unwrap();
    let api = LoomRpc::new(store).router();
    let request = AtomicRefRequest {
        updates: vec![RefCasUpdate::new(
            "grid",
            "refs/main",
            base.clone(),
            head.clone(),
        )],
    };
    let response = api
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/loom/v1/refs/cas")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: loom::AtomicRefResult =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(result.read_back);
    assert_eq!(result.rollback.len(), 1);
    assert_eq!(result.rollback[0].expected, head);
    assert_eq!(result.rollback[0].head, base);
}

#[tokio::test]
async fn rpc_reports_unknown_revisions_as_bounded_readiness_failures() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let api = LoomRpc::new(store).router();
    let request = CandidateRevisionCheck {
        repositories: vec![
            RepositoryBinding::new(
                RepositoryRevision::new("grid", "a".repeat(64)).unwrap(),
                "refs/main".to_owned(),
            )
            .with_head(RepositoryRevision::new("grid", "b".repeat(64)).unwrap()),
        ],
    };
    let response = api
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/loom/v1/candidates/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status: loom::CandidateRevisionStatus =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(!status.ready);
    assert_eq!(status.failures, vec!["loom.revision_unavailable"]);
}

#[tokio::test]
async fn rpc_client_preserves_structured_verification_and_atomic_ref_contracts() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = store
        .commit(&grant, "grid", None, files(&[("a", b"base")]))
        .unwrap();
    let head = store
        .commit(&grant, "grid", Some(&base), files(&[("a", b"head")]))
        .unwrap();
    store
        .create_ref(&grant, "grid", "refs/main", &base)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, LoomRpc::new(store).router())
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();
    let bindings =
        vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned()).with_head(head.clone())];
    assert!(client.verify_candidate(&bindings).await.unwrap().ready);
    let promoted = client
        .compare_and_swap(&[RefCasUpdate::new("grid", "refs/main", base, head)])
        .await
        .unwrap();
    assert!(promoted.read_back);
    assert_eq!(promoted.rollback.len(), 1);
}

#[tokio::test]
async fn rpc_ingests_and_reads_one_exact_revision_scoped_software_graph() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let revision = store
        .commit(
            &grant,
            "grid",
            None,
            files(&[("Cargo.toml", b"[workspace]")]),
        )
        .unwrap();
    let graph = SoftwareGraph {
        schema_version: "v1".to_owned(),
        revision,
        analyzer_digest: loom::contracts::ArtifactDigest::sha256("a".repeat(64)).unwrap(),
        nodes: vec![
            SoftwareNode {
                id: "crate:grid-loom".to_owned(),
                kind: "rust_crate".to_owned(),
                path: "crates/loom/Cargo.toml".to_owned(),
                label: "grid-loom".to_owned(),
            },
            SoftwareNode {
                id: "crate:grid-contracts".to_owned(),
                kind: "rust_crate".to_owned(),
                path: "crates/grid-contracts/Cargo.toml".to_owned(),
                label: "grid-contracts".to_owned(),
            },
        ],
        edges: vec![SoftwareEdge {
            source: "crate:grid-loom".to_owned(),
            target: "crate:grid-contracts".to_owned(),
            kind: "depends_on".to_owned(),
        }],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, LoomRpc::new(store).router())
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    client.ingest_software_graph(&graph).await.unwrap();
    assert_eq!(client.software_graph(&graph.revision).await.unwrap(), graph);
}

#[tokio::test]
async fn rpc_materializes_one_exact_digest_verified_revision() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let revision = store
        .commit(
            &grant,
            "grid",
            None,
            files(&[
                ("Cargo.toml", b"[workspace]"),
                ("src/lib.rs", b"pub fn grid() {}"),
            ]),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, LoomRpc::new(store).router())
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    let materialized = client.source_materialization(&revision).await.unwrap();
    assert_eq!(materialized.revision, revision);
    assert_eq!(materialized.files.len(), 2);
    assert_eq!(materialized.files[0].path, "Cargo.toml");
    assert_eq!(
        Base64::decode_vec(&materialized.files[0].contents_base64).unwrap(),
        b"[workspace]"
    );
}

#[tokio::test]
async fn rpc_client_commits_and_strictly_binds_one_native_source_result() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = store
        .commit(
            &grant,
            "grid",
            None,
            files(&[("README.md", b"base"), ("stale", b"delete me")]),
        )
        .unwrap();
    let request = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base: base.clone(),
        mutations: vec![
            upsert("README.md", SourceFileMode::Regular, b"candidate"),
            SourceCommitMutation::Delete {
                path: "stale".to_owned(),
            },
        ],
    };
    let readback_store = store.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, LoomRpc::new(store).router())
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    let committed = client.commit_source(&request).await.unwrap();
    assert_eq!(committed.schema_version, "v1");
    assert_eq!(committed.base, base);
    assert_eq!(committed.mutation_count, 2);
    let replay = client.commit_source(&request).await.unwrap();
    assert_eq!(replay, committed);
    let source = readback_store
        .materialize_source(&grant, &committed.head)
        .unwrap();
    assert_eq!(source["README.md"].contents, b"candidate");
    assert!(!source.contains_key("stale"));
}

#[tokio::test]
async fn source_commit_route_rejects_unsorted_duplicate_traversal_digest_mode_and_absent_delete() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = store
        .commit(&grant, "grid", None, files(&[("README.md", b"base")]))
        .unwrap();
    let api = LoomRpc::new(store).router();
    let mut mismatched_digest = upsert("README.md", SourceFileMode::Regular, b"candidate");
    if let SourceCommitMutation::Upsert { digest, .. } = &mut mismatched_digest {
        *digest = ArtifactDigest::sha256("a".repeat(64)).unwrap();
    }
    let invalid = vec![
        serde_json::to_value(SourceCommitRequest {
            schema_version: "v1".to_owned(),
            base: base.clone(),
            mutations: vec![
                upsert("b", SourceFileMode::Regular, b"b"),
                upsert("a", SourceFileMode::Regular, b"a"),
            ],
        })
        .unwrap(),
        serde_json::to_value(SourceCommitRequest {
            schema_version: "v1".to_owned(),
            base: base.clone(),
            mutations: vec![
                upsert("same", SourceFileMode::Regular, b"one"),
                SourceCommitMutation::Delete {
                    path: "same".to_owned(),
                },
            ],
        })
        .unwrap(),
        serde_json::to_value(SourceCommitRequest {
            schema_version: "v1".to_owned(),
            base: base.clone(),
            mutations: vec![upsert("../escape", SourceFileMode::Regular, b"no")],
        })
        .unwrap(),
        serde_json::to_value(SourceCommitRequest {
            schema_version: "v1".to_owned(),
            base: base.clone(),
            mutations: vec![upsert(
                "README.md/child",
                SourceFileMode::Regular,
                b"conflict",
            )],
        })
        .unwrap(),
        serde_json::json!({
            "schema_version": "v1",
            "base": base,
            "mutations": [{
                "operation": "upsert",
                "path": "invalid-base64",
                "mode": "regular",
                "digest": digest(b"tool"),
                "contents_base64": "***",
            }],
        }),
        serde_json::json!({
            "schema_version": "v1",
            "base": base,
            "mutations": [{
                "operation": "upsert",
                "path": "tool",
                "mode": "setuid",
                "digest": digest(b"tool"),
                "contents_base64": Base64::encode_string(b"tool"),
            }],
        }),
        serde_json::to_value(SourceCommitRequest {
            schema_version: "v1".to_owned(),
            base: base.clone(),
            mutations: vec![mismatched_digest],
        })
        .unwrap(),
    ];
    for request in invalid {
        assert_eq!(
            post_source_commit(&api, request).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let absent_delete = serde_json::to_value(SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base,
        mutations: vec![SourceCommitMutation::Delete {
            path: "absent".to_owned(),
        }],
    })
    .unwrap();
    assert_eq!(
        post_source_commit(&api, absent_delete).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn source_commit_client_rejects_a_response_not_bound_to_its_exact_request() {
    let base = RepositoryRevision::new("grid", "a".repeat(64)).unwrap();
    let request = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base: base.clone(),
        mutations: vec![upsert("README.md", SourceFileMode::Regular, b"candidate")],
    };
    let app = axum::Router::new().route(
        "/loom/v1/source/commit",
        axum::routing::post(move || async move {
            axum::Json(SourceCommitResult {
                schema_version: "v1".to_owned(),
                request_digest: ArtifactDigest::sha256("f".repeat(64)).unwrap(),
                base,
                head: RepositoryRevision::new("grid", "b".repeat(64)).unwrap(),
                mutation_count: 1,
            })
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    assert!(matches!(
        client.commit_source(&request).await,
        Err(loom::LoomRpcError::InvalidResponse)
    ));
}

#[tokio::test]
async fn source_commit_client_rejects_an_oversized_response_before_reading_its_body() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let base = RepositoryRevision::new("grid", "a".repeat(64)).unwrap();
    let request = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base,
        mutations: vec![upsert("README.md", SourceFileMode::Regular, b"candidate")],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_bytes = [0_u8; 4096];
        let _ = stream.read(&mut request_bytes).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 8193\r\nconnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let client = LoomRpcClient::new(&endpoint, reqwest::Client::new()).unwrap();

    let result = client.commit_source(&request).await;
    assert!(
        matches!(result, Err(loom::LoomRpcError::ResponseTooLarge)),
        "{result:?}"
    );
}
