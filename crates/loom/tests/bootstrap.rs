//! Owner-only protected-ref bootstrap: idempotent, audited, and fail-closed.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::contracts::RepositoryRevision;
use loom::origin::OriginConfig;
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};
use tower::ServiceExt as _;

const OWNER: &str = "owner-token";
const GIT_OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _directory: tempfile::TempDir,
    router: axum::Router,
    store: PersistentLoomStore,
    root: PathBuf,
    grant: NamespaceGrant,
    base: RepositoryRevision,
    head: RepositoryRevision,
}

fn fixture() -> Fixture {
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
            BTreeMap::from([("README.md".to_owned(), b"head\n".to_vec())]),
        )
        .unwrap();
    let origin = OriginConfig::for_test(directory.path().join("origin-work"), true);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root: root.clone(),
        token: AccessToken::new(OWNER),
        deploy_token: None,
        origin,
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/usr/bin/true"),
    })
    .unwrap();
    Fixture {
        _directory: directory,
        router: app.router(),
        store,
        root,
        grant,
        base,
        head,
    }
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

async fn register_repo(router: &axum::Router, name: &str) {
    let (status, _) = send(
        router,
        json_request(
            "POST",
            "/v1/repos",
            OWNER,
            serde_json::json!({ "name": name }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

async fn bootstrap(
    router: &axum::Router,
    bearer: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        router,
        json_request("POST", "/loom/v1/refs/bootstrap", bearer, body),
    )
    .await
}

/// Writes the durable oid↔revision mapping exactly as the Git import does.
fn write_git_mapping(store_root: &std::path::Path, revision: &RepositoryRevision) {
    let directory = store_root.join("git-mappings").join("demo");
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join(format!("{GIT_OID}.json"));
    let mapping = serde_json::json!({
        "schema_version": "v1",
        "repository": "demo",
        "git_oid": GIT_OID,
        "revision": { "repository": "demo", "revision": revision.revision },
    });
    fs::write(&path, serde_json::to_vec(&mapping).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn bootstrap_creates_reads_back_and_is_idempotent() {
    let fixture = fixture();
    register_repo(&fixture.router, "demo").await;

    let body = serde_json::json!({ "repo": "demo", "revision": fixture.base.revision });
    let (status, created) = bootstrap(&fixture.router, OWNER, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["repo"], "demo");
    assert_eq!(created["ref_name"], "refs/main");
    assert_eq!(created["revision"], fixture.base.revision);
    assert_eq!(created["created"], true);
    assert_eq!(created["read_back"], true);

    // The protected ref really exists at exactly that revision.
    assert_eq!(
        fixture
            .store
            .resolve_ref(&fixture.grant, "demo", "refs/main")
            .unwrap(),
        fixture.base
    );

    // Replaying the same request is a 200 without a second audit event.
    let (status, replay) = bootstrap(&fixture.router, OWNER, body).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["created"], false);
    assert_eq!(replay["read_back"], true);

    // A different revision cannot silently move the protected ref.
    let conflict = serde_json::json!({ "repo": "demo", "revision": fixture.head.revision });
    let (status, denied) = bootstrap(&fixture.router, OWNER, conflict).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(denied["code"], "loom.ref_conflict");
    assert_eq!(
        fixture
            .store
            .resolve_ref(&fixture.grant, "demo", "refs/main")
            .unwrap(),
        fixture.base
    );

    // Exactly one durable refs.bootstrapped audit event exists.
    let (status, page) = send(
        &fixture.router,
        json_request("GET", "/v1/events", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bootstrapped = page["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "refs.bootstrapped")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(bootstrapped.len(), 1, "{page}");
    assert_eq!(bootstrapped[0]["repos"][0], "demo");
    assert_eq!(bootstrapped[0]["payload"]["ref_name"], "refs/main");
    assert_eq!(
        bootstrapped[0]["payload"]["revision"],
        fixture.base.revision
    );
    assert_eq!(bootstrapped[0]["payload"]["source"], "revision");
}

#[tokio::test]
async fn bootstrap_from_git_oid_uses_the_durable_mapping() {
    let fixture = fixture();
    register_repo(&fixture.router, "demo").await;

    // Unknown OIDs are refused before any ref is touched.
    let (status, body) = bootstrap(
        &fixture.router,
        OWNER,
        serde_json::json!({ "repo": "demo", "git_oid": GIT_OID }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "revision.unknown");

    write_git_mapping(&fixture.root, &fixture.base);
    let (status, created) = bootstrap(
        &fixture.router,
        OWNER,
        serde_json::json!({ "repo": "demo", "git_oid": GIT_OID }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["revision"], fixture.base.revision);
    assert_eq!(created["git_oid"], GIT_OID);
    assert_eq!(
        fixture
            .store
            .resolve_ref(&fixture.grant, "demo", "refs/main")
            .unwrap(),
        fixture.base
    );
}

#[tokio::test]
async fn bootstrap_refuses_unknown_repos_revisions_and_bad_shapes() {
    let fixture = fixture();
    register_repo(&fixture.router, "demo").await;

    // Unregistered repository: 404 before revision checks.
    let (status, body) = bootstrap(
        &fixture.router,
        OWNER,
        serde_json::json!({ "repo": "ghost", "revision": fixture.base.revision }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "repo.unknown");

    // Registered repository, unknown snapshot revision: 404.
    let (status, body) = bootstrap(
        &fixture.router,
        OWNER,
        serde_json::json!({ "repo": "demo", "revision": "f".repeat(64) }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "revision.unknown");

    // Exactly one of revision/git_oid is required.
    for body in [
        serde_json::json!({ "repo": "demo" }),
        serde_json::json!({
            "repo": "demo",
            "revision": fixture.base.revision,
            "git_oid": GIT_OID,
        }),
        serde_json::json!({ "repo": "demo", "revision": "not-hex" }),
    ] {
        let (status, _) = bootstrap(&fixture.router, OWNER, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Nothing was created by any refusal.
    assert!(
        fixture
            .store
            .resolve_ref(&fixture.grant, "demo", "refs/main")
            .is_err()
    );
}

#[tokio::test]
async fn bootstrap_is_owner_only_even_for_fully_scoped_tokens() {
    let fixture = fixture();
    register_repo(&fixture.router, "demo").await;

    let (status, minted) = send(
        &fixture.router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "ws-full",
                "repositories": ["demo"],
                "perms": ["git", "features", "evidence", "review", "events"],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = minted["secret"].as_str().unwrap();

    let body = serde_json::json!({ "repo": "demo", "revision": fixture.base.revision });
    let (status, denied) = bootstrap(&fixture.router, secret, body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(denied["code"], "loom.unauthorized");
    let (status, _) = bootstrap(&fixture.router, "wrong-token", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // No ref was created and no audit event was emitted.
    assert!(
        fixture
            .store
            .resolve_ref(&fixture.grant, "demo", "refs/main")
            .is_err()
    );
    let (status, page) = send(
        &fixture.router,
        json_request("GET", "/v1/events", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["kind"] != "refs.bootstrapped")
    );
}
