//! Origin webhook (verify-only), Loom-keyed release/deploy, and mirror queue.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
use loom::catalog::{DeployTarget, RepoCatalog, RepoEntry};
use loom::ci::{CiStatus, execute_command, load_pipeline};
use loom::contracts::RepositoryRevision;
use loom::origin::{
    OriginConfig, OriginEngine, OriginMirrorRunner, OriginMirrorStatus, OriginRelease,
    test_verifying_key, test_webhook_signature,
};
use loom::server::{LoomApp, ServerConfig};
use loom::{NamespaceGrant, PersistentLoomStore};
use tower::ServiceExt as _;

const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OWNER: &str = "owner-token";
const DEPLOY: &str = "deploy-token";

fn unix_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

fn test_app(passed: bool, webhook_secret: Option<[u8; 32]>) -> (tempfile::TempDir, axum::Router) {
    let directory = tempfile::tempdir().unwrap();
    let mut origin = OriginConfig::for_test(directory.path().join("origin-work"), passed);
    if let Some(secret) = webhook_secret {
        origin.webhook_keys = vec![test_verifying_key(&secret)];
    }
    let root = directory.path().join("loom");
    let store = PersistentLoomStore::open(&root).unwrap();
    register_release_repos(&store);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root,
        token: AccessToken::new(OWNER),
        deploy_token: Some(AccessToken::new(DEPLOY)),
        origin,
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/usr/bin/true"),
    })
    .unwrap();
    (directory, app.router())
}

fn register_release_repos(store: &PersistentLoomStore) {
    let catalog = RepoCatalog::open(store.clone());
    catalog
        .upsert(RepoEntry {
            name: "loom".to_owned(),
            protected_ref: "refs/main".to_owned(),
            checkout_path: None,
            ci: loom::catalog::CiPolicy::LoomCi,
            deploy_target: DeployTarget::LocalApply {
                script: PathBuf::from("/usr/local/sbin/loom-apply"),
            },
            description: String::new(),
        })
        .unwrap();
    for name in ["grid", "nero"] {
        catalog
            .upsert(RepoEntry {
                name: name.to_owned(),
                protected_ref: "refs/main".to_owned(),
                checkout_path: None,
                ci: loom::catalog::CiPolicy::LoomCi,
                deploy_target: DeployTarget::SshApply {
                    host: None,
                    script: PathBuf::from("/usr/local/sbin/remote-apply"),
                },
                description: String::new(),
            })
            .unwrap();
    }
}

fn test_engine(mirror_ok: bool) -> (tempfile::TempDir, OriginEngine) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = OriginConfig::for_test(directory.path().join("work"), true);
    config.mirror_runner = OriginMirrorRunner::Fixed {
        ok: mirror_ok,
        log: if mirror_ok {
            "mirror.ok".to_owned()
        } else {
            "mirror.error".to_owned()
        },
    };
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let origin = OriginEngine::new(store.clone(), config);
    register_release_repos(&store);
    (directory, origin)
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

#[tokio::test]
async fn webhook_rejects_missing_and_invalid_signatures() {
    let secret = [7_u8; 32];
    let (_directory, router) = test_app(true, Some(secret));
    let body = br#"{"event":{"type":"pull_request.created"}}"#;
    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri("/v1/origin/webhook")
            .body(Body::from(body.as_slice()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri("/v1/origin/webhook")
            .header("webhook-id", "msg_1")
            .header("webhook-timestamp", unix_now())
            .header("webhook-signature", "v1ed,AAAA")
            .body(Body::from(body.as_slice()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_accepts_signed_payload_without_starting_ci() {
    let secret = [9_u8; 32];
    let (_directory, router) = test_app(true, Some(secret));
    let body = format!(
        r#"{{"event":{{"type":"pull_request.created","payload":{{"repository":{{"name":"loom"}},"pullRequest":{{"headSha":"{OID}"}}}}}}}}"#
    );
    let timestamp = unix_now();
    let signature = test_webhook_signature("msg_ok", &timestamp, body.as_bytes(), &secret);
    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri("/v1/origin/webhook")
            .header("webhook-id", "msg_ok")
            .header("webhook-timestamp", timestamp)
            .header("webhook-signature", signature)
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &router,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/releases/loom/{OID}"))
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Envelope and payload shapes exactly as Origin delivers them
/// (deliveryId/appId wrapper, camelCase `pullRequest.head.sha`).
#[test]
fn webhook_targets_parse_origin_pull_request_shape() {
    let (_directory, origin) = test_engine(true);
    let body = format!(
        r#"{{"deliveryId":"whd_1","appId":"app_1","installationId":"i_1","event":{{"id":"evt_1","type":"pull_request.created","payload":{{"pullRequest":{{"number":"1","head":{{"ref":"scratch/x","sha":"{OID}"}},"base":{{"ref":"main","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"version":{{"headSha":"{OID}"}}}},"repository":{{"name":"loom","owner":{{"slug":"grogan-dev"}}}}}}}}}}"#
    );
    let targets = origin.targets_from_webhook(body.as_bytes());
    assert_eq!(targets, vec![("loom".to_owned(), OID.to_owned())]);
}

/// Origin push events carry a `refUpdates` array, not top-level `ref`/`after`.
/// Only updates to `main` are parsed; branch pushes and deletions are ignored.
#[test]
fn webhook_targets_parse_origin_ref_updates_shape() {
    let (_directory, origin) = test_engine(true);
    let body = format!(
        r#"{{"deliveryId":"whd_2","appId":"app_1","installationId":"i_1","event":{{"id":"evt_2","type":"repository.pushed","payload":{{"repository":{{"name":"loom","owner":{{"slug":"grogan-dev"}}}},"refUpdates":[{{"ref":"refs/heads/scratch/x","before":"0000000000000000000000000000000000000000","after":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","created":true,"deleted":false}},{{"ref":"refs/heads/main","before":"cccccccccccccccccccccccccccccccccccccccc","after":"{OID}","created":false,"deleted":false}},{{"ref":"refs/heads/gone","after":"dddddddddddddddddddddddddddddddddddddddd","deleted":true}}]}}}}}}"#
    );
    let targets = origin.targets_from_webhook(body.as_bytes());
    assert_eq!(targets, vec![("loom".to_owned(), OID.to_owned())]);
}

/// Webhook targets for repositories outside the catalog are dropped.
#[test]
fn webhook_targets_drop_unregistered_repositories() {
    let (_directory, origin) = test_engine(true);
    let body = format!(
        r#"{{"event":{{"type":"pull_request.created","payload":{{"repository":{{"name":"secret"}},"pullRequest":{{"headSha":"{OID}"}}}}}}}}"#
    );
    assert!(origin.targets_from_webhook(body.as_bytes()).is_empty());
}

#[tokio::test]
async fn deploy_is_rejected_without_passing_evidence_and_without_deploy_token() {
    let (_directory, router) = test_app(false, None);
    let (status, body) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/releases/loom/{OID}/deploy"))
            .header("authorization", format!("Bearer {DEPLOY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "origin.deploy_blocked");

    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/releases/loom/{OID}/deploy"))
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Writes the durable oid↔revision mapping exactly as the Git import does.
fn write_git_mapping(
    store_root: &Path,
    repository: &str,
    oid: &str,
    revision: &RepositoryRevision,
) {
    let directory = store_root
        .join("git-mappings")
        .join(loom::repository_storage_name(repository));
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mapping = serde_json::json!({
        "schema_version": "v1",
        "repository": repository,
        "git_oid": oid,
        "revision": { "repository": repository, "revision": revision.revision },
    });
    let path = directory.join(format!("{oid}.json"));
    fs::write(&path, serde_json::to_vec(&mapping).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn loom_release_record_allows_deploy_token_to_apply() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let store = PersistentLoomStore::open(&root).unwrap();
    register_release_repos(&store);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root: root.clone(),
        token: AccessToken::new(OWNER),
        deploy_token: Some(AccessToken::new(DEPLOY)),
        origin: OriginConfig::for_test(directory.path().join("origin-work"), true),
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/usr/bin/true"),
    })
    .unwrap();
    let router = app.router();

    // The CI route no longer fabricates passing evidence: a SHA Loom never
    // imported has no execution context, is refused, and records nothing.
    let (status, body) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri("/v1/releases/loom/ci")
            .header("authorization", format!("Bearer {OWNER}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"git_oid":"{OID}"}}"#)))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "origin.revision_unknown");
    let (status, _) = send(
        &router,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/releases/loom/{OID}"))
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Candidate acceptance records evidence through record_loom_release; the
    // deploy token can then apply that exact SHA.
    let engine = OriginEngine::new(
        PersistentLoomStore::open(&root).unwrap(),
        OriginConfig::for_test(directory.path().join("origin-work"), true),
    );
    engine.record_loom_release("loom", OID, true).unwrap();

    let (status, body) = send(
        &router,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/releases/loom/{OID}"))
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tests_passed"], true);
    assert!(!body["job_id"].as_str().unwrap().is_empty());

    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/releases/loom/{OID}/deploy"))
            .header("authorization", format!("Bearer {DEPLOY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn ci_route_executes_pipeline_and_records_honest_results() {
    const FAIL_OID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PASS_OID: &str = "cccccccccccccccccccccccccccccccccccccccc";
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let store = PersistentLoomStore::open(&root).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["loom".to_owned()]));
    let failing = store
        .commit(
            &grant,
            "loom",
            None,
            BTreeMap::from([(
                "loom-ci.toml".to_owned(),
                b"[ci]\ncommands = [[\"sh\", \"-c\", \"echo boom; exit 1\"]]\n".to_vec(),
            )]),
        )
        .unwrap();
    let passing = store
        .commit(
            &grant,
            "loom",
            Some(&failing),
            BTreeMap::from([(
                "loom-ci.toml".to_owned(),
                b"[ci]\ncommands = [[\"sh\", \"-c\", \"echo real-ci-ok\"]]\n".to_vec(),
            )]),
        )
        .unwrap();
    write_git_mapping(&root, "loom", FAIL_OID, &failing);
    write_git_mapping(&root, "loom", PASS_OID, &passing);
    register_release_repos(&store);
    let app = LoomApp::new(ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        root,
        token: AccessToken::new(OWNER),
        deploy_token: Some(AccessToken::new(DEPLOY)),
        origin: OriginConfig::for_test(directory.path().join("origin-work"), true),
        git_program: PathBuf::from("/usr/bin/git"),
        hook_program: PathBuf::from("/usr/bin/true"),
    })
    .unwrap();
    let router = app.router();

    let run_ci = |oid: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/releases/loom/ci")
            .header("authorization", format!("Bearer {OWNER}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"git_oid":"{oid}"}}"#)))
            .unwrap()
    };

    // The failing pipeline records failed evidence which blocks deploy.
    let (status, body) = send(&router, run_ci(FAIL_OID)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tests_passed"], false);
    assert_eq!(body["status"], "failed");
    assert!(body["log"].as_str().unwrap().contains("boom"));
    let (status, body) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/releases/loom/{FAIL_OID}/deploy"))
            .header("authorization", format!("Bearer {DEPLOY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "origin.deploy_blocked");

    // The passing pipeline records real passing evidence which allows deploy.
    let (status, body) = send(&router, run_ci(PASS_OID)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tests_passed"], true);
    assert_eq!(body["status"], "passed");
    assert!(body["log"].as_str().unwrap().contains("real-ci-ok"));
    let (status, _) = send(
        &router,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/releases/loom/{PASS_OID}/deploy"))
            .header("authorization", format!("Bearer {DEPLOY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The successful apply left exactly one durable deploy.applied event;
    // the blocked deploy for the failing SHA left none.
    let (status, page) = send(
        &router,
        Request::builder()
            .method("GET")
            .uri("/v1/events")
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let applied = page["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "deploy.applied")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(applied.len(), 1, "{page}");
    assert_eq!(applied[0]["repos"][0], "loom");
    assert_eq!(applied[0]["payload"]["git_oid"], PASS_OID);
    assert_eq!(applied[0]["payload"]["deploy_target"], "local_apply");
}

#[test]
fn record_loom_release_is_accept_equivalent_for_deploy() {
    let (_directory, origin) = test_engine(true);
    origin.record_loom_release("loom", OID, true).unwrap();
    let release = origin.release("loom", OID).unwrap().unwrap();
    assert!(release.tests_passed);
    assert_eq!(release.status, CiStatus::Passed);
    let deployed = origin.deploy("loom", OID).unwrap();
    assert_eq!(deployed.deployed_oid.as_deref(), Some(OID));
}

#[test]
fn sha_keyed_release_lookup_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let origin = OriginEngine::new(
        store.clone(),
        OriginConfig::for_test(directory.path().join("work"), false),
    );
    register_release_repos(&store);
    origin
        .put_release(OriginRelease {
            repository: "grid".to_owned(),
            git_oid: OID.to_owned(),
            job_id: "job-1".to_owned(),
            status: CiStatus::Failed,
            tests_passed: false,
            log: "failed".to_owned(),
            origin_check_id: None,
            deployed_oid: None,
        })
        .unwrap();
    let found = origin.release("grid", OID).unwrap().unwrap();
    assert_eq!(found.job_id, "job-1");
    assert!(!found.tests_passed);
    assert!(
        origin
            .release("grid", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap()
            .is_none()
    );
}

#[test]
fn queue_mirror_fixed_runner_records_ok_without_network() {
    let (_directory, origin) = test_engine(true);
    let job = origin.queue_mirror("nero", Some(OID)).unwrap();
    assert_eq!(job.status, OriginMirrorStatus::Ok);
    assert_eq!(job.git_oid.as_deref(), Some(OID));
    assert_eq!(job.log, "mirror.ok");
    let listed = origin.mirrors().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, job.id);
}

#[test]
fn queue_mirror_fixed_runner_records_error_without_network() {
    let (_directory, origin) = test_engine(false);
    let job = origin.queue_mirror("grid", Some(OID)).unwrap();
    assert_eq!(job.status, OriginMirrorStatus::Error);
    assert_eq!(job.log, "mirror.error");
}

#[test]
fn queue_mirror_without_git_mapping_records_error() {
    let (_directory, origin) = test_engine(true);
    let job = origin.queue_mirror("loom", None).unwrap();
    assert_eq!(job.status, OriginMirrorStatus::Error);
    assert_eq!(job.log, "no git mapping");
    assert!(job.git_oid.is_none());
}

#[test]
fn unknown_repo_is_denied_for_release_and_mirror() {
    let (_directory, origin) = test_engine(true);
    let denied = origin.record_loom_release("secret", OID, true).unwrap_err();
    assert!(matches!(
        denied,
        loom::LoomError::OriginRepositoryDenied { repository } if repository == "secret"
    ));
    let denied = origin.queue_mirror("secret", Some(OID)).unwrap_err();
    assert!(matches!(
        denied,
        loom::LoomError::OriginRepositoryDenied { repository } if repository == "secret"
    ));
}

#[test]
fn loom_ci_toml_parse_and_command_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let parsed = directory.path().join("parsed");
    std::fs::create_dir_all(&parsed).unwrap();
    std::fs::write(
        parsed.join("loom-ci.toml"),
        "[ci]\ntimeout_seconds = 42\ncommands = [[\"true\"]]\n",
    )
    .unwrap();
    let (commands, timeout) = load_pipeline(&parsed);
    assert_eq!(commands, vec![vec!["true".to_owned()]]);
    assert_eq!(timeout, Duration::from_secs(42));

    let timed = directory.path().join("timed");
    std::fs::create_dir_all(&timed).unwrap();
    std::fs::write(
        timed.join("loom-ci.toml"),
        "[ci]\ntimeout_seconds = 1\ncommands = [[\"sleep\", \"5\"]]\n",
    )
    .unwrap();
    let (commands, timeout) = load_pipeline(&timed);
    assert_eq!(timeout, Duration::from_secs(1));
    let (ok, log) = execute_command(&timed, &commands[0], timeout).unwrap();
    assert!(!ok);
    assert_eq!(log, "ci.timeout");
}
