//! Scoped tokens: owner mints, scopes bind repos and perms, revocation is
//! immediate, and the git gateway accepts Bearer or Basic credentials.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64ct::{Base64, Encoding as _};
use http_body_util::BodyExt as _;
use loom::auth::AccessToken;
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
    assert!(secret.starts_with("lt_"));
    assert!(body["token"]["secret_sha256"].as_str().unwrap() != secret);
    (id, secret)
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

#[tokio::test]
async fn token_mint_requires_owner_and_validates() {
    let (_directory, router) = test_app();
    let body = serde_json::json!({
        "name": "ws-1", "repositories": ["demo"], "perms": ["git"],
    });
    let (status, _) = send(
        &router,
        json_request("POST", "/v1/tokens", "wrong", body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({ "name": "", "repositories": ["demo"], "perms": ["git"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({ "name": "ws-1", "repositories": [], "perms": ["git"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "ws-1", "repositories": ["demo"], "perms": ["git"], "expires_at": 1,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "bad-bound-review",
                "repositories": ["demo"],
                "perms": ["review"],
                "feature_id": "feature-without-review",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn scoped_token_gates_features_by_repository() {
    let (_directory, router) = test_app();
    register_repo(&router, "demo").await;
    register_repo(&router, "other").await;
    let (_id, secret) = mint(&router, "ws-demo", &["demo"], &["features"]).await;

    let (status, created) = send(
        &router,
        json_request("POST", "/v1/features", &secret, feature_create_body("demo")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let feature_id = created["id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        &router,
        json_request(
            "POST",
            "/v1/features",
            &secret,
            feature_create_body("other"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Owner-created feature on another repo is invisible and unreadable.
    let (status, other) = send(
        &router,
        json_request("POST", "/v1/features", OWNER, feature_create_body("other")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let other_id = other["id"].as_str().unwrap();
    let (status, _) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/features/{other_id}"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, listed) = send(
        &router,
        json_request("GET", "/v1/features", &secret, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"].as_str().unwrap(), feature_id);

    // Gate transitions stay owner-only.
    let (status, _) = send(
        &router,
        json_request(
            "POST",
            &format!("/v1/features/{feature_id}/approve"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scoped_token_gates_evidence_and_missing_perm_is_forbidden() {
    let (_directory, router) = test_app();
    register_repo(&router, "grid").await;
    register_repo(&router, "loom").await;
    let (_id, secret) = mint(&router, "runner", &["grid"], &["evidence"]).await;

    // In-scope: auth passes, release is simply absent.
    let (status, body) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/releases/grid/{REVISION}"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"].as_str().unwrap(), "origin.release_missing");

    // Out-of-scope repo is forbidden before any lookup.
    let (status, body) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/releases/loom/{REVISION}"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"].as_str().unwrap(), "loom.forbidden");

    // Evidence-only tokens cannot touch features.
    let (status, _) = send(
        &router,
        json_request("POST", "/v1/features", &secret, feature_create_body("grid")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn git_gateway_accepts_scoped_bearer_and_basic_within_scope() {
    let (_directory, router) = test_app();
    register_repo(&router, "demo").await;
    let (_id, secret) = mint(&router, "ws-git", &["demo"], &["git"]).await;

    let challenge = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/git/demo.git/info/refs?service=git-upload-pack")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"loom\"")
    );

    let bearer = Request::builder()
        .method("GET")
        .uri("/git/demo.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, bearer).await;
    assert_eq!(status, StatusCode::OK);

    let credentials = Base64::encode_string(format!("x-token:{secret}").as_bytes());
    let basic = Request::builder()
        .method("GET")
        .uri("/git/demo.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Basic {credentials}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, basic).await;
    assert_eq!(status, StatusCode::OK);

    let out_of_scope = Request::builder()
        .method("GET")
        .uri("/git/other.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, out_of_scope).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Tokens without the git perm never reach the backend.
    let (_id, feature_only) = mint(&router, "ws-nogit", &["demo"], &["features"]).await;
    let denied = Request::builder()
        .method("GET")
        .uri("/git/demo.git/info/refs?service=git-upload-pack")
        .header("authorization", format!("Bearer {feature_only}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&router, denied).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_lookup_by_id_reconciles_without_secrets() {
    let (_directory, router) = test_app();
    let expiry = 4_102_444_800_u64; // 2100-01-01, far future
    let (status, minted) = send(
        &router,
        json_request(
            "POST",
            "/v1/tokens",
            OWNER,
            serde_json::json!({
                "name": "review-agent",
                "repositories": ["demo"],
                "perms": ["review", "features"],
                "feature_id": "feat-1",
                "review_id": "rev-1",
                "expires_at": expiry,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = minted["token"]["id"].as_str().unwrap().to_owned();
    let secret = minted["secret"].as_str().unwrap().to_owned();

    // The owner can verify every reconciliation field by id.
    let (status, body) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/tokens/{id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["name"], "review-agent");
    assert_eq!(body["repositories"], serde_json::json!(["demo"]));
    assert_eq!(body["perms"], serde_json::json!(["features", "review"]));
    assert_eq!(body["feature_id"], "feat-1");
    assert_eq!(body["review_id"], "rev-1");
    assert_eq!(body["expires_at"], expiry);
    assert!(body.get("revoked_at").is_none());
    // The bearer secret never appears anywhere in the response.
    assert!(!body.to_string().contains(&secret));
    assert_eq!(body["secret_sha256"].as_str().unwrap().len(), 64);

    // Only the owner may read the reconciliation record.
    let (status, _) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/tokens/{id}"),
            &secret,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown ids are distinguishable from revoked tokens.
    let (status, body) = send(
        &router,
        json_request(
            "GET",
            "/v1/tokens/no-such-token",
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "token.not_found");

    // After revocation the record still reads back, now with revoked_at set.
    let (status, _) = send(
        &router,
        json_request(
            "DELETE",
            &format!("/v1/tokens/{id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &router,
        json_request(
            "GET",
            &format!("/v1/tokens/{id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["revoked_at"].as_u64().unwrap() > 0);
    assert!(!body.to_string().contains(&secret));
}

#[tokio::test]
async fn revoked_tokens_stop_resolving_immediately() {
    let (_directory, router) = test_app();
    let (id, secret) = mint(&router, "ws-revoke", &["demo"], &["features"]).await;

    let (status, listed) = send(
        &router,
        json_request("GET", "/v1/tokens", OWNER, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let (status, _) = send(
        &router,
        json_request(
            "DELETE",
            &format!("/v1/tokens/{id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(
        &router,
        json_request("GET", "/v1/features", &secret, serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &router,
        json_request(
            "DELETE",
            &format!("/v1/tokens/{id}"),
            OWNER,
            serde_json::Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
