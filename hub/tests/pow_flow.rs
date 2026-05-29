use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::{compute_security_level, Identity};

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    });
    let app = server::create_router(state);
    TestServer::new(app)
}

async fn do_auth_with_pow(
    server: &TestServer,
    identity: &Identity,
    pow_nonce: Option<u64>,
    pow_level: Option<u8>,
) -> axum_test::TestResponse {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });

    if let (Some(nonce), Some(level)) = (pow_nonce, pow_level) {
        body["pow_proof"] = json!({
            "level": level,
            "nonce": nonce.to_string(),
        });
    }

    server.post("/auth/verify").json(&body).await
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let resp = do_auth_with_pow(server, identity, None, None).await;
    resp.assert_status_ok();
    resp.json::<VerifyResponse>().token
}

// ---- /admin/settings/pow ----

#[tokio::test]
async fn get_pow_settings_defaults_to_zero() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/settings/pow")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 0);
}

#[tokio::test]
async fn patch_and_get_pow_settings() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 5 }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/settings/pow")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 5);
}

#[tokio::test]
async fn pow_settings_routes_reject_non_admin() {
    let server = setup().await;
    // First user becomes owner
    let owner = Identity::generate();
    let _owner_token = authenticate(&server, &owner).await;

    // Second user is plain member
    let member = Identity::generate();
    let member_token = authenticate(&server, &member).await;

    server
        .get("/admin/settings/pow")
        .authorization_bearer(&member_token)
        .await
        .assert_status_forbidden();

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&member_token)
        .json(&json!({ "min_pow_level": 3 }))
        .await
        .assert_status_forbidden();
}

// ---- /info includes min_pow_level ----

#[tokio::test]
async fn info_includes_min_pow_level() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Default: 0
    let resp = server.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 0, "info must include min_pow_level");

    // After raising it
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 4 }))
        .await
        .assert_status_ok();

    let resp = server.get("/info").await;
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 4);
}

// ---- Auth enforcement ----

#[tokio::test]
async fn auth_succeeds_without_pow_when_min_is_zero() {
    let server = setup().await;
    let user = Identity::generate();
    // min_pow_level defaults to 0 — no proof needed
    let resp = do_auth_with_pow(&server, &user, None, None).await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn auth_rejected_when_pow_missing_and_min_level_set() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Raise the minimum
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 4 }))
        .await
        .assert_status_ok();

    // New user tries to auth without pow_proof
    let newcomer = Identity::generate();
    let resp = do_auth_with_pow(&server, &newcomer, None, None).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}

#[tokio::test]
async fn auth_rejected_when_pow_level_below_minimum() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 8 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let pub_key = newcomer.public_key_hex();

    // Compute a nonce that satisfies level 4 (below the minimum of 8)
    let (nonce, level) = compute_security_level(&pub_key, 0, 4);
    assert!(level >= 4);

    // Submit with the low level — must be rejected
    let resp = do_auth_with_pow(&server, &newcomer, Some(nonce), Some(level as u8)).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}

#[tokio::test]
async fn auth_succeeds_with_valid_pow_proof() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Use a very low level so the test runs fast
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 1 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let pub_key = newcomer.public_key_hex();
    let (nonce, level) = compute_security_level(&pub_key, 0, 1);
    assert!(level >= 1);

    let resp = do_auth_with_pow(&server, &newcomer, Some(nonce), Some(level as u8)).await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn auth_rejected_with_fake_nonce() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 1 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();

    // Claim level 5 with a clearly bogus nonce (nonce=0 will not achieve level 5
    // for an arbitrary key — astronomically unlikely).
    let resp = do_auth_with_pow(&server, &newcomer, Some(0), Some(5)).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}
