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
use voxply_identity::Identity;

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let (chat_tx, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
    });
    let app = server::create_router(state);
    TestServer::new(app)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

async fn admin_set_challenge_mode(server: &TestServer, token: &str, mode: &str) {
    server
        .put("/hub/settings/challenge")
        .authorization_bearer(token)
        .json(&json!({ "challenge_mode": mode, "challenge_difficulty": "easy" }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn challenge_new_returns_404_when_off() {
    let server = setup().await;
    let identity = Identity::generate();

    // challenge_mode defaults to 'off' — /challenge/new should 404
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", identity.public_key_hex())
        .await;
    resp.assert_status_not_found();
}

#[tokio::test]
async fn click_challenge_happy_path() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;
    admin_set_challenge_mode(&server, &owner_token, "click").await;

    let pubkey = owner.public_key_hex();

    // Get a click challenge
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", &pubkey)
        .await;
    resp.assert_status_ok();
    let challenge: Value = resp.json();
    assert_eq!(challenge["mode"], "click");
    assert!(challenge["prompt_svg"].is_null());
    let id = challenge["id"].as_str().unwrap().to_string();

    // Verify click challenge (no answer needed)
    let resp = server
        .post("/challenge/verify")
        .json(&json!({ "id": id, "pubkey": pubkey }))
        .await;
    resp.assert_status_ok();
    let result: Value = resp.json();
    assert_eq!(result["ok"], true);
    assert!(result["token"].is_string());
    assert!(result["expires_at"].is_number());
}

#[tokio::test]
async fn click_challenge_cannot_be_consumed_twice() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;
    admin_set_challenge_mode(&server, &owner_token, "click").await;

    let pubkey = owner.public_key_hex();
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", &pubkey)
        .await;
    let challenge: Value = resp.json();
    let id = challenge["id"].as_str().unwrap().to_string();

    // First verify succeeds
    server
        .post("/challenge/verify")
        .json(&json!({ "id": id, "pubkey": pubkey }))
        .await
        .assert_status_ok();

    // Second verify fails (already consumed)
    let resp = server
        .post("/challenge/verify")
        .json(&json!({ "id": id, "pubkey": pubkey }))
        .await;
    // should be 410 Gone
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn puzzle_challenge_happy_path() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;
    admin_set_challenge_mode(&server, &owner_token, "puzzle").await;

    let pubkey = owner.public_key_hex();

    // Get a puzzle challenge
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", &pubkey)
        .await;
    resp.assert_status_ok();
    let challenge: Value = resp.json();
    assert_eq!(challenge["mode"], "puzzle");
    assert!(challenge["prompt_svg"].is_string(), "puzzle must have an SVG");

    let id = challenge["id"].as_str().unwrap().to_string();

    // Wrong answer returns ok:false
    let resp = server
        .post("/challenge/verify")
        .json(&json!({ "id": id, "pubkey": pubkey, "answer": "9999" }))
        .await;
    resp.assert_status_ok();
    let result: Value = resp.json();
    assert_eq!(result["ok"], false);
    assert!(result["attempts_remaining"].is_number());
}

#[tokio::test]
async fn challenge_pubkey_mismatch_rejected() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;
    admin_set_challenge_mode(&server, &owner_token, "click").await;

    let attacker = Identity::generate();
    let victim = Identity::generate();

    // Get challenge for victim's pubkey
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", victim.public_key_hex())
        .await;
    let challenge: Value = resp.json();
    let id = challenge["id"].as_str().unwrap().to_string();

    // Try to verify with attacker's pubkey — should be rejected
    let resp = server
        .post("/challenge/verify")
        .json(&json!({ "id": id, "pubkey": attacker.public_key_hex() }))
        .await;
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn admin_can_update_challenge_settings() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let resp = server
        .put("/hub/settings/challenge")
        .authorization_bearer(&owner_token)
        .json(&json!({ "challenge_mode": "puzzle", "challenge_difficulty": "medium" }))
        .await;
    resp.assert_status_ok();

    // Info endpoint should reflect challenge_mode
    let info: Value = server.get("/info").await.json();
    assert_eq!(info["challenge_mode"], "puzzle");
}

#[tokio::test]
async fn non_admin_cannot_update_challenge_settings() {
    let server = setup().await;
    // First user becomes owner
    let owner = Identity::generate();
    let _owner_token = authenticate(&server, &owner).await;
    // Second user is just @everyone
    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let resp = server
        .put("/hub/settings/challenge")
        .authorization_bearer(&user_token)
        .json(&json!({ "challenge_mode": "click", "challenge_difficulty": "easy" }))
        .await;
    resp.assert_status_forbidden();
}

#[tokio::test]
async fn info_includes_challenge_mode() {
    let server = setup().await;
    let info: Value = server.get("/info").await.json();
    // Default is "off"
    assert_eq!(info["challenge_mode"], "off");
}

#[tokio::test]
async fn auth_verify_requires_challenge_token_when_mode_is_not_off() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    // Enable click challenges
    admin_set_challenge_mode(&server, &owner_token, "click").await;

    // Try to auth without a challenge token — should fail
    let new_user = Identity::generate();
    let pub_key = new_user.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = new_user.sign(&hex::decode(&challenge.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            // no challenge_token
        }))
        .await;
    resp.assert_status_forbidden();
}

#[tokio::test]
async fn auth_verify_succeeds_with_valid_challenge_token() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    // Enable click challenges
    admin_set_challenge_mode(&server, &owner_token, "click").await;

    let new_user = Identity::generate();
    let pub_key = new_user.public_key_hex();

    // Get challenge token via click flow
    let resp = server
        .get("/challenge/new")
        .add_query_param("pubkey", &pub_key)
        .await;
    let ch: Value = resp.json();
    let ch_id = ch["id"].as_str().unwrap().to_string();

    let resp = server
        .post("/challenge/verify")
        .json(&json!({ "id": ch_id, "pubkey": pub_key }))
        .await;
    let ct: Value = resp.json();
    let challenge_token = ct["token"].as_str().unwrap().to_string();

    // Now authenticate with the challenge token
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = new_user.sign(&hex::decode(&challenge.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            "challenge_token": challenge_token,
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["token"].is_string());
}
