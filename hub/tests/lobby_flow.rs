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

#[tokio::test]
async fn lobby_status_returns_member_when_no_min_level() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // min_security_level defaults to 0 → status should be "member"
    let resp = server
        .get("/lobby/status")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["status"], "member");
    assert_eq!(body["required_level"], 0);
    assert_eq!(body["current_level"], 0);
}

#[tokio::test]
async fn lobby_status_requires_auth() {
    let server = setup().await;
    let resp = server.get("/lobby/status").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn lobby_welcome_returns_hub_name() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .get("/lobby/welcome")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hub_name"], "test-hub");
    assert_eq!(body["required_level"], 0);
}

#[tokio::test]
async fn admin_can_update_lobby_settings() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Update welcome_md
    let resp = server
        .put("/hub/settings/lobby")
        .authorization_bearer(&token)
        .json(&json!({ "lobby_enabled": true, "welcome_md": "# Welcome!" }))
        .await;
    resp.assert_status_ok();

    // Welcome endpoint should reflect it
    let resp = server
        .get("/lobby/welcome")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["welcome_md"], "# Welcome!");
}

#[tokio::test]
async fn non_admin_cannot_update_lobby_settings() {
    let server = setup().await;
    // First user is owner
    let owner = Identity::generate();
    let _owner_token = authenticate(&server, &owner).await;

    // Second user is just @everyone
    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let resp = server
        .put("/hub/settings/lobby")
        .authorization_bearer(&user_token)
        .json(&json!({ "lobby_enabled": false }))
        .await;
    resp.assert_status_forbidden();
}

#[tokio::test]
async fn submit_pow_invalid_format_returns_bad_request() {
    let server = setup().await;
    let user = Identity::generate();
    let token = authenticate(&server, &user).await;

    let resp = server
        .post("/lobby/submit-pow")
        .authorization_bearer(&token)
        .json(&json!({ "pow_proof": "not-valid" }))
        .await;
    resp.assert_status_bad_request();
}

#[tokio::test]
async fn verify_response_includes_scope_field() {
    let server = setup().await;
    let user = Identity::generate();
    let pub_key = user.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = user.sign(&hex::decode(&challenge.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // With min_security_level = 0 and lobby_enabled = '1', scope should be "member"
    // because pow_level (0) >= min_level (0)
    assert!(body["scope"].is_string(), "scope field must be present");
    assert_eq!(body["scope"], "member");
}
