use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::me::MeResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup() -> TestServer {
    // In-memory SQLite for tests — no file created, fresh every time
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
                voice_addr_map: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),    });

    let app = server::create_router(state);
    TestServer::new(app)
}

#[tokio::test]
async fn full_auth_flow() {
    let server = setup().await;
    let identity = Identity::generate();
    let pub_key = identity.public_key_hex();

    // 1. Request challenge
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    resp.assert_status_ok();
    let challenge: ChallengeResponse = resp.json();

    // 2. Sign the challenge
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature.to_bytes());

    // 3. Verify (get token)
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": signature_hex,
        }))
        .await;
    resp.assert_status_ok();
    let verify: VerifyResponse = resp.json();
    assert!(!verify.token.is_empty());

    // 4. Use token to access /me
    let resp = server
        .get("/me")
        .authorization_bearer(&verify.token)
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, pub_key);
}

#[tokio::test]
async fn me_rejects_no_token() {
    let server = setup().await;
    let resp = server.get("/me").await;
    resp.assert_status_unauthorized();
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
async fn pending_members_are_blocked_until_approved() {
    let server = setup().await;

    // Owner signs up first — auto-approved since they're the hub creator.
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    // Owner turns on require_approval.
    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "require_approval": true }))
        .await
        .assert_status_ok();

    // New member joins — they get a token but start pending.
    let newbie = Identity::generate();
    let newbie_token = authenticate(&server, &newbie).await;

    // Can see their own status
    let resp = server
        .get("/me")
        .authorization_bearer(&newbie_token)
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.approval_status, "pending");

    // Cannot see channels or anything else
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner sees them in the pending queue
    let resp = server
        .get("/hub/pending")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pending: serde_json::Value = resp.json();
    assert_eq!(pending.as_array().unwrap().len(), 1);

    // Owner approves
    server
        .post(&format!("/hub/pending/{}/approve", newbie.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // Newbie can now access channels
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status_ok();
}
