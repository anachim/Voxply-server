use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup(startup_name: &str) -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: startup_name.to_string(),
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
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),    });
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

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

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

/// Regression test for the lazy hub_name read. Before the fix, alliance code
/// embedded the startup-time AppState.hub_name into alliance member rows.
/// After the admin renamed the hub, new alliances would still show the old
/// name. This verifies that creating an alliance after a rename uses the new
/// name from hub_settings.
#[tokio::test]
async fn alliance_member_row_uses_renamed_hub_name() {
    let server = setup("Original Name").await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Admin renames the hub via the same /hub PATCH the admin UI uses.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Renamed Hub" }))
        .await
        .assert_status_ok();

    // Create an alliance after the rename.
    server
        .post("/alliances")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Test Alliance" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Pull alliance list and verify the member row shows the renamed name,
    // not the startup name.
    let resp = server
        .get("/alliances")
        .authorization_bearer(&token)
        .await;
    let alliances = resp.json::<serde_json::Value>();
    let arr = alliances.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let alliance_id = arr[0]["id"].as_str().unwrap();

    let resp = server
        .get(&format!("/alliances/{alliance_id}"))
        .authorization_bearer(&token)
        .await;
    let detail = resp.json::<serde_json::Value>();
    let members = detail["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0]["hub_name"], "Renamed Hub",
        "alliance member row should reflect the renamed hub, not the startup name"
    );
}

/// Companion: when no rename has happened, the startup name is still used as
/// the fallback. Confirms current_hub_name's fallback path.
#[tokio::test]
async fn alliance_member_row_falls_back_to_startup_name() {
    let server = setup("Original Name").await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    server
        .post("/alliances")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Test Alliance" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get("/alliances")
        .authorization_bearer(&token)
        .await;
    let arr = resp.json::<serde_json::Value>();
    let alliance_id = arr.as_array().unwrap()[0]["id"].as_str().unwrap();

    let resp = server
        .get(&format!("/alliances/{alliance_id}"))
        .authorization_bearer(&token)
        .await;
    let detail = resp.json::<serde_json::Value>();
    let members = detail["members"].as_array().unwrap();
    assert_eq!(members[0]["hub_name"], "Original Name");
}
