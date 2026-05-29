//! Integration tests for Tier 2 game session routes.

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

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

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
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        active_game_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
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

/// Install a minimal game and return its id.
async fn install_game(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/admin/games")
        .authorization_bearer(token)
        .json(&json!({
            "name": "Test Game",
            "entry_url": "https://example.com/game/index.html"
        }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Create a text channel and return its id.
async fn create_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": "game-room" }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_session_happy_path() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    let body: Value = resp.json();
    assert_eq!(body["game_id"].as_str().unwrap(), game_id);
    assert_eq!(body["channel_id"].as_str().unwrap(), channel_id);
    assert_eq!(body["host_pubkey"].as_str().unwrap(), identity.public_key_hex());
    assert!(body["ended_at"].is_null());
}

#[tokio::test]
async fn get_session_after_create() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let created: Value = create_resp.json();
    let session_id = created["id"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"].as_str().unwrap(), session_id);
}

#[tokio::test]
async fn join_session_happy_path() {
    let server = setup().await;
    let host = Identity::generate();
    let host_token = authenticate(&server, &host).await;
    let player = Identity::generate();
    let player_token = authenticate(&server, &player).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let join_resp = server
        .post(&format!("/game-sessions/{session_id}/join"))
        .authorization_bearer(&player_token)
        .await;
    join_resp.assert_status_ok();
    let body: Value = join_resp.json();
    // players list comes from in-memory state; should include the joiner.
    let players: Vec<String> = body["players"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(players.contains(&player.public_key_hex()));
}

#[tokio::test]
async fn patch_state_by_host() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let patch_resp = server
        .post(&format!("/game-sessions/{session_id}/state"))
        .authorization_bearer(&token)
        .json(&json!({ "patch": { "round": 1, "phase": "voting" } }))
        .await;
    patch_resp.assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn shared_kv_set_and_get() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Set a key.
    let set_resp = server
        .post(&format!("/game-sessions/{session_id}/shared-kv/leaderboard"))
        .authorization_bearer(&token)
        .json(&json!({ "value": "[{\"pubkey\":\"abc\",\"score\":100}]" }))
        .await;
    set_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Get it back.
    let get_resp = server
        .get(&format!("/game-sessions/{session_id}/shared-kv/leaderboard"))
        .authorization_bearer(&token)
        .await;
    get_resp.assert_status_ok();
    let body: Value = get_resp.json();
    assert_eq!(body["key"].as_str().unwrap(), "leaderboard");
    assert!(body["value"].as_str().unwrap().contains("score"));
}

#[tokio::test]
async fn end_session_by_host() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let del_resp = server
        .delete(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET now returns 410 GONE.
    let get_resp = server
        .get(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    get_resp.assert_status(axum::http::StatusCode::GONE);
}

// ---------------------------------------------------------------------------
// Rejection / auth tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_session_rejects_unknown_game() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": "no-such-game", "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn patch_state_rejected_for_non_host() {
    let server = setup().await;
    let host = Identity::generate();
    let host_token = authenticate(&server, &host).await;
    let other = Identity::generate();
    let other_token = authenticate(&server, &other).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Other user (non-admin, non-host) tries to patch.
    let patch_resp = server
        .post(&format!("/game-sessions/{session_id}/state"))
        .authorization_bearer(&other_token)
        .json(&json!({ "patch": { "cheating": true } }))
        .await;
    patch_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn end_session_rejected_for_non_host() {
    let server = setup().await;
    let host = Identity::generate();
    let host_token = authenticate(&server, &host).await;
    let other = Identity::generate();
    let other_token = authenticate(&server, &other).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let del_resp = server
        .delete(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&other_token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
