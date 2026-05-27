use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::chat_models::ChannelResponse;
use voxply_hub::routes::moderation_models::{BanResponse, MuteResponse};
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
        voice_udp_port: 0,
        voice_event_tx,
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

#[tokio::test]
async fn ban_blocks_authentication() {
    let server = setup().await;

    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let _token2 = authenticate(&server, &user2).await;

    // Owner bans user2
    let resp = server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
            "reason": "spamming",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // user2 tries to authenticate again — should be rejected
    let pub_key = user2.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = user2.sign(&challenge_bytes);

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mute_blocks_sending_messages() {
    let server = setup().await;

    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 can send before mute
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "hello" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Owner mutes user2
    server
        .post("/moderation/mutes")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // user2 can't send while muted
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "still here" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner unmutes
    server
        .delete(&format!("/moderation/mutes/{}", user2.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can send again
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "im back" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn cannot_moderate_higher_priority_user() {
    let server = setup().await;

    // Owner is first user (gets Owner role)
    let owner = Identity::generate();
    let _owner_token = authenticate(&server, &owner).await;

    // user2 (only @everyone) tries to ban owner
    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    let resp = server
        .post("/moderation/bans")
        .authorization_bearer(&token2)
        .json(&json!({
            "target_public_key": owner.public_key_hex(),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unban_allows_reauth() {
    let server = setup().await;

    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    authenticate(&server, &user2).await;

    // Ban then unban
    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": user2.public_key_hex() }))
        .await;

    server
        .delete(&format!("/moderation/bans/{}", user2.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can authenticate again
    let token2 = authenticate(&server, &user2).await;
    assert!(!token2.is_empty());
}

#[tokio::test]
async fn list_bans() {
    let server = setup().await;

    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    authenticate(&server, &user2).await;

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
            "reason": "testing",
        }))
        .await;

    let resp = server
        .get("/moderation/bans")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let bans: Vec<BanResponse> = resp.json();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].target_public_key, user2.public_key_hex());
    assert_eq!(bans[0].reason, Some("testing".to_string()));
}

#[tokio::test]
async fn channel_ban_blocks_messages() {
    let server = setup().await;

    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    // Create channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 can send before channel ban
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "hello" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Ban user2 from channel
    server
        .post(&format!("/moderation/channels/{}/bans", channel.id))
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": user2.public_key_hex() }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // user2 can't send to that channel
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "blocked" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Unban
    server
        .delete(&format!("/moderation/channels/{}/bans/{}", channel.id, user2.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can send again
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "im back" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}

// --- WebSocket-level voice moderation enforcement ---

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Spin up a real listener so we can connect a WebSocket client to it.
async fn spawn_real_hub() -> (String, Arc<AppState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: broadcast::channel(256).0,
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
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://127.0.0.1:{port}"), state)
}

async fn http_authenticate(hub_url: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();
    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

/// Send a voice_join over WS, return the first server frame as JSON.
async fn ws_voice_join_and_recv(
    hub_url: &str,
    token: &str,
    channel_id: &str,
) -> serde_json::Value {
    let ws_url = hub_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let url = format!("{ws_url}/ws?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut tx, mut rx) = ws_stream.split();

    // Consume the `hello` frame the hub sends on connect.
    let hello_frame = rx.next().await.unwrap().unwrap();
    let WsMessage::Text(hello_text) = hello_frame else { panic!("expected hello text frame") };
    let hello: serde_json::Value = serde_json::from_str(&hello_text).unwrap();
    assert_eq!(hello["type"], "hello", "first frame should be hello");

    tx.send(WsMessage::Text(
        json!({ "type": "voice_join", "channel_id": channel_id, "udp_port": 12345 })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let frame = rx.next().await.unwrap().unwrap();
    let WsMessage::Text(text) = frame else { panic!("expected text frame, got {frame:?}") };
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn voice_mute_blocks_voice_join() {
    let (hub_url, _state) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    // Owner first to get the Owner role + permissions
    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Victim joins second (gets only @everyone)
    let victim = Identity::generate();
    let victim_token = http_authenticate(&hub_url, &victim).await;

    // Create a channel
    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Owner voice-mutes the victim
    client
        .post(format!("{hub_url}/moderation/voice-mutes"))
        .bearer_auth(&owner_token)
        .json(&json!({ "target_public_key": victim.public_key_hex() }))
        .send()
        .await
        .unwrap();

    // Victim attempts to join voice — should get an error frame, not voice_joined
    let frame = ws_voice_join_and_recv(&hub_url, &victim_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["context"], "voice_join");
    assert!(frame["message"].as_str().unwrap().contains("muted"));
}

#[tokio::test]
async fn talk_power_blocks_low_priority_user() {
    let (hub_url, state) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    // Owner sets up the channel + talk power
    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Random user with only @everyone (priority 0)
    let randuser = Identity::generate();
    let rand_token = http_authenticate(&hub_url, &randuser).await;

    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "vip-only" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Require talk power 100 — only the Owner role qualifies
    client
        .post(format!("{hub_url}/channels/{}/talk-power", channel.id))
        .bearer_auth(&owner_token)
        .json(&json!({ "min_talk_power": 100 }))
        .send()
        .await
        .unwrap();

    // Sanity: confirm the row landed
    let stored: i64 = sqlx::query_scalar(
        "SELECT min_talk_power FROM channel_settings WHERE channel_id = ?",
    )
    .bind(&channel.id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(stored, 100);

    // Random user tries to join — should be refused
    let frame = ws_voice_join_and_recv(&hub_url, &rand_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["context"], "voice_join");
    assert!(frame["message"].as_str().unwrap().contains("priority"));

    // Owner can still join (priority is 999999)
    let frame = ws_voice_join_and_recv(&hub_url, &owner_token, &channel.id).await;
    assert_eq!(frame["type"], "voice_joined");
}
