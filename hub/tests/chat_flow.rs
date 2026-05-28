use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::chat_models::{ChannelResponse, MessageResponse};
use voxply_hub::routes::me::MeResponse;
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
async fn create_and_list_channels() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel: ChannelResponse = resp.json();
    assert_eq!(channel.name, "general");
    assert_eq!(channel.created_by, identity.public_key_hex());

    // Create another
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "random" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // List channels
    let resp = server
        .get("/channels")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let channels: Vec<ChannelResponse> = resp.json();
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0].name, "general");
    assert_eq!(channels[1].name, "random");
}

#[tokio::test]
async fn duplicate_channel_name_returns_conflict() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn channels_require_auth() {
    let server = setup().await;
    let resp = server.get("/channels").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn send_and_get_messages() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // Send messages
    for i in 1..=3 {
        let resp = server
            .post(&format!("/channels/{}/messages", channel.id))
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("message {i}") }))
            .await;
        resp.assert_status(axum::http::StatusCode::CREATED);
    }

    // Get messages (newest first)
    let resp = server
        .get(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let messages: Vec<MessageResponse> = resp.json();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].content, "message 3");
    assert_eq!(messages[2].content, "message 1");
    assert_eq!(messages[0].sender, identity.public_key_hex());
    assert!(messages[0].sender_name.is_none());

    // Set display name and send another message
    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "display_name": "Alice" }))
        .await;

    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token)
        .json(&json!({ "content": "message 4" }))
        .await;

    let resp = server
        .get(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token)
        .await;
    let messages: Vec<MessageResponse> = resp.json();
    assert_eq!(messages[0].sender_name, Some("Alice".to_string()));
}

#[tokio::test]
async fn set_and_get_display_name() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Initially no display name
    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, identity.public_key_hex());
    assert!(me.display_name.is_none());

    // Set display name
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "display_name": "Alice" }))
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.display_name, Some("Alice".to_string()));

    // Verify it persists
    let resp = server.get("/me").authorization_bearer(&token).await;
    let me: MeResponse = resp.json();
    assert_eq!(me.display_name, Some("Alice".to_string()));
}

#[tokio::test]
async fn message_to_nonexistent_channel_returns_404() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let resp = server
        .post("/channels/nonexistent/messages")
        .authorization_bearer(&token)
        .json(&json!({ "content": "hello" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_category_and_nested_channel() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Create a category
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "games", "is_category": true }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let category: ChannelResponse = resp.json();
    assert!(category.is_category);
    assert!(category.parent_id.is_none());

    // Create a channel inside the category
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "chess", "parent_id": category.id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let child: ChannelResponse = resp.json();
    assert!(!child.is_category);
    assert_eq!(child.parent_id, Some(category.id.clone()));

    // List shows both
    let resp = server.get("/channels").authorization_bearer(&token).await;
    let channels: Vec<ChannelResponse> = resp.json();
    assert_eq!(channels.len(), 2);
}

#[tokio::test]
async fn cannot_nest_under_non_category() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Create a regular channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // Try to nest under it (should fail — not a category)
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "sub", "parent_id": channel.id }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_channel() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "temp" }))
        .await;
    let channel: ChannelResponse = resp.json();

    server
        .delete(&format!("/channels/{}", channel.id))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Channel gone from list
    let resp = server.get("/channels").authorization_bearer(&token).await;
    let channels: Vec<ChannelResponse> = resp.json();
    assert_eq!(channels.len(), 0);
}

#[tokio::test]
async fn cannot_delete_non_empty_category() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Category with a child
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "games", "is_category": true }))
        .await;
    let category: ChannelResponse = resp.json();

    server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "chess", "parent_id": category.id }))
        .await;

    // Can't delete category while it has children
    server
        .delete(&format!("/channels/{}", category.id))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn reorder_channels() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let mut ids = Vec::new();
    for name in ["alpha", "beta", "gamma"] {
        let resp = server
            .post("/channels")
            .authorization_bearer(&token)
            .json(&json!({ "name": name }))
            .await;
        let ch: ChannelResponse = resp.json();
        ids.push(ch.id);
    }

    // Reverse the order
    let reversed: Vec<String> = ids.iter().rev().cloned().collect();
    server
        .post("/channels/reorder")
        .authorization_bearer(&token)
        .json(&json!({ "channel_ids": reversed.clone() }))
        .await
        .assert_status_ok();

    // List should now be in the new order
    let resp = server.get("/channels").authorization_bearer(&token).await;
    let channels: Vec<ChannelResponse> = resp.json();
    let names: Vec<&str> = channels.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["gamma", "beta", "alpha"]);
}

#[tokio::test]
async fn delete_channel_nonexistent_returns_404() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    server
        .delete("/channels/nonexistent-id")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn author_can_edit_and_delete_their_message() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let ch: ChannelResponse = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await
        .json();

    let msg: MessageResponse = server
        .post(&format!("/channels/{}/messages", ch.id))
        .authorization_bearer(&token)
        .json(&json!({ "content": "first take" }))
        .await
        .json();
    assert!(msg.edited_at.is_none());

    // Edit
    let edited: MessageResponse = server
        .patch(&format!("/channels/{}/messages/{}", ch.id, msg.id))
        .authorization_bearer(&token)
        .json(&json!({ "content": "better take" }))
        .await
        .json();
    assert_eq!(edited.content, "better take");
    assert!(edited.edited_at.is_some());

    // Delete
    server
        .delete(&format!("/channels/{}/messages/{}", ch.id, msg.id))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // List is empty
    let resp = server
        .get(&format!("/channels/{}/messages", ch.id))
        .authorization_bearer(&token)
        .await;
    let messages: Vec<MessageResponse> = resp.json();
    assert!(messages.is_empty());
}

#[tokio::test]
async fn non_author_cannot_edit_other_peoples_messages() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = authenticate(&server, &bob).await;

    let ch: ChannelResponse = server
        .post("/channels")
        .authorization_bearer(&alice_token)
        .json(&json!({ "name": "general" }))
        .await
        .json();

    let msg: MessageResponse = server
        .post(&format!("/channels/{}/messages", ch.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "mine" }))
        .await
        .json();

    server
        .patch(&format!("/channels/{}/messages/{}", ch.id, msg.id))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hijacked" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}
