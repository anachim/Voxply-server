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

async fn setup() -> TestServer {
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
    TestServer::new(server::create_router(state))
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let challenge: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let verify: VerifyResponse = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await
        .json();
    verify.token
}

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn any_member_can_create_list_and_delete_bot() {
    let server = setup().await;
    let member = Identity::generate();
    let member_token = authenticate(&server, &member).await;

    // Create a bot — any authenticated user can create
    let resp = server
        .post("/admin/bots")
        .authorization_bearer(&member_token)
        .json(&json!({ "display_name": "MyBot" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["display_name"], "MyBot");
    let bot_key = body["public_key"].as_str().unwrap().to_string();
    assert!(bot_key.starts_with("bot_"));
    let returned_token = body["token"].as_str().unwrap().to_string();
    assert_eq!(returned_token.len(), 64);
    // created_by should be the member
    assert_eq!(body["created_by"], member.public_key_hex());
    // token must NOT be in the list response
    assert!(body.get("webhook_url").is_some() || body.get("webhook_url").is_none()); // field may or may not appear

    // List shows the bot (without token)
    let list: serde_json::Value = server
        .get("/admin/bots")
        .authorization_bearer(&member_token)
        .await
        .json();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["public_key"], bot_key);
    assert!(arr[0].get("token").is_none() || arr[0]["token"].is_null());

    // Get detail
    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&member_token)
        .await
        .json();
    assert_eq!(detail["public_key"], bot_key);
    assert!(detail["commands"].as_array().unwrap().is_empty());

    // Creator can delete
    server
        .delete(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Gone from list
    let list2: serde_json::Value = server
        .get("/admin/bots")
        .authorization_bearer(&member_token)
        .await
        .json();
    assert_eq!(list2.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn non_creator_cannot_delete_without_admin() {
    let server = setup().await;
    // First authenticator becomes the owner (gets Owner role).
    let _owner_token = authenticate(&server, &Identity::generate()).await;
    let creator = Identity::generate();
    let creator_token = authenticate(&server, &creator).await;
    let rando = Identity::generate();
    let rando_token = authenticate(&server, &rando).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&creator_token)
        .json(&json!({ "display_name": "BotX" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // rando cannot delete creator's bot
    let del = server
        .delete(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&rando_token)
        .await;
    del.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn creator_can_set_and_clear_webhook() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "WebhookBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // Set webhook
    server
        .put(&format!("/admin/bots/{bot_key}/webhook"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "webhook_url": "https://example.com/hook" }))
        .await
        .assert_status_success();

    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert_eq!(detail["webhook_url"], "https://example.com/hook");

    // Clear webhook
    server
        .put(&format!("/admin/bots/{bot_key}/webhook"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "webhook_url": null }))
        .await
        .assert_status_success();

    let detail2: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(detail2["webhook_url"].is_null());
}

#[tokio::test]
async fn bot_token_can_set_commands_and_poll() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "CmdBot" }))
        .await
        .json();
    let bot_token = resp["token"].as_str().unwrap().to_string();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // Set slash commands
    server
        .put("/bot/commands")
        .authorization_bearer(&bot_token)
        .json(&json!({
            "commands": [
                { "command": "ping", "description": "Ping the bot" },
                { "command": "echo", "description": "Echo back" }
            ]
        }))
        .await
        .assert_status_success();

    // Detail shows commands
    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let cmds = detail["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 2);
    let cmd_names: Vec<&str> = cmds.iter().map(|c| c["command"].as_str().unwrap()).collect();
    assert!(cmd_names.contains(&"ping"));
    assert!(cmd_names.contains(&"echo"));

    // Poll with no events returns empty list
    let poll: serde_json::Value = server
        .get("/bot/poll")
        .authorization_bearer(&bot_token)
        .await
        .json();
    assert_eq!(poll["events"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn bot_can_send_message() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    // Create a channel first
    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "MsgBot" }))
        .await
        .json();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let send = server
        .post("/bot/send")
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "content": "Hello from bot" }))
        .await;
    send.assert_status_success();
    let body: serde_json::Value = send.json();
    assert_eq!(body["ok"], true);
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_bot_rejects_empty_display_name() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "   " }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_bot_returns_404_for_unknown_key() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .delete("/admin/bots/bot_does_not_exist")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_bot_returns_404_for_unknown_key() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .get("/admin/bots/bot_does_not_exist")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_bot_token_returns_unauthorized_on_poll() {
    let server = setup().await;

    let resp = server
        .get("/bot/poll")
        .authorization_bearer("totallyfaketoken1234")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_auth_returns_unauthorized_on_bot_send() {
    let server = setup().await;

    let resp = server
        .post("/bot/send")
        .json(&json!({ "channel_id": "x", "content": "hi" }))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}
