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

const SAMPLE_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>"#;

#[tokio::test]
async fn owner_can_create_list_rename_and_delete_icon() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Create an icon
    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&token)
        .json(&json!({ "name": "My Icon", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    let icon_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["name"], "My Icon");
    assert_eq!(body["svg_content"], SAMPLE_SVG);
    assert!(!icon_id.is_empty());

    // List shows the icon
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], icon_id);

    // Rename it
    server
        .patch(&format!("/hub/icons/{icon_id}"))
        .authorization_bearer(&token)
        .json(&json!({ "name": "Renamed Icon" }))
        .await
        .assert_status(axum::http::StatusCode::OK);

    // List reflects the new name
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list[0]["name"], "Renamed Icon");

    // Delete it
    server
        .delete(&format!("/hub/icons/{icon_id}"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Gone
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn non_admin_cannot_create_icon() {
    let server = setup().await;
    // First user gets Owner role; second gets @everyone only.
    let _owner_token = authenticate(&server, &Identity::generate()).await;
    let rando_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&rando_token)
        .json(&json!({ "name": "Sneaky", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_icon_rejects_empty_name() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "   ", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rename_icon_returns_404_for_unknown_id() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .patch("/hub/icons/nonexistent-id")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Whatever" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_icon_returns_404_for_unknown_id() {
    let server = setup().await;
    let owner_token = authenticate(&server, &Identity::generate()).await;

    let resp = server
        .delete("/hub/icons/nonexistent-id")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn any_authenticated_user_can_list_icons() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;
    let rando_token = authenticate(&server, &Identity::generate()).await;

    // Owner creates one
    server
        .post("/hub/icons")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Public Icon", "svg_content": SAMPLE_SVG }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Regular user can list
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&rando_token)
        .await
        .json();
    assert_eq!(list.as_array().unwrap().len(), 1);
}
