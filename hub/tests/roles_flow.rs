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
use voxply_hub::routes::role_models::RoleResponse;
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
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        started_at: std::time::Instant::now(),    });
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
async fn first_user_gets_owner_and_everyone() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    let resp = server.get("/me").authorization_bearer(&token).await;
    let me: MeResponse = resp.json();

    assert_eq!(me.roles.len(), 2);
    let role_names: Vec<&str> = me.roles.iter().map(|r| r.name.as_str()).collect();
    assert!(role_names.contains(&"Owner"));
    assert!(role_names.contains(&"@everyone"));
}

#[tokio::test]
async fn second_user_gets_only_everyone() {
    let server = setup().await;

    let owner = Identity::generate();
    authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    let resp = server.get("/me").authorization_bearer(&token2).await;
    let me: MeResponse = resp.json();

    assert_eq!(me.roles.len(), 1);
    assert_eq!(me.roles[0].name, "@everyone");
}

#[tokio::test]
async fn owner_can_create_role() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["manage_channels", "manage_messages"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();
    assert_eq!(role.name, "Moderator");
    assert_eq!(role.priority, 50);
    assert!(role.permissions.contains(&"manage_channels".to_string()));
}

#[tokio::test]
async fn everyone_user_cannot_create_role() {
    let server = setup().await;
    let owner = Identity::generate();
    authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "Hacker",
            "permissions": ["admin"],
            "priority": 100,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn priority_enforcement() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    // Owner creates a moderator role at priority 50
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["manage_roles", "manage_channels"],
            "priority": 50,
        }))
        .await;
    let mod_role: RoleResponse = resp.json();

    // Create user2 and assign moderator role
    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    server
        .put(&format!(
            "/users/{}/roles/{}",
            user2.public_key_hex(),
            mod_role.id
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // User2 tries to create a role at priority 50 (= their own) — should fail
    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "HighRole",
            "permissions": ["send_messages"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // User2 creates a role at priority 49 (< their own) — should succeed
    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "LowRole",
            "permissions": ["send_messages"],
            "priority": 49,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn cannot_modify_builtin_roles() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .patch("/roles/builtin-owner")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Hacked" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let resp = server
        .delete("/roles/builtin-everyone")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn permission_gating_on_channels() {
    let server = setup().await;
    let owner = Identity::generate();
    authenticate(&server, &owner).await;

    // User2 (only @everyone) tries to create a channel — should fail
    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token2)
        .json(&json!({ "name": "test" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_remove_last_owner() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .delete(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
