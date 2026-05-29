use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::invite_models::InviteResponse;
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
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),    });
    let app = server::create_router(state);
    TestServer::new(app)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    authenticate_with_invite(server, identity, None).await
}

async fn authenticate_with_invite(
    server: &TestServer,
    identity: &Identity,
    invite_code: Option<&str>,
) -> String {
    let pub_key = identity.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });

    if let Some(code) = invite_code {
        body["invite_code"] = json!(code);
    }

    let resp = server.post("/auth/verify").json(&body).await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

#[tokio::test]
async fn create_and_list_invites() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({ "max_uses": 5 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let invite: InviteResponse = resp.json();
    assert_eq!(invite.max_uses, Some(5));
    assert_eq!(invite.uses, 0);

    let resp = server
        .get("/invites")
        .authorization_bearer(&token)
        .await;
    let invites: Vec<InviteResponse> = resp.json();
    assert_eq!(invites.len(), 1);
}

#[tokio::test]
async fn invite_only_blocks_without_code() {
    let server = setup().await;

    // First user (owner) joins freely
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&owner_token)
        .json(&json!({ "max_uses": 1 }))
        .await;
    let invite: InviteResponse = resp.json();

    let user2 = Identity::generate();
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
            "invite_code": invite.code,
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn revoke_invite() {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({}))
        .await;
    let invite: InviteResponse = resp.json();

    server
        .delete(&format!("/invites/{}", invite.code))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get("/invites")
        .authorization_bearer(&token)
        .await;
    let invites: Vec<InviteResponse> = resp.json();
    assert_eq!(invites.len(), 0);
}
