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

async fn setup() -> (TestServer, Identity) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let hub_identity = Identity::generate();

    let state = Arc::new(AppState {
        hub_name: "Test Hub".to_string(),
        hub_identity,
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
    let server = TestServer::new(app);
    let identity = Identity::generate();
    (server, identity)
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

/// Happy path: admin requests a signed directory payload and the response
/// contains a valid Ed25519 signature over the canonical JSON.
#[tokio::test]
async fn directory_sign_returns_valid_signature() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let resp = server
        .post("/admin/directory-sign")
        .authorization_bearer(&token)
        .json(&json!({
            "hub_url": "https://hub.example.com",
            "tags": ["rust", "gaming", "art"],
            "language": "en",
            "bio": "A friendly community hub",
        }))
        .await;

    resp.assert_status_ok();

    let body: serde_json::Value = resp.json();
    let canonical = body["canonical_payload"].as_str().unwrap();
    let pubkey_hex = body["hub_pubkey"].as_str().unwrap();
    let sig_hex = body["signature"].as_str().unwrap();

    // Canonical payload must contain the expected fields.
    let parsed: serde_json::Value = serde_json::from_str(canonical).unwrap();
    assert_eq!(parsed["bio"], "A friendly community hub");
    assert_eq!(parsed["hub_url"], "https://hub.example.com");
    assert_eq!(parsed["language"], "en");

    // Tags must be sorted alphabetically in the payload.
    let tags: Vec<&str> = parsed["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["art", "gaming", "rust"]);

    // JSON keys must be alphabetically ordered (bio < hub_url < language < nonce < tags).
    let keys: Vec<&str> = parsed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["bio", "hub_url", "language", "nonce", "tags"]);

    // The signature must verify against the hub's public key.
    let sig_bytes = hex::decode(sig_hex).unwrap();
    voxply_identity::verify_signature(pubkey_hex, canonical.as_bytes(), &sig_bytes)
        .expect("signature should verify against hub pubkey");
}

/// Rejection: unauthenticated request must get 401.
#[tokio::test]
async fn directory_sign_rejects_unauthenticated() {
    let (server, _owner) = setup().await;

    let resp = server
        .post("/admin/directory-sign")
        .json(&json!({
            "hub_url": "https://hub.example.com",
            "tags": [],
            "language": "en",
            "bio": "bio",
        }))
        .await;

    resp.assert_status_unauthorized();
}

/// Rejection: non-admin user must get 403.
#[tokio::test]
async fn directory_sign_rejects_non_admin() {
    let (server, owner) = setup().await;
    // Log in the owner first to create the hub.
    let _owner_token = authenticate(&server, &owner).await;

    // A second user that joins — they will only have the built-in "everyone" role.
    let regular_user = Identity::generate();
    let user_token = authenticate(&server, &regular_user).await;

    let resp = server
        .post("/admin/directory-sign")
        .authorization_bearer(&user_token)
        .json(&json!({
            "hub_url": "https://hub.example.com",
            "tags": [],
            "language": "en",
            "bio": "bio",
        }))
        .await;

    resp.assert_status_forbidden();
}
