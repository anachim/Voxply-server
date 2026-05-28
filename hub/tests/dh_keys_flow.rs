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
use voxply_identity::{DhKeyRecord, Identity};

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

fn make_dh_publish_body(identity: &Identity) -> serde_json::Value {
    let (_, dh_pub) = identity.dh_keypair();
    let dh_pubkey_hex = hex::encode(dh_pub.as_bytes());
    let msg = DhKeyRecord::signing_bytes(&identity.public_key_hex(), &dh_pubkey_hex);
    let sig = hex::encode(identity.sign(&msg).to_bytes());
    json!({
        "dh_pubkey_hex": dh_pubkey_hex,
        "signature_hex": sig,
    })
}

#[tokio::test]
async fn publish_and_fetch_dh_key() {
    let server = setup().await;
    let alice = Identity::generate();
    let token = authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();

    // GET before any key is published → 404
    server
        .get(&format!("/identity/{pubkey}/dh-key"))
        .await
        .assert_status(axum::http::StatusCode::NOT_FOUND);

    // PUT the DH key
    let body = make_dh_publish_body(&alice);
    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .authorization_bearer(&token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::OK);

    // GET now returns the key
    let resp = server
        .get(&format!("/identity/{pubkey}/dh-key"))
        .await;
    resp.assert_status_ok();
    let result: serde_json::Value = resp.json();
    assert_eq!(result["dh_pubkey_hex"], body["dh_pubkey_hex"]);
}

#[tokio::test]
async fn publish_dh_key_rejects_wrong_identity() {
    let server = setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    authenticate(&server, &bob).await;

    // Alice tries to publish a DH key under Bob's pubkey — must be rejected.
    let bob_pubkey = bob.public_key_hex();
    let body = make_dh_publish_body(&bob);
    server
        .put(&format!("/identity/{bob_pubkey}/dh-key"))
        .authorization_bearer(&alice_token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_dh_key_rejects_bad_signature() {
    let server = setup().await;
    let alice = Identity::generate();
    let token = authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();

    let (_, dh_pub) = alice.dh_keypair();
    let dh_pubkey_hex = hex::encode(dh_pub.as_bytes());
    // Tampered: signature is all-zeros.
    let bad_sig = "0".repeat(128);

    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .authorization_bearer(&token)
        .json(&json!({
            "dh_pubkey_hex": dh_pubkey_hex,
            "signature_hex": bad_sig,
        }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_requires_authentication() {
    let server = setup().await;
    let alice = Identity::generate();
    // Register alice so the pubkey exists, but don't use the token.
    authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();
    let body = make_dh_publish_body(&alice);

    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::UNAUTHORIZED);
}
