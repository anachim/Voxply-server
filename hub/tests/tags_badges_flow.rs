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
// Test harness
// ---------------------------------------------------------------------------

async fn setup() -> (TestServer, Identity) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let (chat_tx, _) = broadcast::channel(256);

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
    });

    let app = server::create_router(state);
    let server = TestServer::new(app);
    let owner = Identity::generate();
    (server, owner)
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

// ---------------------------------------------------------------------------
// Task #12 — Self-tags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_tags_returns_empty_by_default() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/settings/tags")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    let body: Value = resp.json();
    let tags = body["tags"].as_array().unwrap();
    assert!(tags.is_empty(), "fresh hub should have no tags");
}

#[tokio::test]
async fn patch_tags_happy_path() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/tags")
        .authorization_bearer(&token)
        .json(&json!({ "tags": ["gaming", "english", "18plus"] }))
        .await;
    resp.assert_status_ok();

    let body: Value = resp.json();
    let tags: Vec<&str> = body["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["gaming", "english", "18plus"]);
}

#[tokio::test]
async fn patch_tags_normalises_case() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/tags")
        .authorization_bearer(&token)
        .json(&json!({ "tags": ["RUST", "Gaming"] }))
        .await;
    resp.assert_status_ok();

    let body: Value = resp.json();
    let tags: Vec<&str> = body["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["rust", "gaming"]);
}

#[tokio::test]
async fn patch_tags_rejects_reserved_words() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    for reserved in &["verified", "certified", "official", "partner", "admin"] {
        let resp = server
            .patch("/admin/settings/tags")
            .authorization_bearer(&token)
            .json(&json!({ "tags": [reserved] }))
            .await;
        resp.assert_status_bad_request();
    }
}

#[tokio::test]
async fn patch_tags_rejects_too_many() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let tags: Vec<String> = (1..=13).map(|i| format!("tag{i}")).collect();
    let resp = server
        .patch("/admin/settings/tags")
        .authorization_bearer(&token)
        .json(&json!({ "tags": tags }))
        .await;
    resp.assert_status_bad_request();
}

#[tokio::test]
async fn patch_tags_rejects_invalid_chars() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/tags")
        .authorization_bearer(&token)
        .json(&json!({ "tags": ["has space"] }))
        .await;
    resp.assert_status_bad_request();
}

#[tokio::test]
async fn tags_appear_in_info() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/tags")
        .authorization_bearer(&token)
        .json(&json!({ "tags": ["music", "chill"] }))
        .await
        .assert_status_ok();

    let info: Value = server.get("/info").await.json();
    let self_tags: Vec<&str> = info["self_tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(self_tags, vec!["music", "chill"]);
}

#[tokio::test]
async fn tags_endpoint_rejects_unauthenticated() {
    let (server, _owner) = setup().await;

    server
        .get("/admin/settings/tags")
        .await
        .assert_status_unauthorized();

    server
        .patch("/admin/settings/tags")
        .json(&json!({ "tags": [] }))
        .await
        .assert_status_unauthorized();
}

// ---------------------------------------------------------------------------
// Task #13 — Badge federation
// ---------------------------------------------------------------------------

/// Build a signed badge offer payload for `subject_pubkey` using
/// `issuer_identity` as the issuer. Returns (payload_json, sig_hex).
fn build_badge_offer(
    issuer: &Identity,
    issuer_url: &str,
    subject_pubkey: &str,
    label: &str,
) -> (String, String) {
    let payload = json!({
        "issuer_pubkey": issuer.public_key_hex(),
        "issuer_url": issuer_url,
        "subject_pubkey": subject_pubkey,
        "label": label,
        "issued_at": "2026-05-29T12:00:00Z",
        "expires_at": null,
    });
    let payload_json = serde_json::to_string(&payload).unwrap();
    let sig = issuer.sign(payload_json.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());
    (payload_json, sig_hex)
}

#[tokio::test]
async fn badge_offer_happy_path() {
    let (server, owner) = setup().await;
    // Authenticate owner so we know the hub's pubkey.
    let token = authenticate(&server, &owner).await;

    // Discover the hub's public key from /info.
    let info: Value = server.get("/info").await.json();
    let hub_pubkey = info["public_key"].as_str().unwrap().to_string();

    // Build a badge offer from an external issuer identity.
    let issuer = Identity::generate();
    let (payload_json, sig_hex) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &hub_pubkey,
        "alliance-member",
    );

    let resp = server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "alliance-member",
            "note": "Welcome to the alliance",
            "payload": payload_json,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Now admin should see it in /badges/pending.
    let resp = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let pending: Value = resp.json();
    let arr = pending.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], "alliance-member");
    assert_eq!(arr[0]["from_hub_url"], "https://issuer.example.com");
}

#[tokio::test]
async fn badge_offer_rejects_bad_signature() {
    let (server, _owner) = setup().await;

    let info: Value = server.get("/info").await.json();
    let hub_pubkey = info["public_key"].as_str().unwrap().to_string();

    let issuer = Identity::generate();
    let (payload_json, _) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &hub_pubkey,
        "test-badge",
    );
    // Deliberately corrupt the signature.
    let bad_sig = hex::encode([0u8; 64]);

    let resp = server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "test-badge",
            "note": null,
            "payload": payload_json,
            "signature": bad_sig,
        }))
        .await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn badge_offer_rejects_wrong_subject() {
    let (server, _owner) = setup().await;

    let issuer = Identity::generate();
    let wrong_subject = Identity::generate().public_key_hex();
    let (payload_json, sig_hex) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &wrong_subject, // not this hub's pubkey
        "test-badge",
    );

    let resp = server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "test-badge",
            "note": null,
            "payload": payload_json,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status_bad_request();
}

#[tokio::test]
async fn accept_badge_moves_to_held() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let info: Value = server.get("/info").await.json();
    let hub_pubkey = info["public_key"].as_str().unwrap().to_string();

    let issuer = Identity::generate();
    let (payload_json, sig_hex) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &hub_pubkey,
        "raid-certified",
    );

    server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "raid-certified",
            "note": null,
            "payload": payload_json,
            "signature": sig_hex,
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Get the offer id.
    let pending: Value = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await
        .json();
    let offer_id = pending.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Accept it.
    server
        .post(&format!("/badges/pending/{offer_id}/accept"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Pending should now be empty.
    let pending_after: Value = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(pending_after.as_array().unwrap().is_empty());

    // Held badges should show one.
    let held: Value = server
        .get("/badges")
        .authorization_bearer(&token)
        .await
        .json();
    let held_arr = held.as_array().unwrap();
    assert_eq!(held_arr.len(), 1);
    assert_eq!(held_arr[0]["label"], "raid-certified");

    // Badge should appear in /info.
    let info_after: Value = server.get("/info").await.json();
    let badges = info_after["badges"].as_array().unwrap();
    assert_eq!(badges.len(), 1);
    assert_eq!(badges[0]["payload"]["label"], "raid-certified");
}

#[tokio::test]
async fn decline_badge_removes_offer() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let info: Value = server.get("/info").await.json();
    let hub_pubkey = info["public_key"].as_str().unwrap().to_string();

    let issuer = Identity::generate();
    let (payload_json, sig_hex) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &hub_pubkey,
        "unwanted-badge",
    );

    server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "unwanted-badge",
            "note": null,
            "payload": payload_json,
            "signature": sig_hex,
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let pending: Value = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await
        .json();
    let offer_id = pending.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .post(&format!("/badges/pending/{offer_id}/decline"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let pending_after: Value = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(pending_after.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn delete_held_badge() {
    let (server, owner) = setup().await;
    let token = authenticate(&server, &owner).await;

    let info: Value = server.get("/info").await.json();
    let hub_pubkey = info["public_key"].as_str().unwrap().to_string();

    let issuer = Identity::generate();
    let (payload_json, sig_hex) = build_badge_offer(
        &issuer,
        "https://issuer.example.com",
        &hub_pubkey,
        "removable-badge",
    );

    server
        .post("/federation/badge-offer")
        .json(&json!({
            "from_hub_pubkey": issuer.public_key_hex(),
            "from_hub_url": "https://issuer.example.com",
            "label": "removable-badge",
            "note": null,
            "payload": payload_json,
            "signature": sig_hex,
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let pending: Value = server
        .get("/badges/pending")
        .authorization_bearer(&token)
        .await
        .json();
    let offer_id = pending.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .post(&format!("/badges/pending/{offer_id}/accept"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let held: Value = server
        .get("/badges")
        .authorization_bearer(&token)
        .await
        .json();
    let badge_id = held.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .delete(&format!("/badges/{badge_id}"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Badge must be gone from held and /info.
    let held_after: Value = server
        .get("/badges")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(held_after.as_array().unwrap().is_empty());

    let info_after: Value = server.get("/info").await.json();
    assert!(info_after["badges"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn badge_admin_routes_require_auth() {
    let (server, _owner) = setup().await;

    server
        .get("/badges/pending")
        .await
        .assert_status_unauthorized();

    server
        .get("/badges")
        .await
        .assert_status_unauthorized();

    server
        .post("/badges/pending/fake-id/accept")
        .await
        .assert_status_unauthorized();

    server
        .post("/badges/pending/fake-id/decline")
        .await
        .assert_status_unauthorized();

    server
        .delete("/badges/fake-id")
        .await
        .assert_status_unauthorized();
}
