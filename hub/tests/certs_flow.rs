//! Integration tests for hub certification issuance (#20) and auth gate (#21).

use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::cert_worker;
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::certs::{Certification, IssuanceRow};
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

// ---------------------------------------------------------------------------
// Shared test setup
// ---------------------------------------------------------------------------

async fn make_state() -> Arc<AppState> {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    Arc::new(AppState {
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
        cached_farm_pubkey: Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
    })
}

async fn setup() -> (Arc<AppState>, TestServer) {
    let state = make_state().await;
    let app = server::create_router(state.clone());
    let server = TestServer::new(app);
    (state, server)
}

/// Authenticate an identity against the test server; returns a session token.
async fn do_auth(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    resp.assert_status_ok();
    let ch: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = identity.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": ch.challenge,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status_ok();
    let v: VerifyResponse = resp.json();
    v.token
}

// ---------------------------------------------------------------------------
// Task #20 — Issuance
// ---------------------------------------------------------------------------

/// Admin can manually issue a cert for an existing member.
#[tokio::test]
async fn admin_issue_happy_path() {
    let (_, server) = setup().await;

    // First user becomes owner.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Second user registers.
    let member = Identity::generate();
    let _member_token = do_auth(&server, &member).await;

    // Admin issues a cert.
    let resp = server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let cert: Certification = resp.json();

    assert_eq!(cert.payload.subject_pubkey, member.public_key_hex());
    assert_eq!(cert.payload.standing, "good");
    assert!(!cert.signature.is_empty());
}

/// Admin list returns the issued cert.
#[tokio::test]
async fn admin_list_certs() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let _mt = do_auth(&server, &member).await;

    server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get("/admin/certs")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let rows: Vec<IssuanceRow> = resp.json();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].subject_pubkey, member.public_key_hex());
}

/// Admin can revoke a cert; it no longer appears in the public endpoint.
#[tokio::test]
async fn admin_revoke_cert() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let _mt = do_auth(&server, &member).await;
    let member_pk = member.public_key_hex();

    // Issue then revoke.
    server
        .post(&format!("/admin/certs/{member_pk}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .post(&format!("/admin/certs/{member_pk}/revoke"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Public endpoint returns empty (revoked cert filtered out).
    let resp = server
        .get(&format!("/identity/{member_pk}/certs"))
        .await;
    resp.assert_status_ok();
    let certs: Vec<Certification> = resp.json();
    assert!(certs.is_empty(), "revoked cert should not appear in public list");
}

/// Non-admin cannot issue a cert.
#[tokio::test]
async fn non_admin_cannot_issue() {
    let (_, server) = setup().await;
    let _owner = Identity::generate();
    let _owner_token = do_auth(&server, &_owner).await;
    let member = Identity::generate();
    let member_token = do_auth(&server, &member).await;

    let resp = server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&member_token)
        .await;
    resp.assert_status_forbidden();
}

/// Issuing a cert for an unknown pubkey returns 404.
#[tokio::test]
async fn issue_unknown_pubkey_returns_404() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let resp = server
        .post("/admin/certs/deadbeef0000000000000000000000000000000000000000000000000000abcd")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_not_found();
}

/// Cert worker tick issues certs to members whose first_seen_at is old enough.
#[tokio::test]
async fn cert_worker_issues_on_tick() {
    let state = make_state().await;
    let server = TestServer::new(server::create_router(state.clone()));

    // Register a member.
    let member = Identity::generate();
    let member_pk = member.public_key_hex();
    let _owner = Identity::generate();
    do_auth(&server, &_owner).await;
    do_auth(&server, &member).await;

    // Back-date first_seen_at to 31 days ago so the worker considers them eligible.
    let thirty_one_days_ago = voxply_hub::auth::handlers::unix_timestamp() - 31 * 86400;
    sqlx::query("UPDATE users SET first_seen_at = ? WHERE public_key = ?")
        .bind(thirty_one_days_ago)
        .bind(&member_pk)
        .execute(&state.db)
        .await
        .unwrap();

    // Run a worker tick.
    cert_worker::tick(&state).await.unwrap();

    // Check the public endpoint returns a cert (reads cert_issuances).
    let resp = server
        .get(&format!("/identity/{member_pk}/certs"))
        .await;
    resp.assert_status_ok();
    let certs: Vec<Certification> = resp.json();
    assert!(!certs.is_empty(), "worker should have issued a cert");
    assert_eq!(certs[0].payload.subject_pubkey, member_pk);
}

// ---------------------------------------------------------------------------
// Task #21 — Auth gate
// ---------------------------------------------------------------------------

/// When cert_mode = 'none' (default), /auth/verify succeeds without any certs.
#[tokio::test]
async fn cert_mode_none_no_cert_needed() {
    let (_, server) = setup().await;
    let id = Identity::generate();
    let _ = do_auth(&server, &Identity::generate()).await; // owner
    let token = do_auth(&server, &id).await;
    assert!(!token.is_empty());
}

/// When cert_mode = 'any', /auth/verify without a cert returns 403 cert_required.
#[tokio::test]
async fn cert_mode_any_rejects_no_cert() {
    let (state, server) = setup().await;

    // Set up owner.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Enable cert_mode = 'any'.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // A new user tries to auth without a cert.
    let newcomer = Identity::generate();
    let pk = newcomer.public_key_hex();
    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = newcomer.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pk,
            "challenge": ch.challenge,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status_forbidden();
    assert!(resp.text().contains("cert_required"));

    // Suppress unused state warning.
    let _ = state.hub_name.as_str();
}

/// When cert_mode = 'any', a valid cert from any hub is accepted.
#[tokio::test]
async fn cert_mode_any_accepts_valid_cert() {
    let (state, server) = setup().await;

    // Owner registers first.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Enable cert_mode = 'any'.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Create a newcomer and issue them a cert from THIS hub (simulates
    // them having been a member of a hub that trusts them).
    let newcomer = Identity::generate();
    let newcomer_pk = newcomer.public_key_hex();

    // Insert minimal user row so issue_cert_for can find them.
    let now = voxply_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status)
         VALUES (?, ?, ?, 'approved')",
    )
    .bind(&newcomer_pk)
    .bind(now - 86400)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let cert = voxply_hub::routes::certs::issue_cert_for(&state, &newcomer_pk)
        .await
        .unwrap();

    // Now authenticate presenting the cert. Use newcomer_pk as both public_key and
    // the cert's subject (no subkey cert, so master = auth pubkey).
    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": newcomer_pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = newcomer.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": newcomer_pk,
            "challenge": ch.challenge,
            "signature": sig_hex,
            "certifications": [cert],
        }))
        .await;
    resp.assert_status_ok();
    let v: VerifyResponse = resp.json();
    assert!(!v.token.is_empty());
}

/// GET /info includes cert_requirement when cert_mode != 'none'.
#[tokio::test]
async fn info_includes_cert_requirement() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Default: cert_requirement is absent.
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("cert_requirement").is_none());

    // Enable cert gate.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let info: serde_json::Value = server.get("/info").await.json();
    let req = info.get("cert_requirement").expect("cert_requirement should be present");
    assert_eq!(req["mode"], "any");
}

/// PATCH /admin/settings/certs rejects invalid cert_mode values.
#[tokio::test]
async fn patch_cert_settings_rejects_invalid_mode() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "banana" }))
        .await;
    resp.assert_status_bad_request();
}
