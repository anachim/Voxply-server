/// Integration tests for Phase 3 farm admin routes.
///
/// Tests exercise:
/// - GET  /farm/settings         (admin-only)
/// - PATCH /farm/settings        (admin-only, validation)
/// - GET  /farm/me/hub-quota     (authenticated)
/// - GET  /farm/users            (admin-only, pagination)
/// - POST /farm/users/:pk/revoke-sessions (admin-only)
/// - GET  /farm/public-info      (unauthenticated; respects allow_discovery_listing)
/// - POST /farm/hubs creation policy enforcement
use std::sync::Arc;

use axum::http::HeaderValue;
use axum_test::TestServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use voxply_farm::db;
use voxply_farm::hub_manager::HubManager;
use voxply_farm::server;
use voxply_farm::state::FarmState;
use voxply_identity::Identity;

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

async fn setup() -> (TestServer, Arc<FarmState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let now = unix_now();

    sqlx::query(
        "INSERT INTO farms (id, public_key, created_at, creation_policy, max_hubs_per_user, max_hubs_total)
         VALUES (1, ?, ?, 'open', 0, 0)",
    )
    .bind(&pubkey_hex)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    let farm_url = "https://farm.test";
    let hub_manager = Arc::new(HubManager::new("voxply-hub".to_string(), farm_url.to_string()));
    let state = Arc::new(FarmState::new(db, keypair, farm_url.to_string(), hub_manager));
    let app = server::create_router(state.clone());
    (TestServer::new(app), state)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn authenticate(server: &TestServer, _state: &FarmState, identity: &Identity) -> String {
    let pubkey = identity.public_key_hex();
    let cr = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    cr.assert_status_ok();
    let challenge_hex = cr.json::<Value>()["challenge"].as_str().unwrap().to_string();
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let sig_hex = hex::encode(identity.sign(&challenge_bytes).to_bytes());
    let vr = server
        .post("/auth/verify")
        .json(&json!({ "public_key": pubkey, "signature": sig_hex }))
        .await;
    vr.assert_status_ok();
    vr.json::<Value>()["token"].as_str().unwrap().to_string()
}

async fn set_admin(state: &FarmState, pubkey: &str) {
    sqlx::query("UPDATE farms SET admin_pubkey = ? WHERE id = 1")
        .bind(pubkey)
        .execute(&state.db)
        .await
        .unwrap();
}

async fn set_policy(state: &FarmState, policy: &str) {
    sqlx::query("UPDATE farms SET creation_policy = ? WHERE id = 1")
        .bind(policy)
        .execute(&state.db)
        .await
        .unwrap();
}

fn bearer(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {token}")).unwrap()
}

// ---------------------------------------------------------------------------
// GET /farm/settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_settings_requires_admin() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    // Unauthenticated.
    let resp = server.get("/farm/settings").await;
    resp.assert_status_unauthorized();

    // Authenticated but not admin.
    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .get("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "farm_admin_only");
}

#[tokio::test]
async fn get_settings_returns_full_row_for_admin() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .get("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["creation_policy"], "open");
    assert_eq!(body["max_hubs_per_user"], 0);
    assert_eq!(body["max_hubs_total"], 0);
    assert_eq!(body["allow_discovery_listing"], false);
    assert!(body["languages"].is_array());
    assert!(body["tags"].is_array());
}

// ---------------------------------------------------------------------------
// PATCH /farm/settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_settings_requires_admin() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "new name" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_settings_updates_fields() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({
            "name": "Updated Farm",
            "creation_policy": "admin_only",
            "max_hubs_per_user": 3,
            "max_hubs_total": 100,
            "allow_discovery_listing": true,
            "languages": ["it", "en"],
            "tags": ["gaming", "community"]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["name"], "Updated Farm");
    assert_eq!(body["creation_policy"], "admin_only");
    assert_eq!(body["max_hubs_per_user"], 3);
    assert_eq!(body["max_hubs_total"], 100);
    assert_eq!(body["allow_discovery_listing"], true);
    let langs = body["languages"].as_array().unwrap();
    assert!(langs.iter().any(|v| v == "it"));
    let tags = body["tags"].as_array().unwrap();
    assert!(tags.iter().any(|v| v == "gaming"));
}

#[tokio::test]
async fn patch_settings_rejects_invalid_creation_policy() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "creation_policy": "invite_only" }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_value");
}

#[tokio::test]
async fn patch_settings_rejects_unknown_tag() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "tags": ["hacking"] }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_tag");
}

#[tokio::test]
async fn patch_settings_rejects_too_many_tags() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "tags": ["gaming", "creative", "education", "community"] }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_tag");
}

#[tokio::test]
async fn patch_settings_rejects_invalid_language_code() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/settings")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "languages": ["english"] }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_value");
}

// ---------------------------------------------------------------------------
// GET /farm/me/hub-quota
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hub_quota_requires_auth() {
    let (server, _state) = setup().await;
    let resp = server.get("/farm/me/hub-quota").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn hub_quota_returns_unlimited_when_zero() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let token = authenticate(&server, &state, &user).await;

    let resp = server
        .get("/farm/me/hub-quota")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["creation_policy"], "open");
    assert_eq!(body["hubs_owned"], 0);
    assert_eq!(body["max_hubs_per_user"], 0);
    assert!(body["quota_remaining"].is_null());
    assert!(body["farm_quota_remaining"].is_null());
}

#[tokio::test]
async fn hub_quota_reflects_owned_hubs_and_limit() {
    let (server, state) = setup().await;
    let user = Identity::generate();

    // Set per-user limit to 3.
    sqlx::query("UPDATE farms SET max_hubs_per_user = 3 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    // Insert 2 hubs owned by user directly.
    let now = unix_now();
    for i in 0..2u32 {
        sqlx::query(
            "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at)
             VALUES (?, ?, ?, 'private', '/tmp/test.db', ?)",
        )
        .bind(format!("hub{i}"))
        .bind(user.public_key_hex())
        .bind(format!("Hub {i}"))
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();
    }

    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .get("/farm/me/hub-quota")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hubs_owned"], 2);
    assert_eq!(body["max_hubs_per_user"], 3);
    assert_eq!(body["quota_remaining"], 1);
}

// ---------------------------------------------------------------------------
// POST /farm/hubs — creation policy enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_hub_blocked_when_policy_disabled() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    set_policy(&state, "disabled").await;

    // Even the admin is blocked when policy is 'disabled'.
    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .post("/farm/hubs")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "Admin Hub" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "hub_creation_disabled");
}

#[tokio::test]
async fn create_hub_blocked_for_non_admin_when_policy_admin_only() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    let user = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    set_policy(&state, "admin_only").await;

    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .post("/farm/hubs")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "User Hub" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "admin_only");
}

#[tokio::test]
async fn create_hub_allowed_for_admin_when_policy_admin_only() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    set_policy(&state, "admin_only").await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .post("/farm/hubs")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "Admin Hub" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn create_hub_enforces_per_user_quota() {
    let (server, state) = setup().await;
    let user = Identity::generate();

    // Set per-user limit to 1.
    sqlx::query("UPDATE farms SET max_hubs_per_user = 1 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    // Pre-insert a hub for this user.
    let now = unix_now();
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at)
         VALUES ('existinghub', ?, 'Existing Hub', 'private', '/tmp/test.db', ?)",
    )
    .bind(user.public_key_hex())
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .post("/farm/hubs")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "Second Hub" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "user_quota_exceeded");
}

#[tokio::test]
async fn create_hub_enforces_farm_total_quota() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let other = Identity::generate();

    // Set farm-wide limit to 1.
    sqlx::query("UPDATE farms SET max_hubs_total = 1 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    // Pre-insert a hub owned by another user so total is 1.
    let now = unix_now();
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at)
         VALUES ('farmhub', ?, 'Farm Hub', 'public', '/tmp/test.db', ?)",
    )
    .bind(other.public_key_hex())
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .post("/farm/hubs")
        .add_header("Authorization", bearer(&token))
        .json(&json!({ "name": "Over Limit Hub" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "farm_quota_exceeded");
}

// ---------------------------------------------------------------------------
// GET /farm/users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_users_requires_admin() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    // Unauthenticated.
    let resp = server.get("/farm/users").await;
    resp.assert_status_unauthorized();

    // Non-admin.
    let token = authenticate(&server, &state, &user).await;
    let resp = server
        .get("/farm/users")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_users_returns_users_with_counts() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    let user = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    // Authenticate both to seed farm_users.
    let _admin_token = authenticate(&server, &state, &admin).await;
    let _user_token = authenticate(&server, &state, &user).await;

    // Give user a hub.
    let now = unix_now();
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at)
         VALUES ('uh1', ?, 'User Hub', 'private', '/tmp/test.db', ?)",
    )
    .bind(user.public_key_hex())
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let admin_token = authenticate(&server, &state, &admin).await;
    let resp = server
        .get("/farm/users")
        .add_header("Authorization", bearer(&admin_token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let total = body["total"].as_i64().unwrap();
    assert!(total >= 2, "expected at least admin + user, got {total}");
    let users = body["users"].as_array().unwrap();
    let user_entry = users
        .iter()
        .find(|u| u["public_key"] == user.public_key_hex());
    assert!(user_entry.is_some(), "user entry not found in list");
    assert_eq!(user_entry.unwrap()["hubs_owned"], 1);
}

#[tokio::test]
async fn list_users_cursor_pagination() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    // Seed 3 non-admin users.
    let users: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    for u in &users {
        let _ = authenticate(&server, &state, u).await;
    }

    let token = authenticate(&server, &state, &admin).await;

    // Get first page (limit=2).
    let resp = server
        .get("/farm/users?limit=2")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let page1 = body["users"].as_array().unwrap();
    assert_eq!(page1.len(), 2);
    let cursor = page1.last().unwrap()["public_key"].as_str().unwrap().to_string();

    // Get next page using cursor.
    let resp = server
        .get(&format!("/farm/users?limit=10&cursor={cursor}"))
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let page2 = body["users"].as_array().unwrap();
    // All subsequent pubkeys should be > cursor.
    for u in page2 {
        let pk = u["public_key"].as_str().unwrap();
        assert!(pk > cursor.as_str(), "cursor pagination broken: {pk} not > {cursor}");
    }
}

// ---------------------------------------------------------------------------
// POST /farm/users/:pubkey/revoke-sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_sessions_requires_admin() {
    let (server, state) = setup().await;
    let user = Identity::generate();
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let user_token = authenticate(&server, &state, &user).await;
    let resp = server
        .post(&format!("/farm/users/{}/revoke-sessions", user.public_key_hex()))
        .add_header("Authorization", bearer(&user_token))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_sessions_returns_404_for_unknown_user() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .post("/farm/users/deadbeef/revoke-sessions")
        .add_header("Authorization", bearer(&token))
        .await;
    resp.assert_status_not_found();
    assert_eq!(resp.json::<Value>()["error"], "user_not_found");
}

#[tokio::test]
async fn revoke_sessions_marks_active_sessions_revoked() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    let user = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;

    // Authenticate user twice to create 2 sessions.
    let _ = authenticate(&server, &state, &user).await;
    let _ = authenticate(&server, &state, &user).await;

    let admin_token = authenticate(&server, &state, &admin).await;
    let resp = server
        .post(&format!("/farm/users/{}/revoke-sessions", user.public_key_hex()))
        .add_header("Authorization", bearer(&admin_token))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(
        body["revoked"].as_u64().unwrap() >= 2,
        "expected at least 2 revoked, got {:?}",
        body["revoked"]
    );

    // Verify in DB that revoked_at and revoked_manually are set.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM farm_sessions WHERE public_key = ? AND revoked_at IS NOT NULL AND revoked_manually = 1",
    )
    .bind(user.public_key_hex())
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert!(count >= 2, "expected ≥2 manually-revoked rows, got {count}");
}

// ---------------------------------------------------------------------------
// GET /farm/public-info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn public_info_returns_404_when_discovery_disabled() {
    let (server, _state) = setup().await;
    // allow_discovery_listing defaults to 0.
    let resp = server.get("/farm/public-info").await;
    resp.assert_status_not_found();
    assert_eq!(resp.json::<Value>()["error"], "discovery_disabled");
}

#[tokio::test]
async fn public_info_returns_body_when_discovery_enabled() {
    let (server, state) = setup().await;
    sqlx::query(
        "UPDATE farms SET allow_discovery_listing = 1, name = 'Test Farm',
         languages = '[\"it\",\"en\"]', tags = '[\"gaming\"]' WHERE id = 1",
    )
    .execute(&state.db)
    .await
    .unwrap();

    let resp = server.get("/farm/public-info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["kind"], "voxply-farm-public");
    assert_eq!(body["name"], "Test Farm");
    assert_eq!(body["allow_discovery_listing"], true);
    assert_eq!(body["creation_policy"], "open");
    let langs = body["languages"].as_array().unwrap();
    assert!(langs.iter().any(|v| v == "it"));
    let tags = body["tags"].as_array().unwrap();
    assert!(tags.iter().any(|v| v == "gaming"));
    assert!(body["hub_count"].is_number());
}

#[tokio::test]
async fn public_info_does_not_expose_admin_pubkey() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    sqlx::query("UPDATE farms SET allow_discovery_listing = 1 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    let resp = server.get("/farm/public-info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body.get("admin_pubkey").is_none(), "admin_pubkey must not be exposed");
}
