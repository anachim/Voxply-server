/// Integration tests for farm hub management routes.
///
/// Tests exercise:
/// - GET /farm/hubs (unauthenticated, authenticated)
/// - POST /farm/hubs (create hub, validation, auth required)
/// - GET /farm/hubs/:hub_id (single hub)
/// - PATCH /farm/hubs/:hub_id/suspend (admin-only)
/// - DELETE /farm/hubs/:hub_id (admin or owner)
/// - GET /farm/info includes hosted_hubs count
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
    setup_with_farm_url("https://farm.test").await
}

async fn setup_with_farm_url(farm_url: &str) -> (TestServer, Arc<FarmState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Use 'open' policy so existing hub-management tests don't need admin tokens.
    // Policy-enforcement tests live in admin_flow.rs and set their own policy.
    sqlx::query(
        "INSERT INTO farms (id, public_key, created_at, creation_policy)
         VALUES (1, ?, ?, 'open')",
    )
    .bind(&pubkey_hex)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    let hub_manager = Arc::new(HubManager::new(
        "voxply-hub".to_string(),
        farm_url.to_string(),
    ));
    let state = Arc::new(FarmState::new(
        db,
        keypair,
        farm_url.to_string(),
        hub_manager,
    ));
    let app = server::create_router(state.clone());
    (TestServer::new(app), state)
}

/// Perform the full auth flow and return a Bearer token string.
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

/// Set admin_pubkey for the farm singleton row.
async fn set_admin(state: &FarmState, pubkey: &str) {
    sqlx::query("UPDATE farms SET admin_pubkey = ? WHERE id = 1")
        .bind(pubkey)
        .execute(&state.db)
        .await
        .unwrap();
}

/// Insert a hub row directly (bypassing the create endpoint) for setup purposes.
async fn insert_hub(
    state: &FarmState,
    hub_id: &str,
    owner_pubkey: &str,
    name: &str,
    visibility: &str,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(hub_id)
    .bind(owner_pubkey)
    .bind(name)
    .bind(visibility)
    .bind(format!("/tmp/{hub_id}.db"))
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// GET /farm/info — hosted_hubs count
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farm_info_hosted_hubs_zero_on_empty() {
    let (server, _state) = setup().await;
    let resp = server.get("/farm/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hosted_hubs"], 0);
}

#[tokio::test]
async fn farm_info_hosted_hubs_counts_active_only() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hub001", &owner.public_key_hex(), "Hub One", "public").await;
    insert_hub(&state, "hub002", &owner.public_key_hex(), "Hub Two", "public").await;

    // Suspend one.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query("UPDATE hubs SET suspended_at = ? WHERE id = 'hub002'")
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();

    let resp = server.get("/farm/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hosted_hubs"], 1);
}

// ---------------------------------------------------------------------------
// GET /farm/hubs — list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_hubs_unauthenticated_empty_when_directory_private() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hubpub", &owner.public_key_hex(), "Public Hub", "public").await;

    // directory_public defaults to 0.
    let resp = server.get("/farm/hubs").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hubs"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_hubs_unauthenticated_returns_public_when_directory_public() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hubpub", &owner.public_key_hex(), "Public Hub", "public").await;
    insert_hub(&state, "hubprv", &owner.public_key_hex(), "Private Hub", "private").await;

    sqlx::query("UPDATE farms SET directory_public = 1 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    let resp = server.get("/farm/hubs").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let hubs = body["hubs"].as_array().unwrap();
    assert_eq!(hubs.len(), 1);
    assert_eq!(hubs[0]["id"], "hubpub");
    assert!(hubs[0]["hub_url"].as_str().unwrap().contains("hubpub"));
}

#[tokio::test]
async fn list_hubs_authenticated_returns_owned_plus_public() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();

    sqlx::query("UPDATE farms SET directory_public = 1 WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    insert_hub(&state, "hub_owner_pub", &owner.public_key_hex(), "Owner Public", "public").await;
    insert_hub(
        &state,
        "hub_owner_prv",
        &owner.public_key_hex(),
        "Owner Private",
        "private",
    )
    .await;
    insert_hub(
        &state,
        "hub_other_pub",
        &other.public_key_hex(),
        "Other Public",
        "public",
    )
    .await;
    insert_hub(
        &state,
        "hub_other_prv",
        &other.public_key_hex(),
        "Other Private",
        "private",
    )
    .await;

    let token = authenticate(&server, &state, &owner).await;

    let resp = server
        .get("/farm/hubs")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let ids: Vec<&str> = body["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap())
        .collect();

    // Should see: own public, own private, other public — NOT other private.
    assert!(ids.contains(&"hub_owner_pub"), "own public must be in list");
    assert!(ids.contains(&"hub_owner_prv"), "own private must be in list");
    assert!(ids.contains(&"hub_other_pub"), "other public must be in list");
    assert!(!ids.contains(&"hub_other_prv"), "other private must NOT be in list");
}

// ---------------------------------------------------------------------------
// POST /farm/hubs — create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_hub_requires_auth() {
    let (server, _state) = setup().await;
    let resp = server
        .post("/farm/hubs")
        .json(&json!({ "name": "Test Hub" }))
        .await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn create_hub_rejects_empty_name() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &state, &identity).await;

    let resp = server
        .post("/farm/hubs")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({ "name": "" }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_name");
}

#[tokio::test]
async fn create_hub_rejects_name_with_invalid_chars() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &state, &identity).await;

    let resp = server
        .post("/farm/hubs")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({ "name": "Hub@Invalid!" }))
        .await;
    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_name");
}

#[tokio::test]
async fn create_hub_happy_path() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &state, &identity).await;

    let resp = server
        .post("/farm/hubs")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({
            "name": "My Test Hub",
            "description": "A hub for testing",
            "visibility": "public"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    let hub_id = body["id"].as_str().unwrap();
    assert!(!hub_id.is_empty());
    let hub_url = body["hub_url"].as_str().unwrap();
    assert!(
        hub_url.contains(hub_id),
        "hub_url should contain hub_id: {hub_url}"
    );

    // Verify the hub exists in the DB.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE id = ? AND deleted_at IS NULL")
            .bind(hub_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

// ---------------------------------------------------------------------------
// GET /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_hub_returns_correct_info() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hub123", &owner.public_key_hex(), "Test Hub", "public").await;

    let resp = server.get("/farm/hubs/hub123").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], "hub123");
    assert_eq!(body["name"], "Test Hub");
    assert_eq!(body["visibility"], "public");
    assert!(body["hub_url"].as_str().unwrap().contains("hub123"));
}

#[tokio::test]
async fn get_hub_returns_404_for_unknown() {
    let (server, _state) = setup().await;
    let resp = server.get("/farm/hubs/doesnotexist").await;
    resp.assert_status_not_found();
    assert_eq!(resp.json::<Value>()["error"], "hub_not_found");
}

// ---------------------------------------------------------------------------
// PATCH /farm/hubs/:hub_id/suspend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suspend_hub_requires_auth() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hubsus", &owner.public_key_hex(), "Hub", "public").await;

    let resp = server
        .patch("/farm/hubs/hubsus/suspend")
        .json(&json!({}))
        .await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn suspend_hub_requires_admin() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    let non_admin = Identity::generate();

    insert_hub(&state, "hubsus", &owner.public_key_hex(), "Hub", "public").await;
    set_admin(&state, &owner.public_key_hex()).await;

    let token = authenticate(&server, &state, &non_admin).await;
    let resp = server
        .patch("/farm/hubs/hubsus/suspend")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({ "reason": "spam" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["error"], "farm_admin_only");
}

#[tokio::test]
async fn suspend_hub_happy_path() {
    let (server, state) = setup().await;
    let admin = Identity::generate();

    insert_hub(&state, "hubsus", &admin.public_key_hex(), "Hub", "public").await;
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .patch("/farm/hubs/hubsus/suspend")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({ "reason": "testing" }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], "hubsus");
    assert!(body["suspended_at"].is_number());

    // Confirm DB state.
    let suspended: Option<i64> =
        sqlx::query_scalar("SELECT suspended_at FROM hubs WHERE id = 'hubsus'")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(suspended.is_some());
}

#[tokio::test]
async fn suspend_hub_returns_404_for_unknown() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    let token = authenticate(&server, &state, &admin).await;

    let resp = server
        .patch("/farm/hubs/nope/suspend")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({}))
        .await;
    resp.assert_status_not_found();
}

// ---------------------------------------------------------------------------
// DELETE /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_hub_requires_auth() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hubdel", &owner.public_key_hex(), "Hub", "public").await;

    let resp = server.delete("/farm/hubs/hubdel").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn delete_hub_by_owner_succeeds() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    insert_hub(&state, "hubdel", &owner.public_key_hex(), "Hub", "public").await;

    let token = authenticate(&server, &state, &owner).await;
    let resp = server
        .delete("/farm/hubs/hubdel")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Row is tombstoned, not hard deleted.
    let deleted_at: Option<i64> =
        sqlx::query_scalar("SELECT deleted_at FROM hubs WHERE id = 'hubdel'")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(deleted_at.is_some());
}

#[tokio::test]
async fn delete_hub_by_non_owner_non_admin_is_forbidden() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();
    let admin = Identity::generate();

    insert_hub(&state, "hubdel", &owner.public_key_hex(), "Hub", "public").await;
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &other).await;
    let resp = server
        .delete("/farm/hubs/hubdel")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_hub_by_admin_succeeds() {
    let (server, state) = setup().await;
    let owner = Identity::generate();
    let admin = Identity::generate();

    insert_hub(&state, "hubdel2", &owner.public_key_hex(), "Hub", "public").await;
    set_admin(&state, &admin.public_key_hex()).await;

    let token = authenticate(&server, &state, &admin).await;
    let resp = server
        .delete("/farm/hubs/hubdel2")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_hub_returns_404_for_unknown() {
    let (server, state) = setup().await;
    let admin = Identity::generate();
    set_admin(&state, &admin.public_key_hex()).await;
    let token = authenticate(&server, &state, &admin).await;

    let resp = server
        .delete("/farm/hubs/nope")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;
    resp.assert_status_not_found();
}
