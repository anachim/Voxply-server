/// Integration tests for the seed discovery service.
///
/// Tests:
/// - GET /info returns role: "discovery"
/// - GET /farms returns empty list initially
/// - POST /farms/register validates body fields
/// - DELETE /farms/register verifies Ed25519 signature and rejects wrong signatures
/// - GET /farms filters by country, region, language, tag
/// - Stale flag appears for entries older than 24 hours
///
/// The registration flow calls back to `{farm_url}/farm/public-info`. Tests that
/// exercise registration use direct DB inserts to bypass the HTTP callback, then
/// test the listing and deregistration paths independently. The signature
/// verification path is tested separately.
use std::sync::Arc;

use axum_test::TestServer;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use voxply_seed::db;
use voxply_seed::server;
use voxply_seed::state::SeedState;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> (TestServer, Arc<SeedState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let state = Arc::new(SeedState::new(db));
    let app = server::create_router(state.clone());
    (TestServer::new(app), state)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Insert a farm row directly into the DB, bypassing the HTTP callback.
async fn insert_farm(
    state: &SeedState,
    farm_url: &str,
    farm_pubkey: &str,
    name: &str,
    hub_count: i64,
    max_hubs_total: Option<i64>,
    country: Option<&str>,
    region: Option<&str>,
    languages: &str,
    tags: &str,
    last_verified_at: i64,
) {
    let capacity_pct: Option<i64> = max_hubs_total.and_then(|cap| {
        if cap <= 0 {
            None
        } else {
            Some(((hub_count * 100) / cap).min(100))
        }
    });
    let now = unix_now();
    sqlx::query(
        "INSERT INTO registered_farms
            (farm_url, farm_pubkey, name, hub_count, max_hubs_total, capacity_pct,
             country, region, languages, tags, geo_unverified,
             last_verified_at, registered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(farm_url)
    .bind(farm_pubkey)
    .bind(name)
    .bind(hub_count)
    .bind(max_hubs_total)
    .bind(capacity_pct)
    .bind(country)
    .bind(region)
    .bind(languages)
    .bind(tags)
    .bind(last_verified_at)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// GET /info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_returns_discovery_role() {
    let (server, _state) = setup().await;

    let resp = server.get("/info").await;
    resp.assert_status_ok();

    let body = resp.json::<Value>();
    assert_eq!(body["kind"], "voxply-seed");
    assert_eq!(body["role"], "discovery");
}

// ---------------------------------------------------------------------------
// GET /farms — empty list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_empty_list() {
    let (server, _state) = setup().await;

    let resp = server.get("/farms").await;
    resp.assert_status_ok();

    let body = resp.json::<Value>();
    assert_eq!(body["farms"].as_array().unwrap().len(), 0);
    assert!(body["generated_at"].as_i64().is_some());
}

// ---------------------------------------------------------------------------
// GET /farms — basic listing with inserted rows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_lists_registered_entries() {
    let (server, state) = setup().await;
    let now = unix_now();

    insert_farm(
        &state,
        "https://farm-a.test",
        &"aa".repeat(32),
        "Farm A",
        5,
        Some(100),
        Some("IT"),
        Some("EU-West"),
        r#"["it","en"]"#,
        r#"["gaming"]"#,
        now,
    )
    .await;

    insert_farm(
        &state,
        "https://farm-b.test",
        &"bb".repeat(32),
        "Farm B",
        20,
        None, // unlimited
        Some("US"),
        Some("US-East"),
        r#"["en"]"#,
        r#"[]"#,
        now,
    )
    .await;

    let resp = server.get("/farms").await;
    resp.assert_status_ok();

    let body = resp.json::<Value>();
    let farms = body["farms"].as_array().unwrap();
    assert_eq!(farms.len(), 2);

    // Farm A has a capacity_pct (max_hubs_total is set).
    let farm_a = farms.iter().find(|f| f["farm_url"] == "https://farm-a.test").unwrap();
    assert_eq!(farm_a["hub_count"], 5);
    assert!(farm_a["capacity_pct"].as_i64().is_some());
    assert_eq!(farm_a["country"], "IT");
    assert_eq!(farm_a["region"], "EU-West");
    assert_eq!(farm_a["geo_unverified"], false);
    assert!(farm_a["stale"].is_null(), "should not be stale");

    // Farm B has unlimited cap — capacity_pct is omitted.
    let farm_b = farms.iter().find(|f| f["farm_url"] == "https://farm-b.test").unwrap();
    assert!(farm_b["capacity_pct"].is_null());
}

// ---------------------------------------------------------------------------
// GET /farms — filter by country
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_filter_by_country() {
    let (server, state) = setup().await;
    let now = unix_now();

    insert_farm(
        &state, "https://farm-it.test", &"aa".repeat(32), "IT Farm",
        0, None, Some("IT"), Some("EU-West"), r#"["en"]"#, r#"[]"#, now,
    ).await;
    insert_farm(
        &state, "https://farm-us.test", &"bb".repeat(32), "US Farm",
        0, None, Some("US"), Some("US-East"), r#"["en"]"#, r#"[]"#, now,
    ).await;

    let resp = server.get("/farms?country=IT").await;
    resp.assert_status_ok();

    let body = resp.json::<Value>();
    let farms = body["farms"].as_array().unwrap();
    assert_eq!(farms.len(), 1);
    assert_eq!(farms[0]["farm_url"], "https://farm-it.test");
}

// ---------------------------------------------------------------------------
// GET /farms — filter by region
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_filter_by_region() {
    let (server, state) = setup().await;
    let now = unix_now();

    insert_farm(
        &state, "https://farm-eu.test", &"aa".repeat(32), "EU Farm",
        0, None, Some("IT"), Some("EU-West"), r#"["en"]"#, r#"[]"#, now,
    ).await;
    insert_farm(
        &state, "https://farm-apac.test", &"bb".repeat(32), "APAC Farm",
        0, None, Some("JP"), Some("APAC"), r#"["ja"]"#, r#"[]"#, now,
    ).await;

    let resp = server.get("/farms?region=EU-West").await;
    resp.assert_status_ok();

    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert_eq!(farms.len(), 1);
    assert_eq!(farms[0]["farm_url"], "https://farm-eu.test");
}

// ---------------------------------------------------------------------------
// GET /farms — filter by language
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_filter_by_language() {
    let (server, state) = setup().await;
    let now = unix_now();

    insert_farm(
        &state, "https://farm-it.test", &"aa".repeat(32), "Italian Farm",
        0, None, None, None, r#"["it","en"]"#, r#"[]"#, now,
    ).await;
    insert_farm(
        &state, "https://farm-de.test", &"bb".repeat(32), "German Farm",
        0, None, None, None, r#"["de"]"#, r#"[]"#, now,
    ).await;

    let resp = server.get("/farms?language=it").await;
    resp.assert_status_ok();

    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert_eq!(farms.len(), 1);
    assert_eq!(farms[0]["farm_url"], "https://farm-it.test");
}

// ---------------------------------------------------------------------------
// GET /farms — filter by tag (AND logic for multiple ?tag= params)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_filter_by_tag_and_logic() {
    let (server, state) = setup().await;
    let now = unix_now();

    // Farm with gaming+community
    insert_farm(
        &state, "https://farm-gc.test", &"aa".repeat(32), "Gaming+Community",
        0, None, None, None, r#"["en"]"#, r#"["gaming","community"]"#, now,
    ).await;
    // Farm with gaming only
    insert_farm(
        &state, "https://farm-g.test", &"bb".repeat(32), "Gaming Only",
        0, None, None, None, r#"["en"]"#, r#"["gaming"]"#, now,
    ).await;
    // Farm with no tags
    insert_farm(
        &state, "https://farm-none.test", &"cc".repeat(32), "No Tags",
        0, None, None, None, r#"["en"]"#, r#"[]"#, now,
    ).await;

    // ?tag=gaming should return both gaming farms
    let resp = server.get("/farms?tag=gaming").await;
    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert_eq!(farms.len(), 2);

    // ?tag=gaming&tag=community should return only the one with both
    let resp = server.get("/farms?tag=gaming&tag=community").await;
    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert_eq!(farms.len(), 1);
    assert_eq!(farms[0]["farm_url"], "https://farm-gc.test");
}

// ---------------------------------------------------------------------------
// GET /farms — stale flag for entries older than 24h
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_stale_flag() {
    let (server, state) = setup().await;

    let now = unix_now();
    let stale_time = now - 90000; // 25 hours ago

    insert_farm(
        &state, "https://farm-fresh.test", &"aa".repeat(32), "Fresh Farm",
        0, None, None, None, r#"["en"]"#, r#"[]"#, now,
    ).await;
    insert_farm(
        &state, "https://farm-stale.test", &"bb".repeat(32), "Stale Farm",
        0, None, None, None, r#"["en"]"#, r#"[]"#, stale_time,
    ).await;

    let resp = server.get("/farms").await;
    resp.assert_status_ok();

    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();

    let fresh = farms.iter().find(|f| f["farm_url"] == "https://farm-fresh.test").unwrap();
    assert!(fresh["stale"].is_null(), "fresh farm should not be stale");

    let stale = farms.iter().find(|f| f["farm_url"] == "https://farm-stale.test").unwrap();
    assert_eq!(stale["stale"], true, "old farm should be stale");
}

// ---------------------------------------------------------------------------
// POST /farms/register — validation rejections (no HTTP callback needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_rejects_missing_farm_url() {
    let (server, _state) = setup().await;

    let resp = server
        .post("/farms/register")
        .json(&json!({
            "farm_url": "",
            "farm_pubkey": "a".repeat(64),
            "name": "Test Farm",
            "signed_nonce": "deadbeef"
        }))
        .await;

    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "missing_farm_url");
}

#[tokio::test]
async fn register_rejects_invalid_pubkey_length() {
    let (server, _state) = setup().await;

    let resp = server
        .post("/farms/register")
        .json(&json!({
            "farm_url": "https://farm.test",
            "farm_pubkey": "short",
            "name": "Test Farm",
            "signed_nonce": "deadbeef"
        }))
        .await;

    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "invalid_farm_pubkey");
}

#[tokio::test]
async fn register_rejects_empty_name() {
    let (server, _state) = setup().await;

    let resp = server
        .post("/farms/register")
        .json(&json!({
            "farm_url": "https://farm.test",
            "farm_pubkey": "a".repeat(64),
            "name": "   ",
            "signed_nonce": "deadbeef"
        }))
        .await;

    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["error"], "missing_name");
}

// ---------------------------------------------------------------------------
// DELETE /farms/register — Ed25519 signature verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deregister_rejects_invalid_signature() {
    let (server, state) = setup().await;
    let now = unix_now();

    let keypair = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());

    insert_farm(
        &state,
        "https://farm-del.test",
        &pubkey_hex,
        "Del Farm",
        0,
        None,
        None,
        None,
        r#"["en"]"#,
        r#"[]"#,
        now,
    )
    .await;

    // Wrong signature (all zeros).
    let resp = server
        .delete("/farms/register")
        .json(&json!({
            "farm_url": "https://farm-del.test",
            "farm_pubkey": pubkey_hex,
            "nonce": "deadbeefdeadbeef",
            "signature": "00".repeat(64)
        }))
        .await;

    resp.assert_status_bad_request();
    let error = resp.json::<Value>()["error"].as_str().unwrap().to_string();
    assert!(
        error == "signature_mismatch" || error == "invalid_pubkey_hex" || error == "invalid_signature_length",
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn deregister_with_valid_signature_removes_farm() {
    let (server, state) = setup().await;
    let now = unix_now();

    let keypair = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());

    insert_farm(
        &state,
        "https://farm-del2.test",
        &pubkey_hex,
        "Del Farm 2",
        0,
        None,
        None,
        None,
        r#"["en"]"#,
        r#"[]"#,
        now,
    )
    .await;

    // Build a valid signature over pubkey_bytes || nonce_bytes.
    let nonce_hex = "cafebabe12345678";
    let pubkey_bytes = hex::decode(&pubkey_hex).unwrap();
    let nonce_bytes = hex::decode(nonce_hex).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(&pubkey_bytes);
    message.extend_from_slice(&nonce_bytes);
    let sig = keypair.sign(&message);
    let sig_hex = hex::encode(sig.to_bytes());

    let resp = server
        .delete("/farms/register")
        .json(&json!({
            "farm_url": "https://farm-del2.test",
            "farm_pubkey": pubkey_hex,
            "nonce": nonce_hex,
            "signature": sig_hex
        }))
        .await;

    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["deregistered"], true);

    // Confirm it's gone.
    let list_resp = server.get("/farms").await;
    let farms = list_resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert!(!farms.iter().any(|f| f["farm_url"] == "https://farm-del2.test"));
}

#[tokio::test]
async fn deregister_returns_404_for_unknown_farm() {
    let (server, _state) = setup().await;

    let keypair = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());

    let nonce_hex = "deadbeefdeadbeef";
    let pubkey_bytes = hex::decode(&pubkey_hex).unwrap();
    let nonce_bytes = hex::decode(nonce_hex).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(&pubkey_bytes);
    message.extend_from_slice(&nonce_bytes);
    let sig = keypair.sign(&message);

    let resp = server
        .delete("/farms/register")
        .json(&json!({
            "farm_url": "https://notlisted.test",
            "farm_pubkey": pubkey_hex,
            "nonce": nonce_hex,
            "signature": hex::encode(sig.to_bytes())
        }))
        .await;

    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    assert_eq!(resp.json::<Value>()["error"], "not_listed");
}

// ---------------------------------------------------------------------------
// GET /farms — combined country+language filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farms_filter_combined_country_and_language() {
    let (server, state) = setup().await;
    let now = unix_now();

    // IT farm with Italian
    insert_farm(
        &state, "https://farm-it-it.test", &"aa".repeat(32), "IT Italian",
        0, None, Some("IT"), Some("EU-West"), r#"["it","en"]"#, r#"[]"#, now,
    ).await;
    // IT farm with English only
    insert_farm(
        &state, "https://farm-it-en.test", &"bb".repeat(32), "IT English",
        0, None, Some("IT"), Some("EU-West"), r#"["en"]"#, r#"[]"#, now,
    ).await;
    // US farm with English
    insert_farm(
        &state, "https://farm-us-en.test", &"cc".repeat(32), "US English",
        0, None, Some("US"), Some("US-East"), r#"["en"]"#, r#"[]"#, now,
    ).await;

    let resp = server.get("/farms?country=IT&language=it").await;
    resp.assert_status_ok();

    let farms = resp.json::<Value>()["farms"].as_array().unwrap().to_vec();
    assert_eq!(farms.len(), 1);
    assert_eq!(farms[0]["farm_url"], "https://farm-it-it.test");
}
