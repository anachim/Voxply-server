use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::me::MeResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::{DeviceSubkey, Identity, MasterIdentity, SubkeyCert};

async fn setup() -> (TestServer, SqlitePool) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db: db.clone(),
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: broadcast::channel(16).0,
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
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),    });

    let server = TestServer::new(server::create_router(state));
    (server, db)
}

fn make_cert(master: &MasterIdentity, subkey_pubkey: &str, label: &str) -> SubkeyCert {
    let master_pubkey = master.public_key_hex();
    let issued_at = 1_700_000_000;
    let bytes = SubkeyCert::signing_bytes(
        &master_pubkey,
        subkey_pubkey,
        label,
        issued_at,
        None,
        &[],
    );
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    SubkeyCert {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        device_label: label.to_string(),
        issued_at,
        not_after: None,
        fallback_hubs: vec![],
        signature,
    }
}

async fn auth_with_cert(
    server: &TestServer,
    subkey: &DeviceSubkey,
    cert: Option<&SubkeyCert>,
) -> Result<String, String> {
    let pub_key = subkey.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = subkey.sign(&challenge_bytes);

    let mut body = serde_json::json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });
    if let Some(cert) = cert {
        body["subkey_cert"] = serde_json::to_value(cert).unwrap();
    }

    let resp = server.post("/auth/verify").json(&body).await;
    if !resp.status_code().is_success() {
        return Err(format!("status: {}", resp.status_code()));
    }
    let verify: VerifyResponse = resp.json();
    Ok(verify.token)
}

/// Auth via the legacy single-key flow (existing Identity, no cert).
async fn auth_legacy(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
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
async fn paired_device_auths_and_records_master() {
    let (server, db) = setup().await;
    let master = Identity::generate().master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let cert = make_cert(&master, &phone.public_key_hex(), "phone");

    let token = auth_with_cert(&server, &phone, Some(&cert))
        .await
        .expect("auth should succeed");
    assert!(!token.is_empty());

    // /me should return the master pubkey as the canonical identity,
    // not the subkey pubkey.
    let resp = server
        .get("/me")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, master.public_key_hex());

    // The user row records the master.
    let stored_master: Option<String> = sqlx::query_scalar(
        "SELECT master_pubkey FROM users WHERE public_key = ?",
    )
    .bind(master.public_key_hex())
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(stored_master, Some(master.public_key_hex()));
}

#[tokio::test]
async fn second_paired_device_finds_existing_user() {
    let (server, db) = setup().await;
    let master = Identity::generate().master().unwrap();

    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&master, &phone.public_key_hex(), "phone");
    auth_with_cert(&server, &phone, Some(&phone_cert))
        .await
        .expect("phone auth");

    // Second device, same master. Should NOT create a new user row.
    let desktop = DeviceSubkey::generate("desktop".into());
    let desktop_cert = make_cert(&master, &desktop.public_key_hex(), "desktop");
    let token = auth_with_cert(&server, &desktop, Some(&desktop_cert))
        .await
        .expect("desktop auth");

    // Both devices see themselves as the same canonical user.
    let resp = server
        .get("/me")
        .authorization_bearer(&token)
        .await;
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, master.public_key_hex());

    let user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE master_pubkey = ?",
    )
    .bind(master.public_key_hex())
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(user_count, 1);
}

#[tokio::test]
async fn legacy_user_upgrade_preserves_canonical_pubkey() {
    let (server, db) = setup().await;

    // Alice exists as a legacy single-key user.
    let alice = Identity::generate();
    auth_legacy(&server, &alice).await;
    let alice_pubkey = alice.public_key_hex();

    // Alice now has a master derived from her phrase and presents
    // a cert for her existing key (subkey 0 = legacy pubkey).
    let alice_master = alice.master().unwrap();
    let subkey_zero = alice.as_subkey_zero("desktop".into());
    let cert = make_cert(&alice_master, &alice_pubkey, "desktop");
    auth_with_cert(&server, &subkey_zero, Some(&cert))
        .await
        .expect("upgrade auth");

    // The canonical pubkey is still Alice's legacy pubkey — her
    // existing role assignments and memberships are intact.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(user_count, 1);

    let stored_master: Option<String> = sqlx::query_scalar(
        "SELECT master_pubkey FROM users WHERE public_key = ?",
    )
    .bind(&alice_pubkey)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(stored_master, Some(alice_master.public_key_hex()));
}

#[tokio::test]
async fn cert_with_subkey_pubkey_mismatch_is_rejected() {
    let (server, _db) = setup().await;
    let master = Identity::generate().master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    // Cert references a different subkey than the one auth'ing.
    let other_subkey = DeviceSubkey::generate("other".into());
    let cert = make_cert(&master, &other_subkey.public_key_hex(), "phone");

    let result = auth_with_cert(&server, &phone, Some(&cert)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn legacy_auth_still_works_unchanged() {
    let (server, db) = setup().await;

    let alice = Identity::generate();
    let token = auth_legacy(&server, &alice).await;
    assert!(!token.is_empty());

    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, alice.public_key_hex());

    let stored_master: Option<String> = sqlx::query_scalar(
        "SELECT master_pubkey FROM users WHERE public_key = ?",
    )
    .bind(alice.public_key_hex())
    .fetch_one(&db)
    .await
    .unwrap();
    // Legacy users have NULL master_pubkey until they upgrade.
    assert_eq!(stored_master, None);
}

#[tokio::test]
async fn master_hijack_attempt_is_blocked_by_coalesce() {
    // Even if a malicious second user's cert claims a master that
    // happens to equal someone else's public_key (legacy collision),
    // COALESCE(users.master_pubkey, ...) preserves whatever was there
    // first. Real-world this is statistically impossible with 256-bit
    // keys, but the defensive logic is worth a regression test.
    let (server, db) = setup().await;

    let alice = Identity::generate();
    auth_legacy(&server, &alice).await;
    let alice_pubkey = alice.public_key_hex();

    // First multi-device user (Bob) with master = Alice's pubkey (forced).
    // We can't actually craft this because Bob can't sign a cert
    // claiming a master he doesn't own. Test the next-best thing:
    // a paired device for Bob completes auth and Alice's row is
    // untouched.
    let bob_master = Identity::generate().master().unwrap();
    let bob_phone = DeviceSubkey::generate("phone".into());
    let bob_cert = make_cert(&bob_master, &bob_phone.public_key_hex(), "phone");
    auth_with_cert(&server, &bob_phone, Some(&bob_cert))
        .await
        .expect("bob auth");

    // Alice's row should still have NULL master.
    let alice_master_value: Option<String> = sqlx::query_scalar(
        "SELECT master_pubkey FROM users WHERE public_key = ?",
    )
    .bind(&alice_pubkey)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(alice_master_value, None);

    // Two distinct rows exist.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(user_count, 2);
}

// ---------------------------------------------------------------------------
// Revocation enforcement in the HTTP auth middleware
// ---------------------------------------------------------------------------

/// Insert a revocation row directly into the DB, bypassing signature checks.
/// The middleware only checks the presence of the row; signature verification
/// lives in the identity route that accepts the POST.
async fn insert_revocation(db: &SqlitePool, subkey_pubkey: &str) {
    sqlx::query(
        "INSERT OR IGNORE INTO subkey_revocations
         (master_pubkey, subkey_pubkey, revoked_at, signature, registered_at)
         VALUES ('test-master', ?, 1, 'test-sig', 1)",
    )
    .bind(subkey_pubkey)
    .execute(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn revoked_key_is_rejected_by_middleware() {
    let (server, db) = setup().await;

    // Alice authenticates normally.
    let alice = Identity::generate();
    let token = auth_legacy(&server, &alice).await;

    // /me works before revocation.
    server
        .get("/me")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();

    // Revoke Alice's key.
    insert_revocation(&db, &alice.public_key_hex()).await;

    // Existing token is now rejected — 401 with the revocation message.
    let resp = server
        .get("/me")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_unauthorized();
    assert!(resp.text().contains("revoked"));
}

#[tokio::test]
async fn non_revoked_key_is_not_affected() {
    let (server, db) = setup().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = auth_legacy(&server, &alice).await;
    let bob_token = auth_legacy(&server, &bob).await;

    // Only Bob's key is revoked.
    insert_revocation(&db, &bob.public_key_hex()).await;

    // Alice is unaffected.
    server
        .get("/me")
        .authorization_bearer(&alice_token)
        .await
        .assert_status_ok();

    // Bob is rejected.
    server
        .get("/me")
        .authorization_bearer(&bob_token)
        .await
        .assert_status_unauthorized();
}
