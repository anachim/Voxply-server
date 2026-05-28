use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::{
    DeviceSubkey, HomeHubList, Identity, RevocationEntry, SignedPrefsBlob, SubkeyCert,
};

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
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

    TestServer::new(server::create_router(state))
}

fn signed_designation(
    master: &voxply_identity::MasterIdentity,
    hubs: Vec<String>,
    issued_at: u64,
    sequence: u64,
) -> HomeHubList {
    let master_pubkey = master.public_key_hex();
    let bytes = HomeHubList::signing_bytes(&master_pubkey, &hubs, issued_at, sequence);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    HomeHubList { master_pubkey, hubs, issued_at, sequence, signature }
}

fn signed_cert(
    master: &voxply_identity::MasterIdentity,
    subkey_pubkey: &str,
    label: &str,
    issued_at: u64,
) -> SubkeyCert {
    let master_pubkey = master.public_key_hex();
    let bytes = SubkeyCert::signing_bytes(&master_pubkey, subkey_pubkey, label, issued_at, None, &[]);
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

fn signed_revocation(
    master: &voxply_identity::MasterIdentity,
    subkey_pubkey: &str,
    revoked_at: u64,
) -> RevocationEntry {
    let master_pubkey = master.public_key_hex();
    let bytes = RevocationEntry::signing_bytes(&master_pubkey, subkey_pubkey, revoked_at);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    RevocationEntry {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        revoked_at,
        signature,
    }
}

fn signed_prefs(
    master: &voxply_identity::MasterIdentity,
    blob_version: u64,
    ciphertext: &[u8],
) -> SignedPrefsBlob {
    let master_pubkey = master.public_key_hex();
    let bytes = SignedPrefsBlob::signing_bytes(&master_pubkey, blob_version, ciphertext);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    SignedPrefsBlob {
        master_pubkey,
        blob_version,
        ciphertext_hex: hex::encode(ciphertext),
        signature,
    }
}

#[tokio::test]
async fn designation_roundtrip() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let designation = signed_designation(
        &master,
        vec!["https://a.example".into(), "https://b.example".into()],
        1_700_000_000,
        1,
    );

    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&designation)
        .await;
    resp.assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/designation"))
        .await;
    resp.assert_status_ok();
    let got: HomeHubList = resp.json();
    assert_eq!(got.hubs, designation.hubs);
    assert_eq!(got.sequence, 1);
    assert!(got.verify().is_ok());
}

#[tokio::test]
async fn designation_rejects_stale_sequence() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let d1 = signed_designation(&master, vec!["https://a.example".into()], 1, 5);
    server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d1)
        .await
        .assert_status_ok();

    // Same sequence should be rejected
    let d2 = signed_designation(&master, vec!["https://b.example".into()], 2, 5);
    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d2)
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn designation_rejects_url_body_mismatch() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let other = Identity::generate().master().unwrap();

    let d = signed_designation(&master, vec!["https://a.example".into()], 1, 1);
    let resp = server
        .post(&format!("/identity/{}/designation", other.public_key_hex()))
        .json(&d)
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn designation_rejects_bad_signature() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let mut d = signed_designation(&master, vec!["https://a.example".into()], 1, 1);
    d.hubs.push("https://attacker.example".into()); // tamper post-sign
    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d)
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn devices_post_and_list() {
    let server = setup().await;
    let identity = Identity::generate();
    let master = identity.master().unwrap();
    let master_pubkey = master.public_key_hex();

    let subkey_zero = identity.as_subkey_zero("desktop".into());
    let phone = DeviceSubkey::generate("phone".into());

    let cert0 = signed_cert(&master, &subkey_zero.public_key_hex(), "desktop", 1);
    let cert1 = signed_cert(&master, &phone.public_key_hex(), "phone", 2);

    server
        .post(&format!("/identity/{master_pubkey}/devices"))
        .json(&cert0)
        .await
        .assert_status_ok();
    server
        .post(&format!("/identity/{master_pubkey}/devices"))
        .json(&cert1)
        .await
        .assert_status_ok();

    let resp = server.get(&format!("/identity/{master_pubkey}/devices")).await;
    resp.assert_status_ok();
    let certs: Vec<SubkeyCert> = resp.json();
    assert_eq!(certs.len(), 2);
    assert!(certs.iter().all(|c| c.verify().is_ok()));
    assert!(certs.iter().any(|c| c.device_label == "phone"));
}

#[tokio::test]
async fn revocation_post_and_list() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let compromised = DeviceSubkey::generate("phone".into()).public_key_hex();
    let entry = signed_revocation(&master, &compromised, 42);

    server
        .post(&format!("/identity/{master_pubkey}/revocations"))
        .json(&entry)
        .await
        .assert_status_ok();

    // Idempotent re-post is OK.
    server
        .post(&format!("/identity/{master_pubkey}/revocations"))
        .json(&entry)
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/revocations"))
        .await;
    resp.assert_status_ok();
    let entries: Vec<RevocationEntry> = resp.json();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].verify().is_ok());
}

#[tokio::test]
async fn prefs_blob_roundtrip_with_version_check() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let v1 = signed_prefs(&master, 1, b"first version");
    server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&v1)
        .await
        .assert_status_ok();

    let resp = server.get(&format!("/identity/{master_pubkey}/prefs")).await;
    resp.assert_status_ok();
    let got: SignedPrefsBlob = resp.json();
    assert_eq!(got.blob_version, 1);
    assert!(got.verify().is_ok());

    // Stale version is rejected.
    let stale = signed_prefs(&master, 1, b"replay attempt");
    let resp = server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&stale)
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);

    // Newer version is accepted.
    let v2 = signed_prefs(&master, 2, b"second version");
    server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&v2)
        .await
        .assert_status_ok();

    let resp = server.get(&format!("/identity/{master_pubkey}/prefs")).await;
    let got: SignedPrefsBlob = resp.json();
    assert_eq!(got.blob_version, 2);
}

#[tokio::test]
async fn empty_resources_return_404_or_empty() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/designation"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    let resp = server.get(&format!("/identity/{master_pubkey}/prefs")).await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    let resp = server.get(&format!("/identity/{master_pubkey}/devices")).await;
    resp.assert_status_ok();
    let v: Vec<SubkeyCert> = resp.json();
    assert!(v.is_empty());

    let resp = server
        .get(&format!("/identity/{master_pubkey}/revocations"))
        .await;
    resp.assert_status_ok();
    let v: Vec<RevocationEntry> = resp.json();
    assert!(v.is_empty());
}
