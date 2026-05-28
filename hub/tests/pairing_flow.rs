use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum_test::TestServer;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::{
    DeviceSubkey, Identity, MasterIdentity, PairingClaim, PairingComplete, PairingOffer,
    PairingStatus, SubkeyCert,
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn make_offer(master: &MasterIdentity, token: &str, lifetime_secs: u64) -> PairingOffer {
    let master_pubkey = master.public_key_hex();
    let home_hubs = vec!["https://a.example".to_string()];
    let issued_at = now();
    let expires_at = issued_at + lifetime_secs;
    let bytes = PairingOffer::signing_bytes(
        &master_pubkey,
        &home_hubs,
        token,
        issued_at,
        expires_at,
    );
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    PairingOffer {
        master_pubkey,
        home_hubs,
        pairing_token: token.to_string(),
        issued_at,
        expires_at,
        signature,
    }
}

fn make_claim(subkey: &DeviceSubkey, token: &str, label: &str) -> PairingClaim {
    let bytes = PairingClaim::signing_bytes(token, &subkey.public_key_hex(), label);
    let proof = hex::encode(subkey.sign(&bytes).to_bytes());
    PairingClaim {
        pairing_token: token.to_string(),
        subkey_pubkey: subkey.public_key_hex(),
        device_label: label.to_string(),
        proof,
    }
}

fn make_cert(master: &MasterIdentity, subkey_pubkey: &str, label: &str) -> SubkeyCert {
    let master_pubkey = master.public_key_hex();
    let issued_at = now();
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

#[tokio::test]
async fn full_pairing_handshake() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();

    let offer = make_offer(&master, &token, 60);
    server
        .post("/identity/pairing/offer")
        .json(&offer)
        .await
        .assert_status_ok();

    // Status: pending
    let resp = server
        .get(&format!("/identity/pairing/status/{token}"))
        .await;
    resp.assert_status_ok();
    let status: PairingStatus = resp.json();
    assert!(matches!(status, PairingStatus::Pending));

    // New device claims
    let phone = DeviceSubkey::generate("phone".into());
    let claim = make_claim(&phone, &token, "phone");
    server
        .post("/identity/pairing/claim")
        .json(&claim)
        .await
        .assert_status_ok();

    // Status: claimed
    let resp = server
        .get(&format!("/identity/pairing/status/{token}"))
        .await;
    let status: PairingStatus = resp.json();
    match status {
        PairingStatus::Claimed { subkey_pubkey, device_label } => {
            assert_eq!(subkey_pubkey, phone.public_key_hex());
            assert_eq!(device_label, "phone");
        }
        other => panic!("expected Claimed, got {other:?}"),
    }

    // Existing device completes
    let cert = make_cert(&master, &phone.public_key_hex(), "phone");
    let complete = PairingComplete {
        pairing_token: token.clone(),
        cert: cert.clone(),
        wrapped_blob_key_hex: "deadbeef".to_string(),
    };
    server
        .post("/identity/pairing/complete")
        .json(&complete)
        .await
        .assert_status_ok();

    // Status: complete, with cert + wrapped key
    let resp = server
        .get(&format!("/identity/pairing/status/{token}"))
        .await;
    let status: PairingStatus = resp.json();
    match status {
        PairingStatus::Complete { cert: returned_cert, wrapped_blob_key_hex } => {
            assert_eq!(returned_cert.subkey_pubkey, phone.public_key_hex());
            assert!(returned_cert.verify().is_ok());
            assert_eq!(wrapped_blob_key_hex, "deadbeef");
        }
        other => panic!("expected Complete, got {other:?}"),
    }

    // Cert is also in the device registry now
    let resp = server
        .get(&format!("/identity/{}/devices", master.public_key_hex()))
        .await;
    resp.assert_status_ok();
    let certs: Vec<SubkeyCert> = resp.json();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subkey_pubkey, phone.public_key_hex());
}

#[tokio::test]
async fn offer_rejects_bad_signature() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();

    let mut offer = make_offer(&master, &token, 60);
    offer.home_hubs.push("https://attacker.example".to_string()); // tamper post-sign

    let resp = server.post("/identity/pairing/offer").json(&offer).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn offer_rejects_lifetime_over_5_minutes() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();

    let offer = make_offer(&master, &token, 600); // 10 minutes
    let resp = server.post("/identity/pairing/offer").json(&offer).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn claim_rejects_unknown_token() {
    let server = setup().await;
    let phone = DeviceSubkey::generate("phone".into());
    let claim = make_claim(&phone, &random_token(), "phone");
    let resp = server.post("/identity/pairing/claim").json(&claim).await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn claim_rejects_bad_proof() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();
    server
        .post("/identity/pairing/offer")
        .json(&make_offer(&master, &token, 60))
        .await
        .assert_status_ok();

    let phone = DeviceSubkey::generate("phone".into());
    let mut claim = make_claim(&phone, &token, "phone");
    claim.device_label = "tampered".to_string(); // proof was over original label

    let resp = server.post("/identity/pairing/claim").json(&claim).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn double_claim_is_rejected() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();
    server
        .post("/identity/pairing/offer")
        .json(&make_offer(&master, &token, 60))
        .await
        .assert_status_ok();

    let phone = DeviceSubkey::generate("phone".into());
    server
        .post("/identity/pairing/claim")
        .json(&make_claim(&phone, &token, "phone"))
        .await
        .assert_status_ok();

    let other = DeviceSubkey::generate("evil".into());
    let resp = server
        .post("/identity/pairing/claim")
        .json(&make_claim(&other, &token, "evil"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn complete_before_claim_is_rejected() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();
    server
        .post("/identity/pairing/offer")
        .json(&make_offer(&master, &token, 60))
        .await
        .assert_status_ok();

    let phone = DeviceSubkey::generate("phone".into());
    let cert = make_cert(&master, &phone.public_key_hex(), "phone");
    let complete = PairingComplete {
        pairing_token: token,
        cert,
        wrapped_blob_key_hex: "deadbeef".into(),
    };

    let resp = server.post("/identity/pairing/complete").json(&complete).await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn complete_rejects_subkey_mismatch() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let token = random_token();
    server
        .post("/identity/pairing/offer")
        .json(&make_offer(&master, &token, 60))
        .await
        .assert_status_ok();

    let phone = DeviceSubkey::generate("phone".into());
    server
        .post("/identity/pairing/claim")
        .json(&make_claim(&phone, &token, "phone"))
        .await
        .assert_status_ok();

    // Cert for a *different* subkey than the one that claimed
    let imposter = DeviceSubkey::generate("imposter".into());
    let cert = make_cert(&master, &imposter.public_key_hex(), "phone");
    let complete = PairingComplete {
        pairing_token: token,
        cert,
        wrapped_blob_key_hex: "deadbeef".into(),
    };

    let resp = server.post("/identity/pairing/complete").json(&complete).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn complete_rejects_master_mismatch() {
    let server = setup().await;
    let master = Identity::generate().master().unwrap();
    let other_master = Identity::generate().master().unwrap();
    let token = random_token();

    server
        .post("/identity/pairing/offer")
        .json(&make_offer(&master, &token, 60))
        .await
        .assert_status_ok();

    let phone = DeviceSubkey::generate("phone".into());
    server
        .post("/identity/pairing/claim")
        .json(&make_claim(&phone, &token, "phone"))
        .await
        .assert_status_ok();

    // Cert signed by a different master
    let cert = make_cert(&other_master, &phone.public_key_hex(), "phone");
    let complete = PairingComplete {
        pairing_token: token,
        cert,
        wrapped_blob_key_hex: "deadbeef".into(),
    };

    let resp = server.post("/identity/pairing/complete").json(&complete).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}
