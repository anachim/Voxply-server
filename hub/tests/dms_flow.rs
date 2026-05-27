use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::dm_models::ConversationResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup() -> TestServer {
    let (server, _pool) = setup_with_pool().await;
    server
}

/// Same as setup() but also returns the SqlitePool so tests can poke the
/// database directly (e.g. to mark a dm_outbox row as bounced for a test
/// that exercises the delivery_failed reporting path).
async fn setup_with_pool() -> (TestServer, sqlx::SqlitePool) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let pool_handle = db.clone();
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
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
    });
    let app = server::create_router(state);
    (TestServer::new(app), pool_handle)
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

#[tokio::test]
async fn create_dm_conversation() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert_eq!(conv.conv_type, "dm");
    assert_eq!(conv.members.len(), 2);
}

#[tokio::test]
async fn dm_conversation_dedup() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    authenticate(&server, &bob).await;

    // First DM creation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv1: ConversationResponse = resp.json();

    // Second creation between same two users — should reuse
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv2: ConversationResponse = resp.json();

    assert_eq!(conv1.id, conv2.id, "DM should be deduped between same users");
}

#[tokio::test]
async fn create_group_dm() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let charlie = Identity::generate();
    authenticate(&server, &bob).await;
    authenticate(&server, &charlie).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert_eq!(conv.conv_type, "group");
    assert_eq!(conv.members.len(), 3);
}

#[tokio::test]
async fn list_my_conversations() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    authenticate(&server, &bob).await;

    server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;

    let resp = server.get("/conversations").authorization_bearer(&alice_token).await;
    resp.assert_status_ok();
    let conversations: Vec<ConversationResponse> = resp.json();
    assert_eq!(conversations.len(), 1);
}

#[tokio::test]
async fn cannot_send_to_conversation_youre_not_in() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = authenticate(&server, &bob).await;
    let charlie = Identity::generate();
    let charlie_token = authenticate(&server, &charlie).await;

    // Alice + Bob create a DM
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv: ConversationResponse = resp.json();

    // Alice can send
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "hi bob" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Bob can send
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hi alice" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Charlie cannot
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&charlie_token)
        .json(&json!({ "content": "intruder!" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_create_empty_conversation() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// --- Cross-hub federated DM tests ---

async fn start_real_hub(name: &str) -> String {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: name.to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
    });
    let app = server::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    url
}

async fn authenticate_http(hub_url: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

/// Return the AppState together with the URL so tests can drive the worker manually.
async fn start_real_hub_with_state(name: &str) -> (String, Arc<AppState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: name.to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
    });
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (url, state)
}

#[tokio::test]
async fn dm_delivered_across_hubs() {
    let hub_a = start_real_hub("hub-a").await;
    let hub_b = start_real_hub("hub-b").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    let bob_token = authenticate_http(&hub_b, &bob).await;

    // Alice creates a conversation on Hub A that includes Bob, routing to Hub B.
    let mut member_hubs = HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "Create conversation failed: {status} {body_text}",
    );
    let conv: ConversationResponse = serde_json::from_str(&body_text).unwrap();

    // Alice sends a DM. Hub A persists it locally and federates to Hub B.
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": "hi bob, from across hubs" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Give the async federation request time to land.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Bob reads the thread from Hub B — message should have been federated there.
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Hub B list endpoint failed: {}", resp.status());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().expect("expected an array");
    assert_eq!(arr.len(), 1, "Bob should see the federated DM");
    assert_eq!(arr[0]["content"], "hi bob, from across hubs");
    assert_eq!(arr[0]["sender"], alice.public_key_hex());
}

#[tokio::test]
async fn dm_retries_when_recipient_hub_comes_online() {
    use voxply_hub::dm_worker;

    // Hub A is up from the start.
    let (hub_a, hub_a_state) = start_real_hub_with_state("hub-a").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;

    // Pick an address that definitely is not serving anything yet.
    let dead_port = {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = tmp.local_addr().unwrap().port();
        drop(tmp);
        p
    };
    let hub_b_url_planned = format!("http://127.0.0.1:{dead_port}");

    // Alice creates a conversation pointing at Hub B's (currently dead) URL.
    let mut member_hubs = HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b_url_planned.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Send while Hub B is down. POST still succeeds (Hub A accepts and queues).
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": "hi from retry land" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Confirm the message is parked in the outbox.
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dm_outbox")
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(queued, 1, "message should be queued while recipient is offline");

    // Bring Hub B up on the previously-chosen port.
    let hub_b_db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&hub_b_db).await.unwrap();
    let (chat_tx_b, _) = broadcast::channel(256);
    let (voice_event_tx_b, _) = broadcast::channel(16);
    let hub_b_state = Arc::new(AppState {
        hub_name: "hub-b".to_string(),
        hub_identity: Identity::generate(),
        db: hub_b_db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: chat_tx_b,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: voice_event_tx_b,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
    });
    let app_b = server::create_router(hub_b_state.clone());
    let listener_b = tokio::net::TcpListener::bind(format!("127.0.0.1:{dead_port}"))
        .await
        .expect("Hub B should be able to claim the chosen port");
    tokio::spawn(async move {
        axum::serve(
            listener_b,
            app_b.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Force next_attempt_at to now so the worker picks the row up immediately.
    sqlx::query("UPDATE dm_outbox SET next_attempt_at = 0")
        .execute(&hub_a_state.db)
        .await
        .unwrap();

    // Run one worker pass.
    dm_worker::tick(&hub_a_state).await.unwrap();

    // Outbox should be empty now.
    let queued_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dm_outbox")
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(queued_after, 0, "worker should have delivered and cleared the outbox");

    // Hub B should have stored the message.
    let bob_token = authenticate_http(&format!("http://127.0.0.1:{dead_port}"), &bob).await;
    let resp = client
        .get(format!(
            "http://127.0.0.1:{dead_port}/conversations/{}/messages",
            conv.id
        ))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["content"], "hi from retry land");
}

#[tokio::test]
async fn list_dm_messages_marks_bounced_as_delivery_failed() {
    let (server, pool) = setup_with_pool().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();

    // Alice creates a DM to Bob with a remote hub URL — Bob isn't on this
    // hub, so the conversation needs hub_url for him.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): "http://unreachable.example" },
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Send a message. The send_dm path will try to deliver synchronously,
    // fail (unreachable URL), and leave the row in the outbox at attempts=1.
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "this won't make it" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Pretend the worker exhausted retries — mark the outbox row bounced.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query("UPDATE dm_outbox SET bounced_at = ? WHERE recipient_hub_url = ?")
        .bind(now)
        .bind("http://unreachable.example")
        .execute(&pool)
        .await
        .unwrap();

    // List the conversation — the message should be marked delivery_failed=true.
    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["delivery_failed"], true,
        "bounced outbox row should surface as delivery_failed on the message"
    );
}

#[tokio::test]
async fn list_dm_messages_returns_delivery_failed_false_for_local_conversation() {
    let server = setup().await;
    let alice = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob = Identity::generate();
    authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv: ConversationResponse = resp.json();

    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "hi" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .await;
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["delivery_failed"], false);
}

// ---------------------------------------------------------------------------
// Phase 5: home-hub designation routing
// ---------------------------------------------------------------------------

/// When a recipient has a home_hub_designations row, send_dm should route via
/// each URL in hubs_json instead of conversation_members.hub_url.
#[tokio::test]
async fn send_dm_uses_home_hub_designation_when_present() {
    let (hub_a, hub_a_state) = start_real_hub_with_state("hub-a-desig").await;
    let hub_b = start_real_hub("hub-b-desig").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_master = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    authenticate_http(&hub_b, &bob).await;

    // Alice creates a conversation on Hub A. She supplies an unreachable
    // placeholder as Bob's hub_url — the designation should override it.
    let placeholder_url = "http://placeholder.invalid";
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): placeholder_url },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Give Bob a master_pubkey in Hub A's users table.
    let bob_master_hex = bob_master.public_key_hex();
    sqlx::query("UPDATE users SET master_pubkey = ? WHERE public_key = ?")
        .bind(&bob_master_hex)
        .bind(bob.public_key_hex())
        .execute(&hub_a_state.db)
        .await
        .unwrap();

    // Insert a designation row pointing at the real Hub B.
    let hubs_json = serde_json::to_string(&vec![hub_b.clone()]).unwrap();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO home_hub_designations
         (master_pubkey, hubs_json, issued_at, sequence, signature, updated_at)
         VALUES (?, ?, ?, 1, 'test', ?)",
    )
    .bind(&bob_master_hex)
    .bind(&hubs_json)
    .bind(now_ts)
    .bind(now_ts)
    .execute(&hub_a_state.db)
    .await
    .unwrap();

    // Alice sends a DM. Hub A should route via the designation to Hub B,
    // ignoring the placeholder hub_url.
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": "routed via designation" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Bob reads from Hub B — message should have arrived via the designation.
    let bob_token = authenticate_http(&hub_b, &bob).await;
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1, "message should have been routed to Hub B via designation");
    assert_eq!(arr[0]["content"], "routed via designation");
}

/// When no home_hub_designations row exists, send_dm falls back to the
/// hub_url from conversation_members (existing behaviour, no regression).
#[tokio::test]
async fn send_dm_falls_back_to_hub_url_when_no_designation() {
    let hub_a = start_real_hub("hub-a-fallback").await;
    let hub_b = start_real_hub("hub-b-fallback").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    authenticate_http(&hub_b, &bob).await;

    // No designation row — only hub_url in member_hubs.
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): hub_b.clone() },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": "fallback delivery" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let bob_token = authenticate_http(&hub_b, &bob).await;
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1, "message should have been delivered via fallback hub_url");
    assert_eq!(arr[0]["content"], "fallback delivery");
}

