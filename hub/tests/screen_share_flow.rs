use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::chat_models::ChannelResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

/// Boot a real TCP listener on a random port and return the base URL.
async fn start_hub() -> (String, Arc<AppState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "ss-test".to_string(),
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
        screen_share_tx: broadcast::channel(256).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),    });

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, state)
}

async fn authenticate_http(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let resp: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&resp.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
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

async fn create_channel(base: &str, token: &str, name: &str) -> ChannelResponse {
    reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Connect a WS client and return the split stream.
async fn connect_ws(
    base: &str,
    token: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_text(
    tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    msg: Value,
) {
    tx.send(TsMessage::Text(msg.to_string().into()))
        .await
        .unwrap();
}

async fn next_text(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Value {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), rx.next())
            .await
            .expect("timed out waiting for WS message")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            // Skip the hello frame the hub sends on connect.
            if v["type"] == "hello" {
                continue;
            }
            return v;
        }
    }
}

/// Read the next raw WS message, returning text or binary.
async fn next_raw(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> TsMessage {
    tokio::time::timeout(std::time::Duration::from_secs(3), rx.next())
        .await
        .expect("timed out waiting for WS message")
        .unwrap()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: sharer sends start + chunk + stop; viewer receives them all.
#[tokio::test]
async fn screen_share_start_chunk_stop_fan_out() {
    let (base, _state) = start_hub().await;

    let sharer_id = Identity::generate();
    let viewer_id = Identity::generate();

    let sharer_token = authenticate_http(&base, &sharer_id).await;
    let viewer_token = authenticate_http(&base, &viewer_id).await;

    let ch = create_channel(&base, &sharer_token, "general").await;

    // Connect both
    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;
    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;

    // Viewer subscribes first
    send_text(&mut viewer_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;

    // Sharer subscribes too (so chat events reach them) then starts the share
    send_text(&mut sharer_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
    send_text(&mut sharer_tx, json!({
        "type": "screen_share_start",
        "channel_id": ch.id,
        "stream_id": "stream-1",
        "kind": "screen",
        "mime": "video/webm;codecs=vp8,opus",
        "has_audio": true,
    })).await;

    // Viewer should receive screen_share_started
    let started = next_text(&mut viewer_rx).await;
    assert_eq!(started["type"], "screen_share_started");
    assert_eq!(started["stream_id"], "stream-1");
    assert_eq!(started["kind"], "screen");
    assert_eq!(started["has_audio"], true);

    // Sharer sends a chunk envelope then binary data
    send_text(&mut sharer_tx, json!({
        "type": "screen_share_chunk",
        "channel_id": ch.id,
        "stream_id": "stream-1",
        "seq": 0,
        "is_init": true,
    })).await;

    sharer_tx
        .send(TsMessage::Binary(b"INIT_SEGMENT_BYTES".to_vec().into()))
        .await
        .unwrap();

    // Viewer should receive the chunk envelope then the binary
    let chunk_env = next_text(&mut viewer_rx).await;
    assert_eq!(chunk_env["type"], "screen_share_chunk");
    assert_eq!(chunk_env["seq"], 0);
    assert_eq!(chunk_env["is_init"], true);

    let binary_msg = next_raw(&mut viewer_rx).await;
    assert!(matches!(binary_msg, TsMessage::Binary(_)));
    if let TsMessage::Binary(data) = binary_msg {
        assert_eq!(&data[..], b"INIT_SEGMENT_BYTES");
    }

    // Sharer sends stop
    send_text(&mut sharer_tx, json!({
        "type": "screen_share_stop",
        "channel_id": ch.id,
        "stream_id": "stream-1",
    })).await;

    let stopped = next_text(&mut viewer_rx).await;
    assert_eq!(stopped["type"], "screen_share_stopped");
    assert_eq!(stopped["stream_id"], "stream-1");
}

/// Late joiner: viewer connects after the init chunk is cached and receives it on subscribe.
#[tokio::test]
async fn late_joiner_receives_init_chunk() {
    let (base, _state) = start_hub().await;

    let sharer_id = Identity::generate();
    let viewer_id = Identity::generate();

    let sharer_token = authenticate_http(&base, &sharer_id).await;
    let viewer_token = authenticate_http(&base, &viewer_id).await;

    let ch = create_channel(&base, &sharer_token, "video").await;

    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;

    // Sharer starts, sends init chunk
    send_text(&mut sharer_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
    send_text(&mut sharer_tx, json!({
        "type": "screen_share_start",
        "channel_id": ch.id,
        "stream_id": "str-abc",
        "kind": "screen",
        "mime": "video/webm;codecs=vp8",
        "has_audio": false,
    })).await;

    send_text(&mut sharer_tx, json!({
        "type": "screen_share_chunk",
        "channel_id": ch.id,
        "stream_id": "str-abc",
        "seq": 0,
        "is_init": true,
    })).await;
    sharer_tx
        .send(TsMessage::Binary(b"WEBM_INIT".to_vec().into()))
        .await
        .unwrap();

    // Give the hub a moment to process the chunk and cache it
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Late viewer now connects and subscribes
    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;
    send_text(&mut viewer_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;

    // Should receive screen_share_started
    let started = next_text(&mut viewer_rx).await;
    assert_eq!(started["type"], "screen_share_started");
    assert_eq!(started["stream_id"], "str-abc");

    // Then a synthetic init chunk envelope
    let chunk_env = next_text(&mut viewer_rx).await;
    assert_eq!(chunk_env["type"], "screen_share_chunk");
    assert_eq!(chunk_env["is_init"], true);

    // Then the binary init segment
    let binary = next_raw(&mut viewer_rx).await;
    assert!(matches!(binary, TsMessage::Binary(_)));
    if let TsMessage::Binary(data) = binary {
        assert_eq!(&data[..], b"WEBM_INIT");
    }
}

/// Rejection: a second user trying to share in a channel where someone else is active.
#[tokio::test]
async fn second_sharer_rejected() {
    let (base, _state) = start_hub().await;

    let alice = Identity::generate();
    let bob = Identity::generate();

    let alice_token = authenticate_http(&base, &alice).await;
    let bob_token = authenticate_http(&base, &bob).await;

    let ch = create_channel(&base, &alice_token, "general").await;

    let (mut alice_tx, _alice_rx) = connect_ws(&base, &alice_token).await;
    let (mut bob_tx, mut bob_rx) = connect_ws(&base, &bob_token).await;

    // Alice starts sharing
    send_text(&mut alice_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
    send_text(&mut alice_tx, json!({
        "type": "screen_share_start",
        "channel_id": ch.id,
        "stream_id": "alice-stream",
        "kind": "screen",
        "mime": "video/webm",
        "has_audio": false,
    })).await;

    // Give hub time to register Alice's share
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Bob tries to share in the same channel
    send_text(&mut bob_tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
    send_text(&mut bob_tx, json!({
        "type": "screen_share_start",
        "channel_id": ch.id,
        "stream_id": "bob-stream",
        "kind": "screen",
        "mime": "video/webm",
        "has_audio": false,
    })).await;

    // Bob should receive an error message (may follow screen_share_started for Alice)
    let mut got_error = false;
    for _ in 0..5 {
        let msg = next_text(&mut bob_rx).await;
        if msg["type"] == "error" && msg["context"] == "screen_share" {
            got_error = true;
            break;
        }
    }
    assert!(got_error, "Bob should receive a screen_share error");
}
