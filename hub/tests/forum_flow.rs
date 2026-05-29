use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::post_models::{PostDetail, PostListResponse, PostSearchResponse};
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
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
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    });
    TestServer::new(server::create_router(state))
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let ch: ChallengeResponse = resp.json();
    let sig = identity.sign(&hex::decode(&ch.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    let v: VerifyResponse = resp.json();
    v.token
}

/// Create a forum channel and return its id.
async fn create_forum_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "announcements", "channel_type": "forum" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Create a text channel and return its id.
async fn create_text_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "general" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

// ── Happy-path CRUD ──────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_create_list_get_post() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    // Create a post.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Hello forum", "body": "First post body" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.title.as_deref(), Some("Hello forum"));
    assert!(!detail.summary.is_deleted);
    let post_id = detail.summary.id.clone();

    // List posts — should include the new post.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let list: PostListResponse = resp.json();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].id, post_id);

    // Get post detail.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let detail2: PostDetail = resp.json();
    assert_eq!(detail2.summary.id, post_id);
    assert_eq!(detail2.body.as_deref(), Some("First post body"));
}

#[tokio::test]
async fn forum_edit_post() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Old title", "body": "Old body" }))
        .await;
    assert_eq!(resp.status_code(), 201);
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "New title", "body": "New body" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: PostDetail = resp.json();
    assert_eq!(updated.summary.title.as_deref(), Some("New title"));
    assert_eq!(updated.body.as_deref(), Some("New body"));
}

#[tokio::test]
async fn forum_delete_post_soft() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Delete me", "body": "Gone" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // The post list excludes soft-deleted posts.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let list: PostListResponse = resp.json();
    assert!(list.posts.is_empty());
}

#[tokio::test]
async fn forum_reply_create_edit_delete() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "With replies", "body": "Body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Create reply.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "First reply" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let reply: Value = resp.json();
    let reply_id = reply["id"].as_str().unwrap().to_string();
    assert_eq!(reply["body"].as_str(), Some("First reply"));

    // reply_count should be updated.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.reply_count, 1);

    // Edit reply.
    let resp = server
        .patch(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "Edited reply" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: Value = resp.json();
    assert_eq!(updated["body"].as_str(), Some("Edited reply"));

    // Delete reply.
    let resp = server
        .delete(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // reply_count decremented.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.reply_count, 0);
}

#[tokio::test]
async fn forum_pin_and_lock() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Pin me", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Pin.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/pin"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204, "{}", resp.text());

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert!(detail.summary.is_pinned);

    // Unpin.
    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}/pin"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // Lock.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert!(detail.summary.is_locked);

    // Unlock.
    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);
}

#[tokio::test]
async fn forum_search_returns_hits() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Rust is great", "body": "I love Rust programming" }))
        .await;

    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Unrelated post", "body": "Nothing relevant here" }))
        .await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/search?q=Rust"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let sr: PostSearchResponse = resp.json();
    assert!(!sr.results.is_empty(), "expected search hits for 'Rust'");
}

// ── Rejection tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_routes_return_not_a_forum_on_text_channel() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_text_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 409, "{}", resp.text());
    assert!(resp.text().contains("not_a_forum"));

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Oops", "body": "Nope" }))
        .await;
    assert_eq!(resp.status_code(), 409);
}

#[tokio::test]
async fn forum_locked_post_rejects_new_reply_from_non_moderator() {
    let server = setup().await;

    // Owner creates forum channel and a post.
    let owner_id = Identity::generate();
    let owner_token = authenticate(&server, &owner_id).await;
    let channel_id = create_forum_channel(&server, &owner_token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "title": "Locked post", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Owner locks it.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // A second user tries to reply — should be forbidden.
    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "body": "I can't reply" }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());
    assert!(resp.text().contains("post_locked"));
}

#[tokio::test]
async fn forum_non_author_cannot_edit_or_delete_post() {
    let server = setup().await;

    let owner_id = Identity::generate();
    let owner_token = authenticate(&server, &owner_id).await;
    let channel_id = create_forum_channel(&server, &owner_token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "title": "My post", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Second user without manage_posts.
    let user2 = Identity::generate();
    let token2 = authenticate(&server, &user2).await;

    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "body": "hacked" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .await;
    assert_eq!(resp.status_code(), 403);
}

#[tokio::test]
async fn forum_search_requires_non_empty_query() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/search?q="))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
    assert!(resp.text().contains("q_required"));
}

#[tokio::test]
async fn forum_get_post_not_found_returns_404() {
    let server = setup().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/no-such-id"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 404);
}
