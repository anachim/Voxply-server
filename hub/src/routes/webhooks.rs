use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChatEvent, MessageResponse, WsServerMessage};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Constant-time byte comparison to avoid timing attacks on token comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateWebhookRequest {
    pub channel_id: String,
    pub display_name: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateWebhookResponse {
    pub id: String,
    pub webhook_url: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct WebhookPostRequest {
    pub content: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub embeds: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct WebhookPostResponse {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

/// POST /admin/webhooks — admin creates a webhook for a channel.
pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<CreateWebhookResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    // Verify channel exists.
    let ch_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let rate_limit = req.rate_limit.unwrap_or(5);

    // Generate a 32-byte secret token. Only returned here; we store the hash.
    let secret_token = {
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let token_hash = sha256_hex(secret_token.as_bytes());

    sqlx::query(
        "INSERT INTO webhooks(id, channel_id, secret_token_hash, display_name, avatar_url, created_by_pubkey, rate_limit, active, created_at)
         VALUES(?,?,?,?,?,?,?,1,?)",
    )
    .bind(&id)
    .bind(&req.channel_id)
    .bind(&token_hash)
    .bind(&req.display_name)
    .bind(&req.avatar_url)
    .bind(&user.public_key)
    .bind(rate_limit)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Create a users row for the webhook identity so message FKs work.
    // Using the webhook id as "public_key" — a known hack but avoids a
    // parallel auth path (documented in bots.md §9).
    sqlx::query(
        "INSERT OR IGNORE INTO users(public_key, display_name, first_seen_at, last_seen_at, approval_status, is_bot, is_webhook)
         VALUES(?,?,?,?,'approved',1,1)",
    )
    .bind(&id)
    .bind(&req.display_name)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Build the public-facing webhook URL. We read hub_url from settings, or
    // use the same placeholder as dispatch.rs.
    let hub_base: String =
        sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "https://unknown-hub".to_string());

    let webhook_url = format!("{hub_base}/webhooks/{id}/{secret_token}");

    Ok((
        StatusCode::CREATED,
        Json(CreateWebhookResponse {
            id,
            webhook_url,
            display_name: req.display_name,
        }),
    ))
}

/// DELETE /admin/webhooks/:id — admin deactivates a webhook.
pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(webhook_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let rows = sqlx::query("UPDATE webhooks SET active = 0 WHERE id = ?")
        .bind(&webhook_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Public inbound webhook handler
// ---------------------------------------------------------------------------

/// POST /webhooks/:id/:token — external service posts a message to a channel.
/// No auth header — the token in the URL is the credential.
pub async fn post_webhook_message(
    State(state): State<Arc<AppState>>,
    Path((webhook_id, token)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<WebhookPostRequest>,
) -> Result<Json<WebhookPostResponse>, (StatusCode, String)> {
    // Look up webhook.
    #[derive(sqlx::FromRow)]
    struct WebhookRow {
        channel_id: String,
        secret_token_hash: String,
        display_name: String,
    }

    let webhook = sqlx::query_as::<_, WebhookRow>(
        "SELECT channel_id, secret_token_hash, display_name
         FROM webhooks WHERE id = ? AND active = 1",
    )
    .bind(&webhook_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Webhook not found or inactive".to_string()))?;

    // Constant-time hash comparison.
    let presented_hash = sha256_hex(token.as_bytes());
    if !constant_time_eq(presented_hash.as_bytes(), webhook.secret_token_hash.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid webhook token".to_string()));
    }

    // Optional HMAC-SHA256 body signature verification.
    // If the header is present, verify it; if absent, skip (not required).
    // We re-serialize the body to bytes for HMAC. Since we already deserialized,
    // we use the raw body approach via the header value only — we check the header
    // only when present, as documenting that the body bytes were signed.
    // Note: to properly verify HMAC over the raw body, we would need to extract
    // it as bytes before deserialization. For v1 we verify the presence check
    // as a stub: if the header is present we accept it (the sender controls the
    // secret and we've already validated the URL token). A future version should
    // use a middleware that captures raw body bytes.
    if let Some(sig_header) = headers.get("X-Voxply-Signature") {
        // Header present — acknowledged. Full HMAC verification requires raw
        // body bytes captured before JSON parsing; deferred to a future middleware
        // refactor. For now: if signature is present but we can't verify, we log
        // but don't reject (the URL token is the primary credential).
        let _ = sig_header;
        tracing::debug!("Webhook HMAC signature present but full verification deferred");
    }

    let content = req.content.trim();
    if content.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "content is required".to_string()));
    }

    let msg_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    // The sender identity is the webhook id (which has a users row).
    // Override display name if the request provides a username.
    let display_name = req
        .username
        .as_deref()
        .unwrap_or(&webhook.display_name)
        .to_string();

    sqlx::query(
        "INSERT INTO messages(id, channel_id, sender, content, created_at)
         VALUES(?,?,?,?,?)",
    )
    .bind(&msg_id)
    .bind(&webhook.channel_id)
    .bind(&webhook_id)
    .bind(content)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let message = MessageResponse {
        id: msg_id.clone(),
        channel_id: webhook.channel_id.clone(),
        sender: webhook_id.clone(),
        sender_name: Some(display_name),
        content: content.to_string(),
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: None,
    };

    {
        let ws_msg = WsServerMessage::ChatMessage {
            channel_id: webhook.channel_id.clone(),
            message: message.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ChatEvent::New { channel_id: webhook.channel_id, message }, json));
    }

    Ok(Json(WebhookPostResponse { id: msg_id }))
}
