use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::bot_models::{BotCommandDef, BotMeta, BotSubscription};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Audit log route types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub event_type: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub seq: i64,
    pub event_type: String,
    pub at: i64,
    pub actor_pubkey: Option<String>,
    pub target_pubkey: Option<String>,
    pub channel_id: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogEntry>,
    pub next_cursor: Option<i64>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

fn generate_token() -> String {
    hex::encode(Uuid::new_v4().as_bytes()) + &hex::encode(Uuid::new_v4().as_bytes())
}

/// Authenticate a bot request via `Authorization: Bearer <token>` and return
/// the matching bot row.
async fn authenticate_bot(
    db: &sqlx::SqlitePool,
    headers: &HeaderMap,
) -> Result<BotRow, (StatusCode, String)> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Missing bot token".to_string()))?;

    let hash = hash_token(raw);

    sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE token_hash = ?",
    )
    .bind(&hash)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid bot token".to_string()))
}

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct BotRow {
    public_key: String,
    display_name: String,
    created_by: String,
    created_at: i64,
    webhook_url: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SlashCommandRow {
    command: String,
    description: String,
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: String,
    event_type: String,
    payload: String,
    created_at: i64,
}

// ---------------------------------------------------------------------------
// Admin request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateBotRequest {
    pub display_name: String,
}

#[derive(Serialize)]
pub struct BotAdminInfo {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

#[derive(Serialize)]
pub struct BotCreatedResponse {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    pub token: String,
}

#[derive(Serialize)]
pub struct SlashCommandInfo {
    pub command: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct BotDetailResponse {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub commands: Vec<SlashCommandInfo>,
}

#[derive(Deserialize)]
pub struct SetWebhookRequest {
    pub webhook_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Bot API request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetCommandsRequest {
    pub commands: Vec<CommandInput>,
}

#[derive(Deserialize)]
pub struct CommandInput {
    pub command: String,
    pub description: String,
}

#[derive(Deserialize)]
pub struct BotSendRequest {
    pub channel_id: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct PollQuery {
    pub since: Option<i64>,
}

#[derive(Serialize)]
pub struct EventInfo {
    pub id: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct AckRequest {
    pub ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

/// POST /admin/bots  — create a bot (any authenticated hub member)
pub async fn admin_create_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateBotRequest>,
) -> Result<(StatusCode, Json<BotCreatedResponse>), (StatusCode, String)> {
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "display_name cannot be empty".to_string()));
    }

    let public_key = format!("bot_{}", Uuid::new_v4().simple());
    let token = generate_token();
    let token_hash = hash_token(&token);
    let now = crate::auth::handlers::unix_timestamp();

    // Insert into users so messages and member listing work with the existing FK.
    sqlx::query(
        "INSERT INTO users (public_key, display_name, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES (?, ?, ?, ?, 'approved', 1)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO bots (public_key, display_name, created_by, token_hash, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(&user.public_key)
    .bind(&token_hash)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(BotCreatedResponse {
            public_key,
            display_name,
            created_by: user.public_key,
            created_at: now,
            token,
        }),
    ))
}

/// GET /admin/bots  — list all bots (no token)
pub async fn admin_list_bots(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<BotAdminInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BotAdminInfo {
                public_key: r.public_key,
                display_name: r.display_name,
                created_by: r.created_by,
                created_at: r.created_at,
                webhook_url: r.webhook_url,
            })
            .collect(),
    ))
}

/// GET /admin/bots/:pubkey  — bot detail with slash commands
pub async fn admin_get_bot(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<BotDetailResponse>, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    let cmds = sqlx::query_as::<_, SlashCommandRow>(
        "SELECT command, description FROM bot_slash_commands WHERE bot_pubkey = ? ORDER BY command",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(BotDetailResponse {
        public_key: bot.public_key,
        display_name: bot.display_name,
        created_by: bot.created_by,
        created_at: bot.created_at,
        webhook_url: bot.webhook_url,
        commands: cmds
            .into_iter()
            .map(|c| SlashCommandInfo {
                command: c.command,
                description: c.description,
            })
            .collect(),
    }))
}

/// DELETE /admin/bots/:pubkey  — delete bot (creator or admin)
pub async fn admin_delete_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    // Creator can delete; admin can delete anyone's bot.
    if bot.created_by != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    // Cascade deletes slash_commands and event_queue via FK.
    sqlx::query("DELETE FROM bots WHERE public_key = ?")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Clean up the users row so the bot disappears from member lists.
    sqlx::query("DELETE FROM users WHERE public_key = ?")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// PUT /admin/bots/:pubkey/webhook  — set or clear webhook (creator or admin)
pub async fn admin_set_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<SetWebhookRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    if bot.created_by != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    sqlx::query("UPDATE bots SET webhook_url = ? WHERE public_key = ?")
        .bind(&req.webhook_url)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Bot API handlers  (token auth via Authorization: Bearer header)
// ---------------------------------------------------------------------------

/// PUT /bot/commands  — replace slash command list
pub async fn bot_set_commands(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM bot_slash_commands WHERE bot_pubkey = ?")
        .bind(&bot.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    for cmd in &req.commands {
        let cmd_word = cmd.command.trim().to_lowercase();
        if cmd_word.is_empty() {
            continue;
        }
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO bot_slash_commands (id, bot_pubkey, command, description, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&bot.public_key)
        .bind(&cmd_word)
        .bind(cmd.description.trim())
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

/// POST /bot/send  — post a message as the bot
pub async fn bot_send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BotSendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Verify channel exists.
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.channel_id)
    .bind(&bot.public_key)
    .bind(&req.content)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Broadcast via the chat channel so connected WS clients see it.
    use crate::routes::chat_models::{ChatEvent, MessageResponse};
    let message = MessageResponse {
        id,
        channel_id: req.channel_id.clone(),
        sender: bot.public_key,
        sender_name: Some(bot.display_name),
        content: req.content,
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: None,
    };
    let _ = state.chat_tx.send(ChatEvent::New {
        channel_id: req.channel_id,
        message,
    });

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /bot/poll  — poll undelivered events
pub async fn bot_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PollQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    let rows = if let Some(since) = params.since {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = ? AND delivered = 0 AND created_at > ?
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .bind(since)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = ? AND delivered = 0
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let events: Vec<EventInfo> = rows
        .into_iter()
        .map(|r| EventInfo {
            id: r.id,
            event_type: r.event_type,
            payload: r.payload,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "events": events })))
}

/// DELETE /bot/events  — acknowledge events as delivered
pub async fn bot_ack_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    for id in &req.ids {
        let _ = sqlx::query(
            "UPDATE bot_event_queue SET delivered = 1
             WHERE id = ? AND bot_pubkey = ?",
        )
        .bind(id)
        .bind(&bot.public_key)
        .execute(&state.db)
        .await;
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// External bot system — new handlers
// ---------------------------------------------------------------------------

// ---- Request / response types ----

#[derive(Deserialize)]
pub struct InviteBotRequest {
    pub pubkey: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct InviteBotResponse {
    pub invite_token: String,
}

#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    pub pubkey: String,
    pub signature_over_token: String,
    pub bot_meta: BotMeta,
}

#[derive(Serialize)]
pub struct AcceptInviteResponse {
    pub status: String,
}

#[derive(Serialize)]
pub struct BotListEntry {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub commands: Vec<BotCommandSummary>,
}

#[derive(Serialize)]
pub struct BotCommandSummary {
    pub name: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct BotMeResponse {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    pub capabilities: Vec<String>,
    pub commands: Vec<BotCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateCommandsRequest {
    pub commands: Vec<BotCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateSubscriptionsRequest {
    pub subscriptions: Vec<BotSubscription>,
}

#[derive(Serialize)]
pub struct SetSubscriptionsResponse {
    pub count: usize,
}

// ---- DB row helpers ----

#[derive(sqlx::FromRow)]
struct BotProfileRow {
    pubkey: String,
    name: String,
    avatar_url: Option<String>,
    description: Option<String>,
    webhook_url: Option<String>,
    homepage_url: Option<String>,
    capabilities: String,
}

#[derive(sqlx::FromRow)]
struct BotCommandRow {
    name: String,
    description: String,
    args: Option<String>,
    scope: String,
    privileged: i64,
    cooldown_seconds: i64,
}

// ---- Handler: POST /bots — admin invites external bot by pubkey ----

pub async fn ext_invite_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InviteBotRequest>,
) -> Result<Json<InviteBotResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    if !perms.has(permissions::MANAGE_ROLES) && !perms.has(permissions::ADMIN) {
        return Err((
            StatusCode::FORBIDDEN,
            "Missing permission: manage_roles".to_string(),
        ));
    }

    // Validate the pubkey looks like a 64-hex-char Ed25519 pubkey.
    if req.pubkey.len() != 64 || !req.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "pubkey must be 64 hex characters".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    // Create the pending users row (INSERT OR IGNORE so re-inviting is safe).
    sqlx::query(
        "INSERT OR IGNORE INTO users (public_key, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES (?, ?, ?, 'bot_pending', 1)",
    )
    .bind(&req.pubkey)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Generate a 32-byte random invite token.
    let token = {
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let expires = now + 86400; // 24 hours

    sqlx::query(
        "UPDATE users SET bot_invite_token = ?, bot_invite_expires = ? WHERE public_key = ?",
    )
    .bind(&token)
    .bind(expires)
    .bind(&req.pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(InviteBotResponse {
        invite_token: token,
    }))
}

// ---- Handler: POST /bots/accept-invite — bot accepts an invite ----

pub async fn ext_accept_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, (StatusCode, String)> {
    let row: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT bot_invite_token, bot_invite_expires FROM users WHERE public_key = ? AND is_bot = 1",
    )
    .bind(&req.pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (stored_token, expires) = row
        .ok_or((StatusCode::NOT_FOUND, "Bot not found or not invited".to_string()))?;

    let stored_token =
        stored_token.ok_or((StatusCode::NOT_FOUND, "No pending invite for this bot".to_string()))?;

    let now = crate::auth::handlers::unix_timestamp();
    if let Some(exp) = expires {
        if now > exp {
            return Err((StatusCode::GONE, "Invite token has expired".to_string()));
        }
    }

    // Verify the bot signed the raw token bytes with its Ed25519 private key.
    let token_bytes = stored_token.as_bytes();
    let sig_bytes = hex::decode(&req.signature_over_token)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    voxply_identity::verify_signature(&req.pubkey, token_bytes, &sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature over invite token".to_string()))?;

    // Approve and clear the invite token.
    sqlx::query(
        "UPDATE users SET approval_status = 'approved', bot_invite_token = NULL, bot_invite_expires = NULL
         WHERE public_key = ?",
    )
    .bind(&req.pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Upsert bot_profiles.
    let meta = &req.bot_meta;
    sqlx::query(
        "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, updated_at)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(pubkey) DO UPDATE SET
           name=excluded.name, avatar_url=excluded.avatar_url,
           description=excluded.description, webhook_url=excluded.webhook_url,
           homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
           updated_at=excluded.updated_at",
    )
    .bind(&req.pubkey)
    .bind(&meta.name)
    .bind(&meta.avatar_url)
    .bind(&meta.description)
    .bind(&meta.webhook_url)
    .bind(&meta.homepage_url)
    .bind(serde_json::to_string(&meta.capabilities.as_deref().unwrap_or(&[])).unwrap())
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Replace commands if provided.
    if let Some(cmds) = &meta.commands {
        sqlx::query("DELETE FROM bot_commands WHERE pubkey = ?")
            .bind(&req.pubkey)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        for cmd in cmds {
            sqlx::query(
                "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
                 VALUES(?,?,?,?,?,?,?)",
            )
            .bind(&req.pubkey)
            .bind(&cmd.name)
            .bind(&cmd.description)
            .bind(&cmd.args)
            .bind(cmd.scope.as_deref().unwrap_or("channel"))
            .bind(if cmd.privileged.unwrap_or(false) { 1i64 } else { 0 })
            .bind(cmd.cooldown_seconds.unwrap_or(3))
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }
    }

    Ok(Json(AcceptInviteResponse {
        status: "accepted".to_string(),
    }))
}

// ---- Handler: DELETE /bots/:pubkey — admin removes a bot ----

pub async fn ext_remove_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    sqlx::query("UPDATE users SET is_bot_removed = 1 WHERE public_key = ? AND is_bot = 1")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---- Handler: GET /bots — list bots (any member) ----

pub async fn ext_list_bots(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<BotListEntry>>, (StatusCode, String)> {
    #[derive(sqlx::FromRow)]
    struct BotListRow {
        pubkey: String,
        name: String,
        avatar_url: Option<String>,
        description: Option<String>,
        last_seen_at: Option<i64>,
        webhook_url: Option<String>,
    }

    let rows = sqlx::query_as::<_, BotListRow>(
        "SELECT u.public_key as pubkey, bp.name, bp.avatar_url, bp.description,
                u.last_seen_at, bp.webhook_url
         FROM users u
         JOIN bot_profiles bp ON bp.pubkey = u.public_key
         WHERE u.is_bot = 1 AND u.is_bot_removed = 0",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let cmds = sqlx::query_as::<_, (String, String)>(
            "SELECT name, description FROM bot_commands WHERE pubkey = ? ORDER BY name",
        )
        .bind(&row.pubkey)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        entries.push(BotListEntry {
            pubkey: row.pubkey,
            name: row.name,
            avatar_url: row.avatar_url,
            description: row.description,
            last_seen_at: row.last_seen_at,
            webhook_url: row.webhook_url,
            commands: cmds
                .into_iter()
                .map(|(name, description)| BotCommandSummary { name, description })
                .collect(),
        });
    }

    Ok(Json(entries))
}

// ---- Handler: GET /bots/me — bot fetches its own profile ----

pub async fn ext_bot_me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<BotMeResponse>, (StatusCode, String)> {
    // Verify caller is a bot.
    let is_bot: Option<i64> = sqlx::query_scalar(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .flatten();

    if is_bot != Some(1) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    let profile = sqlx::query_as::<_, BotProfileRow>(
        "SELECT pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities
         FROM bot_profiles WHERE pubkey = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot profile not found".to_string()))?;

    let cmds = sqlx::query_as::<_, BotCommandRow>(
        "SELECT name, description, args, scope, privileged, cooldown_seconds
         FROM bot_commands WHERE pubkey = ? ORDER BY name",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let capabilities: Vec<String> =
        serde_json::from_str(&profile.capabilities).unwrap_or_default();

    Ok(Json(BotMeResponse {
        pubkey: profile.pubkey,
        name: profile.name,
        avatar_url: profile.avatar_url,
        description: profile.description,
        webhook_url: profile.webhook_url,
        homepage_url: profile.homepage_url,
        capabilities,
        commands: cmds
            .into_iter()
            .map(|c| BotCommandDef {
                name: c.name,
                description: c.description,
                args: c.args,
                scope: Some(c.scope),
                privileged: Some(c.privileged != 0),
                cooldown_seconds: Some(c.cooldown_seconds),
            })
            .collect(),
    }))
}

// ---- Handler: PUT /bots/me/profile — bot updates its own profile ----

pub async fn ext_update_bot_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(meta): Json<BotMeta>,
) -> Result<Json<BotMeResponse>, (StatusCode, String)> {
    let is_bot: Option<i64> = sqlx::query_scalar(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .flatten();

    if is_bot != Some(1) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, updated_at)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(pubkey) DO UPDATE SET
           name=excluded.name, avatar_url=excluded.avatar_url,
           description=excluded.description, webhook_url=excluded.webhook_url,
           homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
           updated_at=excluded.updated_at",
    )
    .bind(&user.public_key)
    .bind(&meta.name)
    .bind(&meta.avatar_url)
    .bind(&meta.description)
    .bind(&meta.webhook_url)
    .bind(&meta.homepage_url)
    .bind(serde_json::to_string(&meta.capabilities.as_deref().unwrap_or(&[])).unwrap())
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Reload and return.
    ext_bot_me(State(state), user).await
}

// ---- Handler: PUT /bots/me/commands — bot replaces its command list ----

pub async fn ext_update_bot_commands(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let is_bot: Option<i64> = sqlx::query_scalar(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .flatten();

    if is_bot != Some(1) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    sqlx::query("DELETE FROM bot_commands WHERE pubkey = ?")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for cmd in &req.commands {
        sqlx::query(
            "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(&user.public_key)
        .bind(&cmd.name)
        .bind(&cmd.description)
        .bind(&cmd.args)
        .bind(cmd.scope.as_deref().unwrap_or("channel"))
        .bind(if cmd.privileged.unwrap_or(false) { 1i64 } else { 0 })
        .bind(cmd.cooldown_seconds.unwrap_or(3))
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

// ---- Handler: PUT /bots/me/subscriptions — bot replaces its event subscriptions ----

pub async fn ext_update_bot_subscriptions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateSubscriptionsRequest>,
) -> Result<Json<SetSubscriptionsResponse>, (StatusCode, String)> {
    let is_bot: Option<i64> = sqlx::query_scalar(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .flatten();

    if is_bot != Some(1) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    // Validate: message.* events require an explicit channels list.
    for sub in &req.subscriptions {
        let is_message_event = sub.event.starts_with("message.")
            && sub.event != "message.mention_bot"; // mention_bot is hub-scoped, no channels needed
        if is_message_event && sub.channels.as_ref().map_or(true, |v| v.is_empty()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Subscription '{}' requires an explicit channels list",
                    sub.event
                ),
            ));
        }
    }

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM bot_subscriptions WHERE bot_pubkey = ?")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut count = 0usize;
    for sub in &req.subscriptions {
        match &sub.channels {
            Some(channels) if !channels.is_empty() => {
                for channel_id in channels {
                    sqlx::query(
                        "INSERT OR IGNORE INTO bot_subscriptions(bot_pubkey, event_type, channel_id)
                         VALUES(?,?,?)",
                    )
                    .bind(&user.public_key)
                    .bind(&sub.event)
                    .bind(channel_id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                    count += 1;
                }
            }
            _ => {
                // Hub-scoped subscription: use '' as sentinel for "no channel filter".
                sqlx::query(
                    "INSERT OR IGNORE INTO bot_subscriptions(bot_pubkey, event_type, channel_id)
                     VALUES(?,?,'')",
                )
                .bind(&user.public_key)
                .bind(&sub.event)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                count += 1;
            }
        }
    }

    Ok(Json(SetSubscriptionsResponse { count }))
}

// ---------------------------------------------------------------------------
// GET /admin/audit-log
// ---------------------------------------------------------------------------

/// Cursor-paginated view of `hub_audit_log`. Admin only.
pub async fn admin_audit_log(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let limit = params.limit.unwrap_or(50).min(200).max(1);
    // We fetch limit+1 to detect whether there's a next page.
    let fetch_limit = limit + 1;

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        seq: i64,
        event_type: String,
        at: i64,
        actor_pubkey: Option<String>,
        target_pubkey: Option<String>,
        channel_id: Option<String>,
        payload_json: String,
    }

    // Build query dynamically from optional filters.
    // SQLite doesn't support named params easily with sqlx, so we use a flag
    // approach: always bind all params, use 0/MAX for disabled ranges.
    let cursor_seq = params.cursor.unwrap_or(0);
    let since = params.since.unwrap_or(0);
    let until = params.until.unwrap_or(i64::MAX);
    let event_type_filter = params.event_type.as_deref().unwrap_or("");

    let rows: Vec<AuditRow> = if event_type_filter.is_empty() {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > ? AND at >= ? AND at <= ?
             ORDER BY seq ASC
             LIMIT ?",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > ? AND at >= ? AND at <= ? AND event_type = ?
             ORDER BY seq ASC
             LIMIT ?",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(event_type_filter)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<AuditLogEntry> = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| AuditLogEntry {
            seq: r.seq,
            event_type: r.event_type,
            at: r.at,
            actor_pubkey: r.actor_pubkey,
            target_pubkey: r.target_pubkey,
            channel_id: r.channel_id,
            payload: serde_json::from_str(&r.payload_json).unwrap_or(serde_json::Value::Null),
        })
        .collect();

    let next_cursor = if has_more {
        entries.last().map(|e| e.seq)
    } else {
        None
    };

    Ok(Json(AuditLogResponse {
        entries,
        next_cursor,
    }))
}
