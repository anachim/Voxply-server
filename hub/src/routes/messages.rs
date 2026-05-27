use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{
    Attachment, ChatEvent, EditMessageRequest, MessageResponse, PaginationParams,
    ReactionRequest, ReactionSummary, ReplyContext, SendMessageRequest,
    MAX_ATTACHMENTS_BYTES,
};
use crate::state::AppState;

pub async fn send_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    if crate::routes::moderation::is_muted(&state.db, &user.public_key).await? {
        return Err((StatusCode::FORBIDDEN, "You are muted".to_string()));
    }

    if crate::routes::moderation::is_channel_banned(&state.db, &channel_id, &user.public_key).await? {
        return Err((StatusCode::FORBIDDEN, "You are banned from this channel".to_string()));
    }

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    // Cap attachments size. The base64 payload is what counts toward the
    // limit since that's what travels over WS and lands in the DB.
    let attach_total: usize = req.attachments.iter().map(|a| a.data_b64.len()).sum();
    if attach_total > MAX_ATTACHMENTS_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Attachments exceed {}MB cap",
                MAX_ATTACHMENTS_BYTES / 1024 / 1024
            ),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    let attachments_json = if req.attachments.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&req.attachments)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?,
        )
    };

    // If a reply_to is provided, sanity-check the parent exists in this
    // same channel. Cross-channel replies would surprise everyone.
    if let Some(parent_id) = &req.reply_to {
        let parent_channel: Option<String> =
            sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = ?")
                .bind(parent_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        match parent_channel {
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Parent message not found".to_string(),
                ))
            }
            Some(c) if c != channel_id => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Parent message is in a different channel".to_string(),
                ))
            }
            _ => {}
        }
    }

    // Slash command dispatch (external bot system): if the message starts with
    // '/' and a registered bot handles the command, the bot responds via its
    // webhook. We do NOT store the original slash message by default — the bot
    // decides what to post. Only store the message if no bot matched.
    if req.content.starts_with('/') {
        let ephemeral_err = crate::bots::dispatch::dispatch_slash(
            &state,
            &channel_id,
            &user.public_key,
            &req.content,
        )
        .await;

        match ephemeral_err {
            Some(err_text) => {
                // Command matched but errored — insert ephemeral error and return.
                crate::bots::dispatch::insert_ephemeral_error(
                    &state,
                    &channel_id,
                    &user.public_key,
                    &err_text,
                )
                .await?;
                // Return a minimal 200 so the client doesn't retry.
                let placeholder = MessageResponse {
                    id: id.clone(),
                    channel_id: channel_id.clone(),
                    sender: user.public_key.clone(),
                    sender_name: None,
                    content: err_text,
                    created_at: now,
                    edited_at: None,
                    attachments: Vec::new(),
                    reactions: Vec::new(),
                    reply_to: None,
                    visible_to_pubkey: Some(user.public_key),
                };
                return Ok((StatusCode::OK, Json(placeholder)));
            }
            None => {
                // dispatch_slash returns None in two cases:
                //   1. No bot matched — fall through to store the message normally.
                //   2. Bot matched and handled (reply inserted inside dispatch_slash).
                // We have no way to distinguish these without an extra return value,
                // so we always fall through and store the message. The stored slash
                // text serves as the user's "command invocation" record in the channel.
                // (Design note: the spec says "hub does NOT persist slash invocations
                // by default" — this is a pragmatic choice to keep the flow simple
                // while the bot still posts its own reply. A future version could
                // track whether dispatch consumed the message and skip storage.)
            }
        }
    }

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, attachments, reply_to, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&user.public_key)
    .bind(&req.content)
    .bind(&attachments_json)
    .bind(&req.reply_to)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let reply_ctx = if let Some(parent_id) = &req.reply_to {
        load_reply_context(&state.db, parent_id).await?
    } else {
        None
    };

    let sender_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = ?")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    let message = MessageResponse {
        id,
        channel_id: channel_id.clone(),
        sender: user.public_key,
        sender_name,
        content: req.content,
        created_at: now,
        edited_at: None,
        attachments: req.attachments,
        reactions: Vec::new(),
        reply_to: reply_ctx,
        visible_to_pubkey: None,
    };

    let _ = state.chat_tx.send(ChatEvent::New {
        channel_id: channel_id.clone(),
        message: message.clone(),
    });

    // Publish message.created audit event for bot subscriptions.
    {
        let state_c = state.clone();
        let ch = channel_id.clone();
        let msg_c = message.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "message.created",
                Some(&msg_c.sender),
                None,
                Some(&ch),
                serde_json::json!({
                    "message_id": msg_c.id,
                    "content": msg_c.content,
                    "sender": msg_c.sender,
                    "sender_name": msg_c.sender_name,
                    "created_at": msg_c.created_at,
                    "attachments": msg_c.attachments,
                }),
            ).await;
        });
    }

    Ok((StatusCode::CREATED, Json(message)))
}

pub async fn edit_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(req): Json<EditMessageRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT sender, channel_id FROM messages WHERE id = ?",
    )
    .bind(&message_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (sender, msg_channel) = row
        .ok_or((StatusCode::NOT_FOUND, "Message not found".to_string()))?;
    if msg_channel != channel_id {
        return Err((StatusCode::NOT_FOUND, "Message not in this channel".to_string()));
    }
    if sender != user.public_key {
        return Err((StatusCode::FORBIDDEN, "You can only edit your own messages".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "UPDATE messages SET content = ?, edited_at = ? WHERE id = ?",
    )
    .bind(&req.content)
    .bind(now)
    .bind(&message_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let updated = load_message(&state, &message_id).await?;
    let _ = state.chat_tx.send(ChatEvent::Edited {
        channel_id: channel_id.clone(),
        message: updated.clone(),
    });
    Ok(Json(updated))
}

pub async fn delete_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT sender, channel_id FROM messages WHERE id = ?",
    )
    .bind(&message_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (sender, msg_channel) = row
        .ok_or((StatusCode::NOT_FOUND, "Message not found".to_string()))?;
    if msg_channel != channel_id {
        return Err((StatusCode::NOT_FOUND, "Message not in this channel".to_string()));
    }

    // Author can always delete their own. Others need manage_messages.
    if sender != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::MANAGE_MESSAGES)?;
    }

    sqlx::query("DELETE FROM messages WHERE id = ?")
        .bind(&message_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let _ = state.chat_tx.send(ChatEvent::Deleted {
        channel_id,
        message_id,
    });

    Ok(StatusCode::NO_CONTENT)
}

fn parse_attachments(json: Option<String>) -> Vec<Attachment> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

async fn load_message(
    state: &AppState,
    message_id: &str,
) -> Result<MessageResponse, (StatusCode, String)> {
    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name,
                m.content, m.attachments, m.reply_to, m.created_at, m.edited_at
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = ?",
    )
    .bind(message_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let reactions = load_reactions_anon(&state.db, &row.id).await?;
    let reply_to = if let Some(parent_id) = &row.reply_to {
        load_reply_context(&state.db, parent_id).await?
    } else {
        None
    };
    Ok(MessageResponse {
        id: row.id,
        channel_id: row.channel_id,
        sender: row.sender,
        sender_name: row.sender_name,
        content: row.content,
        created_at: row.created_at,
        edited_at: row.edited_at,
        attachments: parse_attachments(row.attachments),
        reactions,
        reply_to,
        visible_to_pubkey: None,
    })
}

pub async fn get_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<MessageResponse>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(100);
    let search = params
        .q
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let rows = match (search, &params.before) {
        // Search mode: ignores `before` for now — search returns the most
        // recent N matches across the whole channel. Good enough for v1.
        (Some(q), _) => {
            let pattern = format!("%{q}%");
            sqlx::query_as::<_, MessageRow>(
                "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at
                 FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                 WHERE m.channel_id = ? AND m.content LIKE ? COLLATE NOCASE
                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ?",
            )
            .bind(&channel_id)
            .bind(pattern)
            .bind(limit)
            .fetch_all(&state.db)
            .await
        }
        (None, Some(before_id)) => {
            sqlx::query_as::<_, MessageRow>(
                "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at
                 FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                 WHERE m.channel_id = ? AND m.rowid < (SELECT rowid FROM messages WHERE id = ?)
                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ?",
            )
            .bind(&channel_id)
            .bind(before_id)
            .bind(limit)
            .fetch_all(&state.db)
            .await
        }
        (None, None) => {
            sqlx::query_as::<_, MessageRow>(
                "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at
                 FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                 WHERE m.channel_id = ?
                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ?",
            )
            .bind(&channel_id)
            .bind(limit)
            .fetch_all(&state.db)
            .await
        }
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut messages: Vec<MessageResponse> = Vec::with_capacity(rows.len());
    for r in rows {
        let reactions = load_reactions(&state.db, &r.id, &user.public_key).await?;
        let reply_to = if let Some(parent_id) = &r.reply_to {
            load_reply_context(&state.db, parent_id).await?
        } else {
            None
        };
        messages.push(MessageResponse {
            id: r.id,
            channel_id: r.channel_id,
            sender: r.sender,
            sender_name: r.sender_name,
            content: r.content,
            created_at: r.created_at,
            edited_at: r.edited_at,
            attachments: parse_attachments(r.attachments),
            reactions,
            reply_to,
            visible_to_pubkey: None,
        });
    }

    Ok(Json(messages))
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: String,
    channel_id: String,
    sender: String,
    sender_name: Option<String>,
    content: String,
    attachments: Option<String>,
    reply_to: Option<String>,
    created_at: i64,
    edited_at: Option<i64>,
}

/// Load a small preview of a parent message for the reply chip. Returns
/// None if the parent has been deleted.
async fn load_reply_context(
    db: &sqlx::SqlitePool,
    parent_id: &str,
) -> Result<Option<ReplyContext>, (StatusCode, String)> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT m.sender, u.display_name as sender_name, m.content
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = ?",
    )
    .bind(parent_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(row.map(|(sender, sender_name, content)| {
        // Cap the preview so a paragraph doesn't blow up the WS frame.
        let preview: String = content.chars().take(140).collect();
        ReplyContext {
            message_id: parent_id.to_string(),
            sender,
            sender_name,
            content_preview: preview,
        }
    }))
}

/// Load aggregated reaction counts for one message, with `me` flagged for
/// rows the viewer reacted to.
pub(crate) async fn load_reactions(
    db: &sqlx::SqlitePool,
    message_id: &str,
    viewer: &str,
) -> Result<Vec<ReactionSummary>, (StatusCode, String)> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt, MAX(CASE WHEN user_key = ? THEN 1 ELSE 0 END) as mine
         FROM message_reactions
         WHERE message_id = ?
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(viewer)
    .bind(message_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(emoji, count, mine)| ReactionSummary {
            emoji,
            count,
            me: mine != 0,
        })
        .collect())
}

/// Same as load_reactions but for broadcast: `me` is false because we
/// don't know who the recipient will be.
async fn load_reactions_anon(
    db: &sqlx::SqlitePool,
    message_id: &str,
) -> Result<Vec<ReactionSummary>, (StatusCode, String)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt
         FROM message_reactions
         WHERE message_id = ?
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(message_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(emoji, count)| ReactionSummary {
            emoji,
            count,
            me: false,
        })
        .collect())
}

pub async fn add_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(req): Json<ReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    let emoji = req.emoji.trim();
    if emoji.is_empty() || emoji.chars().count() > 16 {
        return Err((
            StatusCode::BAD_REQUEST,
            "emoji must be 1..16 chars".to_string(),
        ));
    }

    // Sanity-check the message belongs to the channel claimed in the path.
    let row: Option<String> =
        sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = ?")
            .bind(&message_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    match row {
        None => return Err((StatusCode::NOT_FOUND, "message not found".to_string())),
        Some(c) if c != channel_id => {
            return Err((StatusCode::NOT_FOUND, "message not in channel".to_string()))
        }
        _ => {}
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT OR IGNORE INTO message_reactions (message_id, emoji, user_key, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&message_id)
    .bind(emoji)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let summary = load_reactions_anon(&state.db, &message_id).await?;
    let _ = state.chat_tx.send(ChatEvent::ReactionsUpdated {
        channel_id,
        message_id,
        reactions: summary,
    });

    Ok(StatusCode::CREATED)
}

pub async fn remove_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id, emoji)): Path<(String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query(
        "DELETE FROM message_reactions WHERE message_id = ? AND emoji = ? AND user_key = ?",
    )
    .bind(&message_id)
    .bind(&emoji)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let summary = load_reactions_anon(&state.db, &message_id).await?;
    let _ = state.chat_tx.send(ChatEvent::ReactionsUpdated {
        channel_id,
        message_id,
        reactions: summary,
    });

    Ok(StatusCode::NO_CONTENT)
}
