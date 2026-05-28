use std::sync::Arc;

use axum::http::StatusCode;
use uuid::Uuid;

use crate::routes::bot_models::{
    AuthorInfo, BotResponse, ComponentInteraction, ComponentResponse, ComponentUpdate,
    EphemeralReply, SlashInvocation,
};
use crate::routes::chat_models::{ChatEvent, MessageResponse, WsServerMessage};
use crate::state::AppState;

/// Hub URL placeholder — in production this comes from hub config. We read it
/// from a hub_settings key 'hub_url' if present, else fall back to a placeholder.
/// This is a design note: a proper hub_url config key should be set by the
/// operator; for v1 we read it from settings gracefully.
pub async fn hub_url_public(state: &AppState) -> String {
    hub_url(state).await
}

async fn hub_url(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "https://unknown-hub".to_string())
}

/// Detect a slash command in the message content and, if a registered bot
/// handles it, dispatch the invocation to the bot's webhook.
///
/// Returns:
/// - `None`  — no bot command matched; caller stores the message normally.
/// - `Some(ephemeral_error)` — a command matched but an error occurred; the
///   caller should store an ephemeral error message and return early without
///   storing the original message.
///
/// When the bot responds with a reply, that reply is inserted into the DB
/// here and broadcast via `state.chat_tx` so WS clients receive it.
pub async fn dispatch_slash(
    state: &Arc<AppState>,
    channel_id: &str,
    invoker_pubkey: &str,
    content: &str,
) -> Option<String> {
    if !content.starts_with('/') {
        return None;
    }

    // Parse command name and args.
    let rest = &content[1..];
    let mut parts = rest.splitn(2, ' ');
    let command_name = parts.next().unwrap_or("").to_lowercase();
    let args_raw = parts.next().unwrap_or("").to_string();

    if command_name.is_empty() {
        return None;
    }

    // Look up a matching command. If bot_channel_scope has any rows for this
    // bot, the channel must be listed there. We join bot_profiles to get the
    // webhook URL and bot name.
    #[derive(sqlx::FromRow)]
    struct MatchedCommand {
        bot_pubkey: String,
        bot_name: String,
        webhook_url: Option<String>,
        privileged: i64,
        // Reserved for per-user cooldown enforcement (spec §6). Not yet
        // wired into the in-memory cooldown store.
        #[allow(dead_code)]
        cooldown_seconds: i64,
    }

    let matched = sqlx::query_as::<_, MatchedCommand>(
        "SELECT bc.pubkey as bot_pubkey, bp.name as bot_name, bp.webhook_url,
                bc.privileged, bc.cooldown_seconds
         FROM bot_commands bc
         JOIN bot_profiles bp ON bp.pubkey = bc.pubkey
         JOIN users u ON u.public_key = bc.pubkey
         WHERE bc.name = ?
           AND u.is_bot = 1
           AND u.is_bot_removed = 0
           AND (
             -- Either no channel scope restriction for this bot...
             NOT EXISTS (
               SELECT 1 FROM bot_channel_scope WHERE bot_pubkey = bc.pubkey
             )
             -- ...or this channel is in the bot's scope.
             OR EXISTS (
               SELECT 1 FROM bot_channel_scope
               WHERE bot_pubkey = bc.pubkey AND channel_id = ?
             )
           )
         LIMIT 1",
    )
    .bind(&command_name)
    .bind(channel_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()?; // None = no bot matched, fall through to normal message storage

    // Privileged command: check invoker's permissions.
    if matched.privileged != 0 {
        let perms = crate::permissions::user_permissions(&state.db, invoker_pubkey)
            .await
            .ok()?;
        if !perms.has(crate::permissions::MANAGE_MESSAGES) {
            return Some("You don't have permission to use this command.".to_string());
        }
    }

    let webhook_url = match matched.webhook_url {
        Some(ref url) if !url.is_empty() => url.clone(),
        _ => {
            // No webhook configured; silently store as normal message.
            return None;
        }
    };

    let message_id_hint = Uuid::new_v4().to_string();

    // Look up invoker display name.
    let invoker_name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM users WHERE public_key = ?",
    )
    .bind(invoker_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let hub_url = hub_url(state).await;

    let args_tokens: Vec<String> = if args_raw.is_empty() {
        Vec::new()
    } else {
        args_raw.split_whitespace().map(|s| s.to_string()).collect()
    };

    let invocation = SlashInvocation {
        kind: "slash_command".to_string(),
        hub_url: hub_url.clone(),
        channel_id: channel_id.to_string(),
        message_id_hint: message_id_hint.clone(),
        author: AuthorInfo {
            pubkey: invoker_pubkey.to_string(),
            display_name: invoker_name,
        },
        command: command_name.clone(),
        args_raw: args_raw.clone(),
        args_tokens,
    };

    let body_json = match serde_json::to_string(&invocation) {
        Ok(j) => j,
        Err(_) => return Some(format!("Bot @{} failed to respond.", matched.bot_name)),
    };

    // Sign the body with the hub's federation keypair.
    let hub_pubkey = state.hub_identity.public_key_hex();
    let body_bytes = body_json.as_bytes();
    let signature = state.hub_identity.sign(body_bytes);
    let sig_hex = hex::encode(signature.to_bytes());
    let timestamp = crate::auth::handlers::unix_timestamp();

    // POST to bot webhook with 5s timeout.
    let resp = state
        .http_client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-Voxply-Hub-Pubkey", &hub_pubkey)
        .header("X-Voxply-Signature", &sig_hex)
        .header("X-Voxply-Timestamp", timestamp.to_string())
        .body(body_json)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(_) => {
            return Some(format!("Bot @{} failed to respond.", matched.bot_name));
        }
    };

    if !resp.status().is_success() {
        return Some(format!("Bot @{} failed to respond.", matched.bot_name));
    }

    let bot_response: BotResponse = match resp.json().await {
        Ok(r) => r,
        Err(_) => {
            return Some(format!("Bot @{} failed to respond.", matched.bot_name));
        }
    };

    // Process bot reply.
    if let Some(reply) = bot_response.reply {
        let ephemeral = bot_response.ephemeral.unwrap_or(false);
        let msg_id = Uuid::new_v4().to_string();
        let now = crate::auth::handlers::unix_timestamp();

        let visible_to: Option<&str> = if ephemeral {
            Some(invoker_pubkey)
        } else {
            None
        };

        let embeds_json = reply.embeds.as_ref().and_then(|e| {
            if e.is_empty() {
                None
            } else {
                serde_json::to_string(e).ok()
            }
        });

        sqlx::query(
            "INSERT INTO messages(id, channel_id, sender, content, created_at, visible_to_pubkey, embeds)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(&msg_id)
        .bind(channel_id)
        .bind(&matched.bot_pubkey)
        .bind(&reply.body)
        .bind(now)
        .bind(visible_to)
        .bind(&embeds_json)
        .execute(&state.db)
        .await
        .ok();

        // Look up bot display name.
        let bot_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(&matched.bot_pubkey)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let message = MessageResponse {
            id: msg_id,
            channel_id: channel_id.to_string(),
            sender: matched.bot_pubkey,
            sender_name: bot_name.or(Some(matched.bot_name)),
            content: reply.body,
            created_at: now,
            edited_at: None,
            attachments: Vec::new(),
            reactions: Vec::new(),
            reply_to: None,
            visible_to_pubkey: visible_to.map(|s| s.to_string()),
        };

        {
            let ws_msg = WsServerMessage::ChatMessage {
                channel_id: channel_id.to_string(),
                message: message.clone(),
            };
            let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
            let _ = state.chat_tx.send((ChatEvent::New { channel_id: channel_id.to_string(), message }, json));
        }
    }

    // Slash command was handled (or deferred) — signal to caller not to store.
    // Return None means "no error, command was dispatched successfully".
    None
}

/// Build and return an ephemeral error message row, inserting it into the DB
/// and broadcasting it. The broadcast carries `visible_to_pubkey` so WS
/// filtering in `ws.rs` ensures only the invoker sees it.
pub async fn insert_ephemeral_error(
    state: &Arc<AppState>,
    channel_id: &str,
    invoker_pubkey: &str,
    error_text: &str,
) -> Result<(), (StatusCode, String)> {
    let err_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO messages(id, channel_id, sender, content, created_at, visible_to_pubkey)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&err_id)
    .bind(channel_id)
    .bind(invoker_pubkey)
    .bind(error_text)
    .bind(now)
    .bind(invoker_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let message = MessageResponse {
        id: err_id,
        channel_id: channel_id.to_string(),
        sender: invoker_pubkey.to_string(),
        sender_name: None,
        content: error_text.to_string(),
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: Some(invoker_pubkey.to_string()),
    };

    {
        let ws_msg = WsServerMessage::ChatMessage {
            channel_id: channel_id.to_string(),
            message: message.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ChatEvent::New { channel_id: channel_id.to_string(), message }, json));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Component interaction dispatch (WS → bot webhook → apply response)
// ---------------------------------------------------------------------------

/// Handle a `component_interaction` WS message from a user.
///
/// Looks up the message's bot author, checks channel scope, POSTs to the
/// bot's webhook (signed the same way as slash dispatch), then applies the
/// `ComponentResponse` (update / ephemeral_reply / defer).
///
/// Errors are logged and swallowed — the WS handler has already sent the
/// rate-limit check; any further errors are treated as no-op from the user's
/// perspective.
pub async fn dispatch_component(
    state: &Arc<AppState>,
    message_id: &str,
    custom_id: &str,
    values: &[String],
    user_pubkey: &str,
) {
    // Load the message's channel and sender.
    #[derive(sqlx::FromRow)]
    struct MsgInfo {
        channel_id: String,
        sender: String,
    }

    let msg_info: Option<MsgInfo> = sqlx::query_as::<_, MsgInfo>(
        "SELECT channel_id, sender FROM messages WHERE id = ?",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let msg_info = match msg_info {
        Some(m) => m,
        None => {
            tracing::warn!("dispatch_component: message {message_id} not found");
            return;
        }
    };

    // Verify the sender is a bot.
    let is_bot: Option<i64> = sqlx::query_scalar(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&msg_info.sender)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .flatten();

    if is_bot != Some(1) {
        // Message not from a bot — components shouldn't fire on normal messages.
        return;
    }

    // Get the bot's webhook_url from bot_profiles.
    let webhook_url: Option<String> = sqlx::query_scalar(
        "SELECT webhook_url FROM bot_profiles WHERE pubkey = ?",
    )
    .bind(&msg_info.sender)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .flatten();

    let webhook_url = match webhook_url {
        Some(u) if !u.is_empty() => u,
        _ => return, // No webhook — nothing to do.
    };

    // Check channel scope for this bot.
    let in_scope: bool = sqlx::query_scalar::<_, i64>(
        "SELECT CASE
           WHEN NOT EXISTS (SELECT 1 FROM bot_channel_scope WHERE bot_pubkey = ?)
           THEN 1
           ELSE (SELECT COUNT(*) FROM bot_channel_scope WHERE bot_pubkey = ? AND channel_id = ?)
         END",
    )
    .bind(&msg_info.sender)
    .bind(&msg_info.sender)
    .bind(&msg_info.channel_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(1)
        != 0;

    if !in_scope {
        return;
    }

    // Look up user's display name.
    let user_name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM users WHERE public_key = ?",
    )
    .bind(user_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let hub_url = hub_url(state).await;

    let payload = ComponentInteraction {
        kind: "component_interaction".to_string(),
        hub_url: hub_url.clone(),
        channel_id: msg_info.channel_id.clone(),
        message_id: message_id.to_string(),
        custom_id: custom_id.to_string(),
        values: values.to_vec(),
        user: AuthorInfo {
            pubkey: user_pubkey.to_string(),
            display_name: user_name,
        },
    };

    let body_json = match serde_json::to_string(&payload) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("dispatch_component: serialize error: {e}");
            return;
        }
    };

    let hub_pubkey = state.hub_identity.public_key_hex();
    let body_bytes = body_json.as_bytes();
    let signature = state.hub_identity.sign(body_bytes);
    let sig_hex = hex::encode(signature.to_bytes());
    let timestamp = crate::auth::handlers::unix_timestamp();

    let resp = state
        .http_client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-Voxply-Hub-Pubkey", &hub_pubkey)
        .header("X-Voxply-Signature", &sig_hex)
        .header("X-Voxply-Timestamp", timestamp.to_string())
        .body(body_json)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!("dispatch_component: bot returned HTTP {}", r.status());
            return;
        }
        Err(e) => {
            tracing::warn!("dispatch_component: webhook error: {e}");
            return;
        }
    };

    let component_resp: ComponentResponse = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("dispatch_component: parse response error: {e}");
            return;
        }
    };

    apply_component_response(
        state,
        component_resp,
        message_id,
        &msg_info.channel_id,
        &msg_info.sender,
        user_pubkey,
    )
    .await;
}

async fn apply_component_response(
    state: &Arc<AppState>,
    resp: ComponentResponse,
    message_id: &str,
    channel_id: &str,
    bot_pubkey: &str,
    interacting_user: &str,
) {
    // defer: hub does nothing; bot will post asynchronously.
    if resp.defer.unwrap_or(false) {
        return;
    }

    // update: PATCH the message body and/or components.
    if let Some(ComponentUpdate { body, components }) = resp.update {
        let now = crate::auth::handlers::unix_timestamp();

        if let Some(new_body) = &body {
            let _ = sqlx::query(
                "UPDATE messages SET content = ?, edited_at = ? WHERE id = ?",
            )
            .bind(new_body)
            .bind(now)
            .bind(message_id)
            .execute(&state.db)
            .await;
        }

        if let Some(rows) = &components {
            // Replace all components for this message.
            let _ = sqlx::query("DELETE FROM message_components WHERE message_id = ?")
                .bind(message_id)
                .execute(&state.db)
                .await;

            let components_json = serde_json::to_string(rows).unwrap_or_default();
            // Store as a single config_json blob in row 0.
            let comp_id = Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO message_components(id, message_id, row_idx, component_idx, type, config_json)
                 VALUES(?,?,0,0,'rows',?)",
            )
            .bind(&comp_id)
            .bind(message_id)
            .bind(&components_json)
            .execute(&state.db)
            .await;
        }

        // Reload and broadcast the updated message.
        if let Ok(updated) = load_updated_message(state, message_id).await {
            let ws_msg = WsServerMessage::MessageEdited {
                channel_id: channel_id.to_string(),
                message: updated.clone(),
            };
            let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
            let _ = state.chat_tx.send((ChatEvent::Edited { channel_id: channel_id.to_string(), message: updated }, json));
        }
    }

    // ephemeral_reply: insert an ephemeral message visible only to the interacting user.
    if let Some(EphemeralReply { body }) = resp.ephemeral_reply {
        let msg_id = Uuid::new_v4().to_string();
        let now = crate::auth::handlers::unix_timestamp();

        let _ = sqlx::query(
            "INSERT INTO messages(id, channel_id, sender, content, created_at, visible_to_pubkey)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(&msg_id)
        .bind(channel_id)
        .bind(bot_pubkey)
        .bind(&body)
        .bind(now)
        .bind(interacting_user)
        .execute(&state.db)
        .await;

        let bot_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(bot_pubkey)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let message = MessageResponse {
            id: msg_id,
            channel_id: channel_id.to_string(),
            sender: bot_pubkey.to_string(),
            sender_name: bot_name,
            content: body,
            created_at: now,
            edited_at: None,
            attachments: Vec::new(),
            reactions: Vec::new(),
            reply_to: None,
            visible_to_pubkey: Some(interacting_user.to_string()),
        };

        {
            let ws_msg = WsServerMessage::ChatMessage {
                channel_id: channel_id.to_string(),
                message: message.clone(),
            };
            let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
            let _ = state.chat_tx.send((ChatEvent::New { channel_id: channel_id.to_string(), message }, json));
        }
    }
}

async fn load_updated_message(
    state: &Arc<AppState>,
    message_id: &str,
) -> Result<MessageResponse, sqlx::Error> {
    let row: (String, String, Option<String>, String, i64, Option<i64>) = sqlx::query_as(
        "SELECT m.channel_id, m.sender, u.display_name, m.content, m.created_at, m.edited_at
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = ?",
    )
    .bind(message_id)
    .fetch_one(&state.db)
    .await?;

    Ok(MessageResponse {
        id: message_id.to_string(),
        channel_id: row.0,
        sender: row.1,
        sender_name: row.2,
        content: row.3,
        created_at: row.4,
        edited_at: row.5,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: None,
    })
}
