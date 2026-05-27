//! Hub event fan-out: writes audit log rows and pushes `hub_event` envelopes
//! to subscribed bot WS sessions.
//!
//! Call `publish_hub_event` from any server-side broadcast point (ws.rs,
//! messages.rs, channels.rs, moderation.rs) after the underlying action
//! has been committed to the DB.

use std::sync::Arc;

use uuid::Uuid;

use crate::state::AppState;

/// Publish a hub event.
///
/// - Writes a row to `hub_audit_log`.
/// - Queries `bot_subscriptions` for all bots interested in `event_type` (and
///   optionally `channel_id`).
/// - For each subscribed bot with an active WS session, checks `bot_channel_scope`
///   and for `message.*` events checks `can_read_message_content`.
/// - Pushes a `hub_event` JSON envelope over the bot's WS sender.
///
/// Errors are logged and swallowed — event delivery is best-effort.
pub async fn publish_hub_event(
    state: &Arc<AppState>,
    event_type: &str,
    actor_pubkey: Option<&str>,
    target_pubkey: Option<&str>,
    channel_id: Option<&str>,
    payload: serde_json::Value,
) {
    let seq = match next_seq(state).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("publish_hub_event: failed to get seq: {e}");
            return;
        }
    };

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let payload_json = payload.to_string();

    if let Err(e) = sqlx::query(
        "INSERT INTO hub_audit_log(id, seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(seq)
    .bind(event_type)
    .bind(now)
    .bind(actor_pubkey)
    .bind(target_pubkey)
    .bind(channel_id)
    .bind(&payload_json)
    .execute(&state.db)
    .await
    {
        tracing::warn!("publish_hub_event: failed to write audit log: {e}");
        return;
    }

    // Fetch the hub_url once.
    let hub_url = crate::bots::dispatch::hub_url_public(state).await;

    // Query all bots subscribed to this event_type, hub-wide or for this channel.
    // A subscription row with channel_id = '' means hub-wide (no channel filter).
    #[derive(sqlx::FromRow)]
    struct SubRow {
        bot_pubkey: String,
    }

    let subs: Vec<SubRow> = sqlx::query_as::<_, SubRow>(
        "SELECT DISTINCT bot_pubkey FROM bot_subscriptions
         WHERE event_type = ?
           AND (channel_id = '' OR channel_id = ?)",
    )
    .bind(event_type)
    .bind(channel_id.unwrap_or(""))
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if subs.is_empty() {
        return;
    }

    let sessions = state.bot_sessions.read().await;

    for sub in &subs {
        let Some(tx) = sessions.get(&sub.bot_pubkey) else {
            continue;
        };

        // Check bot_channel_scope: if the bot has any scope rows, the event's
        // channel_id must be in scope (or event has no channel).
        if let Some(ch_id) = channel_id {
            let in_scope: bool = sqlx::query_scalar::<_, i64>(
                "SELECT
                   CASE
                     WHEN NOT EXISTS (SELECT 1 FROM bot_channel_scope WHERE bot_pubkey = ?)
                     THEN 1
                     ELSE (SELECT COUNT(*) FROM bot_channel_scope WHERE bot_pubkey = ? AND channel_id = ?)
                   END",
            )
            .bind(&sub.bot_pubkey)
            .bind(&sub.bot_pubkey)
            .bind(ch_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(1)
                != 0;

            if !in_scope {
                continue;
            }
        }

        // For message.* events: respect can_read_message_content.
        let envelope_payload = if event_type.starts_with("message.") {
            maybe_redact_message_content(state, &sub.bot_pubkey, payload.clone()).await
        } else {
            payload.clone()
        };

        let envelope = serde_json::json!({
            "type": "hub_event",
            "seq": seq,
            "event": event_type,
            "hub_url": hub_url,
            "at": now,
            "payload": envelope_payload,
        });

        let json = envelope.to_string();
        // Non-blocking send; if the channel is full the event is dropped for
        // this bot (back-pressure is acceptable for best-effort delivery).
        let _ = tx.try_send(json);
    }
}

/// Replay audit log rows for a bot starting from `since_seq + 1`, filtered
/// to the bot's subscriptions and channel scope.
///
/// Returns `(rows_sent, earliest_seq_in_window, earliest_at_in_window)`.
/// If `since_seq` is outside the 72-hour window, returns the earliest
/// available row information so the caller can send `replay_unavailable`.
pub async fn replay_events_for_bot(
    state: &Arc<AppState>,
    bot_pubkey: &str,
    since_seq: i64,
    tx: &tokio::sync::mpsc::Sender<String>,
) -> ReplayResult {
    let now = crate::auth::handlers::unix_timestamp();
    let window_start = now - 72 * 3600;

    // Find the earliest seq still in the window.
    let earliest: Option<(i64, i64)> = sqlx::query_as(
        "SELECT seq, at FROM hub_audit_log WHERE at >= ? ORDER BY seq ASC LIMIT 1",
    )
    .bind(window_start)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let (earliest_seq, earliest_at) = match earliest {
        Some((s, a)) => (s, a),
        None => {
            // Nothing in the window at all — nothing to replay.
            return ReplayResult::Complete { replayed: 0 };
        }
    };

    // If since_seq is before the window, signal unavailable.
    if since_seq < earliest_seq - 1 {
        return ReplayResult::Unavailable {
            earliest_seq,
            earliest_at,
        };
    }

    // Collect the bot's subscribed event_types.
    let sub_events: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT event_type FROM bot_subscriptions WHERE bot_pubkey = ?",
    )
    .bind(bot_pubkey)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if sub_events.is_empty() {
        return ReplayResult::Complete { replayed: 0 };
    }

    // Fetch rows in order from since_seq+1.
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

    // We batch rows in memory — for large gaps this could be large but the
    // 72h window is a hard limit so total rows is bounded.
    let rows: Vec<AuditRow> = sqlx::query_as::<_, AuditRow>(
        "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
         FROM hub_audit_log
         WHERE seq > ? AND at >= ?
         ORDER BY seq ASC",
    )
    .bind(since_seq)
    .bind(window_start)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let hub_url = crate::bots::dispatch::hub_url_public(state).await;
    let mut replayed = 0usize;
    let batch_size = 100usize;
    let mut batch_count = 0usize;

    for row in &rows {
        // Filter by subscription.
        if !sub_events.iter().any(|e| e == &row.event_type) {
            continue;
        }

        // Channel scope check.
        if let Some(ref ch_id) = row.channel_id {
            let in_scope: bool = sqlx::query_scalar::<_, i64>(
                "SELECT CASE
                   WHEN NOT EXISTS (SELECT 1 FROM bot_channel_scope WHERE bot_pubkey = ?)
                   THEN 1
                   ELSE (SELECT COUNT(*) FROM bot_channel_scope WHERE bot_pubkey = ? AND channel_id = ?)
                 END",
            )
            .bind(bot_pubkey)
            .bind(bot_pubkey)
            .bind(ch_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(1)
                != 0;

            if !in_scope {
                continue;
            }
        }

        let payload: serde_json::Value =
            serde_json::from_str(&row.payload_json).unwrap_or(serde_json::Value::Null);

        let envelope_payload = if row.event_type.starts_with("message.") {
            maybe_redact_message_content(state, bot_pubkey, payload).await
        } else {
            payload
        };

        let envelope = serde_json::json!({
            "type": "hub_event",
            "seq": row.seq,
            "event": row.event_type,
            "hub_url": hub_url,
            "at": row.at,
            "actor_pubkey": row.actor_pubkey,
            "target_pubkey": row.target_pubkey,
            "channel_id": row.channel_id,
            "payload": envelope_payload,
            "replayed": true,
        });

        if tx.send(envelope.to_string()).await.is_err() {
            // Bot disconnected mid-replay.
            break;
        }

        replayed += 1;
        batch_count += 1;

        // Yield every `batch_size` messages so we don't starve the tokio
        // runtime on a large replay.
        if batch_count >= batch_size {
            batch_count = 0;
            tokio::task::yield_now().await;
        }
    }

    ReplayResult::Complete { replayed }
}

pub enum ReplayResult {
    Complete { replayed: usize },
    Unavailable { earliest_seq: i64, earliest_at: i64 },
}

/// Return the current live seq (from hub_audit_seq).
pub async fn current_seq(state: &AppState) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT seq FROM hub_audit_seq WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
}

/// Atomically increment the sequence counter and return the new value.
async fn next_seq(state: &AppState) -> Result<i64, sqlx::Error> {
    sqlx::query("UPDATE hub_audit_seq SET seq = seq + 1 WHERE id = 1")
        .execute(&state.db)
        .await?;
    sqlx::query_scalar::<_, i64>("SELECT seq FROM hub_audit_seq WHERE id = 1")
        .fetch_one(&state.db)
        .await
}

/// If the bot does NOT have `can_read_message_content` in its capabilities,
/// strip `content`/`attachments` from the payload and add `content_preview`
/// (first 100 chars of content).
async fn maybe_redact_message_content(
    state: &AppState,
    bot_pubkey: &str,
    mut payload: serde_json::Value,
) -> serde_json::Value {
    let caps_json: Option<String> = sqlx::query_scalar(
        "SELECT capabilities FROM bot_profiles WHERE pubkey = ?",
    )
    .bind(bot_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let caps: Vec<String> = caps_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let can_read = caps.iter().any(|c| c == "can_read_message_content");

    if !can_read {
        if let Some(obj) = payload.as_object_mut() {
            let preview: Option<String> = obj
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.chars().take(100).collect());

            obj.remove("content");
            obj.remove("attachments");

            if let Some(p) = preview {
                obj.insert("content_preview".to_string(), serde_json::Value::String(p));
            }
        }
    }

    payload
}
