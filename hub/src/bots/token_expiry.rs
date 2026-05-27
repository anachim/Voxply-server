//! Background worker that pushes `token_expiring_soon` to bot WS sessions
//! whose session token expires within 72 hours and haven't been warned yet.
//!
//! Mirrors the dm_worker pattern: `spawn` starts a tokio task, `tick` does
//! one pass and is public for direct test usage.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(3600); // hourly
const WARN_WINDOW_SECS: i64 = 72 * 3600;

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("token_expiry tick failed: {e}");
            }
        }
    });
}

/// One pass: find bot sessions expiring soon, push the warning over WS.
pub async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::auth::handlers::unix_timestamp();
    let warn_before = now + WARN_WINDOW_SECS;

    // Find bot sessions expiring within the window that haven't been warned.
    #[derive(sqlx::FromRow)]
    struct SessionRow {
        token: String,
        public_key: String,
        expires_at: i64,
    }

    let rows: Vec<SessionRow> = sqlx::query_as::<_, SessionRow>(
        "SELECT s.token, s.public_key, s.expires_at
         FROM sessions s
         JOIN users u ON u.public_key = s.public_key
         WHERE u.is_bot = 1
           AND s.expires_at IS NOT NULL
           AND s.expires_at <= ?
           AND s.expiry_warned_at IS NULL",
    )
    .bind(warn_before)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    let sessions = state.bot_sessions.read().await;

    for row in &rows {
        // Push the warning over the bot's active WS session (if connected).
        if let Some(tx) = sessions.get(&row.public_key) {
            let msg = serde_json::json!({
                "type": "token_expiring_soon",
                "expires_at": row.expires_at,
            });
            let _ = tx.try_send(msg.to_string());
        }

        // Mark as warned regardless of whether the bot is currently connected.
        let _ = sqlx::query(
            "UPDATE sessions SET expiry_warned_at = ? WHERE token = ?",
        )
        .bind(now)
        .bind(&row.token)
        .execute(&state.db)
        .await;
    }

    Ok(())
}
