//! Background worker that periodically issues certifications to eligible members.
//!
//! Eligibility criteria:
//!  1. Member has existed at least `cert_standing_days` days.
//!  2. Member is `approval_status = 'approved'` and not banned.
//!  3. No existing non-expired, non-revoked cert from this hub.
//!  4. `cert_auto_issue` setting is 'true'.
//!
//! The worker wakes once per day (configurable via POLL_INTERVAL) and sweeps
//! all eligible members, skipping any that already have a fresh cert.

use std::sync::Arc;
use std::time::Duration;

use crate::routes::certs::issue_cert_for;
use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(86400); // 24 hours

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("Cert worker tick failed: {e}");
            }
        }
    });
}

/// Run a single issuance sweep. Public for tests.
pub async fn tick(state: &AppState) -> anyhow::Result<()> {
    // Check auto-issue setting
    let auto_issue: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_auto_issue'",
    )
    .fetch_optional(&state.db)
    .await?
    .map(|v| v == "true")
    .unwrap_or(true);

    if !auto_issue {
        return Ok(());
    }

    let standing_days: i64 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_standing_days'",
    )
    .fetch_optional(&state.db)
    .await?
    .and_then(|v| v.parse().ok())
    .unwrap_or(30);

    let validity_days: i64 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_validity_days'",
    )
    .fetch_optional(&state.db)
    .await?
    .and_then(|v| v.parse().ok())
    .unwrap_or(90);

    let now = crate::auth::handlers::unix_timestamp();
    let threshold = now - standing_days * 86400;

    // Find approved, non-banned users who joined before the threshold
    // and whose most recent non-revoked cert from this hub has either expired
    // or does not exist.
    let cert_cutoff = now - validity_days * 86400; // re-issue if existing cert is old

    // Candidates: approved users with first_seen_at <= threshold.
    // We LEFT JOIN on cert_issuances to find those without a fresh, non-revoked cert.
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT u.public_key
         FROM users u
         LEFT JOIN (
             SELECT subject_pubkey, MAX(issued_at) AS latest_issued
             FROM cert_issuances
             WHERE standing = 'good' AND revoked_at IS NULL
             GROUP BY subject_pubkey
         ) ci ON ci.subject_pubkey = u.public_key
         WHERE u.approval_status = 'approved'
           AND COALESCE(u.is_bot, 0) = 0
           AND u.first_seen_at <= ?
           AND (ci.latest_issued IS NULL OR ci.latest_issued < ?)
         LIMIT 500",
    )
    .bind(threshold)
    .bind(cert_cutoff)
    .fetch_all(&state.db)
    .await?;

    if candidates.is_empty() {
        return Ok(());
    }

    tracing::info!("Cert worker: sweeping {} candidates", candidates.len());

    // Load banned pubkeys in one query to avoid per-user ban checks.
    let banned: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT target_public_key FROM bans",
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .collect();

    let mut issued = 0usize;
    for pubkey in candidates {
        if banned.contains(&pubkey) {
            continue;
        }
        match issue_cert_for(state, &pubkey).await {
            Ok(_) => { issued += 1; }
            Err((code, msg)) => {
                tracing::debug!(
                    "Cert worker skipped {}: HTTP {} — {msg}",
                    &pubkey[..16.min(pubkey.len())],
                    code,
                );
            }
        }
    }

    tracing::info!("Cert worker: issued {issued} new certs");
    Ok(())
}
