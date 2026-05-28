/// Background revalidation task for the discovery aggregator.
///
/// Runs every 6 hours. For each registered farm:
///   - Fetches `GET {farm_url}/farm/public-info`.
///   - If the fetch fails or `allow_discovery_listing != true`: removes the row.
///   - If successful: updates hub_count, max_hubs_total, capacity_pct, last_verified_at.
///
/// Mirrors the dm_worker.rs spawn-loop pattern.
use std::sync::Arc;
use std::time::Duration;

use crate::state::SeedState;

/// Interval between revalidation sweeps.
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

pub fn spawn(state: Arc<SeedState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REVALIDATION_INTERVAL).await;
            match tick(&state).await {
                Ok((checked, removed)) => {
                    tracing::info!(
                        "Revalidated {checked} farms, removed {removed}"
                    );
                }
                Err(e) => {
                    tracing::warn!("Revalidation tick failed: {e}");
                }
            }
        }
    });
}

/// One sweep. Returns `(farms_checked, farms_removed)`.
pub async fn tick(state: &SeedState) -> anyhow::Result<(usize, usize)> {
    // Load all registered farm URLs and their pubkeys.
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT farm_url FROM registered_farms ORDER BY farm_url")
            .fetch_all(&state.db)
            .await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut checked = 0usize;
    let mut removed = 0usize;

    for (farm_url,) in rows {
        checked += 1;
        let probe_url = format!("{}/farm/public-info", farm_url.trim_end_matches('/'));

        let result = state.http_client.get(&probe_url).send().await;

        let keep = match result {
            Err(_) => false,
            Ok(resp) if !resp.status().is_success() => false,
            Ok(resp) => {
                match resp.json::<serde_json::Value>().await {
                    Err(_) => false,
                    Ok(info) => {
                        info.get("allow_discovery_listing")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    }
                }
            }
        };

        if !keep {
            sqlx::query("DELETE FROM registered_farms WHERE farm_url = ?")
                .bind(&farm_url)
                .execute(&state.db)
                .await?;
            removed += 1;
            tracing::debug!("Removed stale/opted-out farm: {farm_url}");
            continue;
        }

        // Re-fetch to extract fresh hub counts (reuse a second request to keep logic simple;
        // the first response was already consumed above via .json()).
        if let Ok(resp2) = state.http_client.get(&probe_url).send().await {
            if let Ok(info) = resp2.json::<serde_json::Value>().await {
                let hub_count = info
                    .get("hub_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let max_hubs_total: Option<i64> = info
                    .get("max_hubs_total")
                    .and_then(|v| v.as_i64())
                    .filter(|&v| v > 0);
                let capacity_pct: Option<i64> = max_hubs_total.map(|cap| {
                    if cap <= 0 {
                        0
                    } else {
                        ((hub_count * 100) / cap).min(100)
                    }
                });

                let _ = sqlx::query(
                    "UPDATE registered_farms
                     SET hub_count = ?, max_hubs_total = ?, capacity_pct = ?, last_verified_at = ?
                     WHERE farm_url = ?",
                )
                .bind(hub_count)
                .bind(max_hubs_total)
                .bind(capacity_pct)
                .bind(now)
                .bind(&farm_url)
                .execute(&state.db)
                .await;
            }
        }
    }

    Ok((checked, removed))
}
