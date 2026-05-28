use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    // Discovery aggregator listing. One row per registered farm.
    // farm_url is the primary key — re-registration is an upsert.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS registered_farms (
            farm_url            TEXT PRIMARY KEY,
            farm_pubkey         TEXT NOT NULL,
            name                TEXT NOT NULL,
            description         TEXT,
            country             TEXT,
            region              TEXT,
            languages           TEXT NOT NULL DEFAULT '[\"en\"]',
            tags                TEXT NOT NULL DEFAULT '[]',
            hub_count           INTEGER NOT NULL DEFAULT 0,
            max_hubs_total      INTEGER,
            capacity_pct        INTEGER,
            geo_unverified      INTEGER NOT NULL DEFAULT 0,
            last_verified_at    INTEGER NOT NULL,
            registered_at       INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}
