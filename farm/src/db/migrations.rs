use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    // Farm singleton metadata — always id=1.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farms (
            id                  INTEGER PRIMARY KEY CHECK(id = 1),
            public_key          TEXT NOT NULL,
            name                TEXT NOT NULL DEFAULT 'My Farm',
            description         TEXT,
            directory_public    INTEGER NOT NULL DEFAULT 0,
            created_at          INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Canonical per-farm user identity.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_users (
            public_key      TEXT PRIMARY KEY,
            master_pubkey   TEXT,
            first_seen_at   INTEGER NOT NULL,
            last_seen_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Short-lived challenge nonces (60s TTL, swept on read).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_challenges (
            public_key      TEXT PRIMARY KEY,
            challenge_hex   TEXT NOT NULL,
            expires_at      INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Issued session records (the token itself is the signed blob — not stored here).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_sessions (
            jti         TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL REFERENCES farm_users(public_key),
            issued_at   INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            revoked_at  INTEGER,
            scope       TEXT NOT NULL DEFAULT 'member'
        )",
    )
    .execute(pool)
    .await?;

    // Phase 2: per-hub process registry.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hubs (
            id                  TEXT PRIMARY KEY,
            owner_pubkey        TEXT NOT NULL,
            name                TEXT NOT NULL,
            description         TEXT,
            visibility          TEXT NOT NULL DEFAULT 'private'
                                    CHECK(visibility IN ('public', 'private')),
            process_port        INTEGER,
            db_path             TEXT NOT NULL,
            created_at          INTEGER NOT NULL,
            suspended_at        INTEGER,
            suspension_reason   TEXT,
            deleted_at          INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // Phase 2: admin_pubkey on the farms singleton (first operator who sets it becomes admin).
    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN admin_pubkey TEXT")
        .execute(pool)
        .await;

    // Phase 3A: creation policy and quota columns.
    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN creation_policy TEXT NOT NULL DEFAULT 'admin_only'
         CHECK(creation_policy IN ('open', 'admin_only', 'disabled'))",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN max_hubs_per_user INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN max_hubs_total INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN allow_discovery_listing INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // Phase 3E: locality and discovery metadata columns.
    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN languages TEXT NOT NULL DEFAULT '[\"en\"]'")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN country TEXT")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN region TEXT")
        .execute(pool)
        .await;

    // Phase 3B: revoked_manually flag on farm_sessions for admin-initiated revocations.
    let _ = sqlx::query(
        "ALTER TABLE farm_sessions ADD COLUMN revoked_manually INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    Ok(())
}
