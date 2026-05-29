use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            public_key    TEXT PRIMARY KEY,
            display_name  TEXT,
            first_seen_at INTEGER NOT NULL,
            last_seen_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            public_key TEXT NOT NULL REFERENCES users(public_key),
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channels (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL UNIQUE,
            created_by    TEXT NOT NULL REFERENCES users(public_key),
            parent_id     TEXT REFERENCES channels(id),
            is_category   INTEGER NOT NULL DEFAULT 0,
            display_order INTEGER NOT NULL DEFAULT 0,
            description   TEXT,
            created_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Additive migrations for pre-existing databases (ignore errors — columns may already exist)
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN parent_id TEXT REFERENCES channels(id)")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN is_category INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN description TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN icon TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN color TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN custom_icon_svg TEXT")
        .execute(pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS messages (
            id         TEXT PRIMARY KEY,
            channel_id TEXT NOT NULL REFERENCES channels(id),
            sender     TEXT NOT NULL REFERENCES users(public_key),
            content    TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            edited_at  INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // Attachments JSON column: a serialized Vec<Attachment>. NULL/empty for
    // legacy rows. We store inline base64 here rather than a side table since
    // the size cap (~3 MB) keeps this manageable.
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN attachments TEXT")
        .execute(pool)
        .await;

    // Optional parent message id for threaded replies. We don't FK to
    // messages.id because the parent might get deleted later -- the reply
    // simply renders without a preview when the parent is gone.
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN reply_to TEXT")
        .execute(pool)
        .await;

    // One row per (message, emoji, user). PRIMARY KEY collapses re-reacts
    // into idempotent inserts.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_reactions (
            message_id  TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            emoji       TEXT NOT NULL,
            user_key    TEXT NOT NULL REFERENCES users(public_key),
            created_at  INTEGER NOT NULL,
            PRIMARY KEY (message_id, emoji, user_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions(message_id)",
    )
    .execute(pool)
    .await?;

    // Additive migration for older DBs
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN edited_at INTEGER")
        .execute(pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS peers (
            public_key TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            url        TEXT NOT NULL,
            added_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_channels (
            id              TEXT PRIMARY KEY,
            peer_public_key TEXT NOT NULL REFERENCES peers(public_key),
            remote_id       TEXT NOT NULL,
            name            TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            last_synced_at  INTEGER NOT NULL,
            UNIQUE(peer_public_key, remote_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_messages (
            id             TEXT PRIMARY KEY,
            fed_channel_id TEXT NOT NULL REFERENCES federated_channels(id),
            remote_id      TEXT NOT NULL,
            sender         TEXT NOT NULL,
            content        TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            UNIQUE(fed_channel_id, remote_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS roles (
            id                 TEXT PRIMARY KEY,
            name               TEXT NOT NULL UNIQUE,
            priority           INTEGER NOT NULL DEFAULT 0,
            display_separately INTEGER NOT NULL DEFAULT 0,
            created_at         INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    let _ = sqlx::query(
        "ALTER TABLE roles ADD COLUMN display_separately INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS role_permissions (
            role_id    TEXT NOT NULL REFERENCES roles(id),
            permission TEXT NOT NULL,
            PRIMARY KEY (role_id, permission)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_roles (
            user_public_key TEXT NOT NULL REFERENCES users(public_key),
            role_id         TEXT NOT NULL REFERENCES roles(id),
            assigned_at     INTEGER NOT NULL,
            PRIMARY KEY (user_public_key, role_id)
        )",
    )
    .execute(pool)
    .await?;

    // Seed built-in roles
    sqlx::query(
        "INSERT OR IGNORE INTO roles (id, name, priority, created_at) VALUES ('builtin-everyone', '@everyone', 0, 0)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO roles (id, name, priority, created_at) VALUES ('builtin-owner', 'Owner', 999999, 0)",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'send_messages')")
        .execute(pool).await?;
    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'read_messages')")
        .execute(pool).await?;
    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'admin')")
        .execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bans (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            banned_by  TEXT NOT NULL,
            reason     TEXT,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mutes (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            muted_by   TEXT NOT NULL,
            reason     TEXT,
            expires_at INTEGER,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invites (
            code       TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            max_uses   INTEGER,
            uses       INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Hub settings (key-value store for simple config)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Default: hub is open (no invite required)
    sqlx::query("INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('invite_only', 'false')")
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('min_security_level', '0')",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('require_approval', 'false')",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('max_channel_depth', '0')",
    )
    .execute(pool)
    .await?;

    // Approval state per user. 'approved' for existing users (default), 'pending'
    // for new sign-ups when require_approval is on.
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query("ALTER TABLE users ADD COLUMN avatar TEXT")
        .execute(pool)
        .await;

    // Multi-device: NULL for legacy single-key users, set for users
    // who have authenticated at least once with a master-signed
    // SubkeyCert. The canonical user identity is `users.public_key`
    // for everyone — this column just records which master "owns"
    // the row, so a second paired device authenticating with the
    // same master finds the existing row.
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN master_pubkey TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_users_master_pubkey ON users(master_pubkey)",
    )
    .execute(pool)
    .await;

    // Games installed per hub (admin installs a manifest; all members can play).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_games (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            description    TEXT,
            version        TEXT NOT NULL,
            entry_url      TEXT NOT NULL,
            thumbnail_url  TEXT,
            author         TEXT,
            min_players    INTEGER NOT NULL DEFAULT 1,
            max_players    INTEGER NOT NULL DEFAULT 1,
            installed_by   TEXT NOT NULL REFERENCES users(public_key),
            installed_at   INTEGER NOT NULL,
            manifest_url   TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliances (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_members (
            alliance_id    TEXT NOT NULL REFERENCES alliances(id),
            hub_public_key TEXT NOT NULL,
            hub_name       TEXT NOT NULL,
            hub_url        TEXT NOT NULL,
            joined_at      INTEGER NOT NULL,
            PRIMARY KEY (alliance_id, hub_public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_shared_channels (
            alliance_id TEXT NOT NULL REFERENCES alliances(id),
            channel_id  TEXT NOT NULL REFERENCES channels(id),
            shared_at   INTEGER NOT NULL,
            PRIMARY KEY (alliance_id, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_bans (
            channel_id TEXT NOT NULL REFERENCES channels(id),
            target_public_key TEXT NOT NULL REFERENCES users(public_key),
            banned_by TEXT NOT NULL,
            reason TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (channel_id, target_public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS voice_mutes (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            muted_by TEXT NOT NULL,
            reason TEXT,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Add min_talk_power column to channels (0 = anyone can talk)
    // Using a separate table since ALTER TABLE IF NOT EXISTS isn't clean in SQLite
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_settings (
            channel_id      TEXT PRIMARY KEY REFERENCES channels(id),
            min_talk_power  INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // Conversations (DM / group DM) — only tracks members, NOT message content
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conversations (
            id         TEXT PRIMARY KEY,
            conv_type  TEXT NOT NULL DEFAULT 'dm',
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id TEXT NOT NULL REFERENCES conversations(id),
            public_key      TEXT NOT NULL REFERENCES users(public_key),
            joined_at       INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS friends (
            user_a TEXT NOT NULL REFERENCES users(public_key),
            user_b TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            hub_url TEXT,
            display_name TEXT,
            PRIMARY KEY (user_a, user_b)
        )",
    )
    .execute(pool)
    .await?;

    // Cross-hub friends: hub_url is where the friend is reachable; display_name
    // is a cached snapshot (their hub may rename them later, we'll resync). Both
    // are NULL for same-hub friends, where we look up the local users table.
    let _ = sqlx::query("ALTER TABLE friends ADD COLUMN hub_url TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE friends ADD COLUMN display_name TEXT")
        .execute(pool)
        .await;

    // Persisted DM messages (both local and federated deliveries land here)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_messages (
            id              TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender          TEXT NOT NULL,
            content         TEXT NOT NULL,
            signature       TEXT,
            created_at      INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Attachments JSON for DMs, mirroring the channel-message pattern.
    let _ = sqlx::query("ALTER TABLE dm_messages ADD COLUMN attachments TEXT")
        .execute(pool)
        .await;

    // Per-member delivery hub for cross-hub DM routing.
    // Nullable: NULL means the member lives on this hub.
    let _ = sqlx::query("ALTER TABLE conversation_members ADD COLUMN hub_url TEXT")
        .execute(pool)
        .await;

    // DM delivery queue — one row per (message, recipient hub) awaiting delivery.
    // Rows are deleted on successful delivery; rows where attempts >= max are
    // kept with bounced_at set so senders can see failures (if we add UI for it).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_outbox (
            message_id         TEXT NOT NULL REFERENCES dm_messages(id),
            recipient_hub_url  TEXT NOT NULL,
            attempts           INTEGER NOT NULL DEFAULT 0,
            next_attempt_at    INTEGER NOT NULL,
            last_error         TEXT,
            bounced_at         INTEGER,
            PRIMARY KEY (message_id, recipient_hub_url)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Multi-device / home-hub state (Phase 2) ----
    // These tables store master-signed personal-axis state. The hub
    // does not authenticate writes via session tokens; the master
    // signature inside each row is the authorization.

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS home_hub_designations (
            master_pubkey  TEXT PRIMARY KEY,
            hubs_json      TEXT NOT NULL,
            issued_at      INTEGER NOT NULL,
            sequence       INTEGER NOT NULL,
            signature      TEXT NOT NULL,
            updated_at     INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_certs (
            master_pubkey       TEXT NOT NULL,
            subkey_pubkey       TEXT NOT NULL,
            device_label        TEXT NOT NULL,
            issued_at           INTEGER NOT NULL,
            not_after           INTEGER,
            fallback_hubs_json  TEXT NOT NULL,
            signature           TEXT NOT NULL,
            registered_at       INTEGER NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_revocations (
            master_pubkey  TEXT NOT NULL,
            subkey_pubkey  TEXT NOT NULL,
            revoked_at     INTEGER NOT NULL,
            signature      TEXT NOT NULL,
            registered_at  INTEGER NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS prefs_blobs (
            master_pubkey  TEXT PRIMARY KEY,
            blob_version   INTEGER NOT NULL,
            ciphertext_hex TEXT NOT NULL,
            signature      TEXT NOT NULL,
            updated_at     INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Short-lived pairing state. State machine: pending → claimed →
    // complete. Rows are pruned when expires_at passes; cleanup runs
    // lazily on each access to avoid a background task for now.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pairing_offers (
            pairing_token    TEXT PRIMARY KEY,
            master_pubkey    TEXT NOT NULL,
            home_hubs_json   TEXT NOT NULL,
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            offer_signature  TEXT NOT NULL,
            state            TEXT NOT NULL DEFAULT 'pending',
            subkey_pubkey    TEXT,
            device_label     TEXT,
            claim_proof      TEXT,
            cert_json        TEXT,
            wrapped_key_hex  TEXT,
            created_at       INTEGER NOT NULL,
            updated_at       INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS public_hub_profiles (
            pubkey       TEXT PRIMARY KEY,
            profile_json TEXT NOT NULL,
            updated_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // E2E encryption: DH key store
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dh_keys (
            pubkey         TEXT PRIMARY KEY REFERENCES users(public_key),
            dh_pubkey_hex  TEXT NOT NULL,
            signature_hex  TEXT NOT NULL,
            published_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // E2E encryption: encrypted DM storage
    // is_encrypted=1 → content is NULL, ciphertext_json holds the envelope
    let _ = sqlx::query("ALTER TABLE dm_messages ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE dm_messages ADD COLUMN ciphertext_json TEXT")
        .execute(pool)
        .await;

    // content column in dm_messages must be nullable for encrypted messages.
    // SQLite does not support ALTER COLUMN, so new rows are inserted with NULL content
    // when is_encrypted=1. Existing rows already have content so no data is lost.

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_icons (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            svg_content TEXT NOT NULL,
            uploaded_by TEXT NOT NULL REFERENCES users(public_key),
            created_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Bot support
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_bot INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_tokens (
            token      TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_alliance_invites (
            id                  TEXT PRIMARY KEY,
            alliance_id         TEXT NOT NULL,
            alliance_name       TEXT NOT NULL,
            from_hub_url        TEXT NOT NULL,
            from_hub_name       TEXT NOT NULL,
            from_hub_public_key TEXT NOT NULL,
            invite_token        TEXT NOT NULL,
            created_at          INTEGER NOT NULL,
            message             TEXT
        )",
    )
    .execute(pool)
    .await?;

    let _ = sqlx::query(
        "ALTER TABLE pending_alliance_invites ADD COLUMN message TEXT",
    )
    .execute(pool)
    .await;

    // ---- Feature: Security Level Lobby ----
    // Additive columns on users
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN lobby_status TEXT NOT NULL DEFAULT 'none'",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN lobby_entered_at INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN pow_level INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // Lobby settings
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('lobby_enabled', '1')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('lobby_welcome_md', '')",
    )
    .execute(pool)
    .await?;

    // ---- Feature: Bot Challenge ----
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_challenges (
            id           TEXT PRIMARY KEY,
            pubkey       TEXT NOT NULL,
            kind         TEXT NOT NULL,
            expected_answer TEXT,
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER NOT NULL,
            consumed_at  INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_bot_challenges_pubkey ON bot_challenges(pubkey, expires_at)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS challenge_tokens (
            token       TEXT PRIMARY KEY,
            pubkey      TEXT NOT NULL,
            issued_at   INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            consumed_at INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // Challenge settings
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('challenge_mode', 'off')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('challenge_difficulty', 'easy')",
    )
    .execute(pool)
    .await?;

    // ---- Feature: PoW minimum level on auth ----
    // 0 = off (no PoW required). Clients read this from GET /info and submit
    // pow_proof in /auth/verify when the level is > 0.
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('min_pow_level', '0')",
    )
    .execute(pool)
    .await?;

    // ---- Feature: Role Questionnaire / Onboarding Survey ----
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS surveys (
            id         TEXT PRIMARY KEY,
            enabled    INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_questions (
            id            TEXT PRIMARY KEY,
            survey_id     TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
            prompt        TEXT NOT NULL,
            kind          TEXT NOT NULL,
            required      INTEGER NOT NULL DEFAULT 1,
            display_order INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_choices (
            id            TEXT PRIMARY KEY,
            question_id   TEXT NOT NULL REFERENCES survey_questions(id) ON DELETE CASCADE,
            label         TEXT NOT NULL,
            display_order INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_choice_roles (
            choice_id TEXT NOT NULL REFERENCES survey_choices(id) ON DELETE CASCADE,
            role_id   TEXT NOT NULL,
            PRIMARY KEY (choice_id, role_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_responses (
            id           TEXT PRIMARY KEY,
            pubkey       TEXT NOT NULL,
            survey_id    TEXT NOT NULL,
            submitted_at INTEGER NOT NULL,
            UNIQUE(pubkey, survey_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_answers (
            response_id TEXT NOT NULL REFERENCES survey_responses(id) ON DELETE CASCADE,
            question_id TEXT NOT NULL,
            choice_id   TEXT,
            text_answer TEXT,
            PRIMARY KEY (response_id, question_id)
        )",
    )
    .execute(pool)
    .await?;

    // ---- External bot system: new users columns ----
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_bot_removed INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN bot_invite_token TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN bot_invite_expires INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_webhook INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    // Ephemeral messages: only visible to a specific user. NULL = normal broadcast.
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN visible_to_pubkey TEXT")
        .execute(pool)
        .await;
    // Rich embeds: JSON array of Embed objects. NULL = no embeds.
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN embeds TEXT")
        .execute(pool)
        .await;

    // Bot profile metadata (operator-supplied, per-hub).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_profiles (
            pubkey       TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            avatar_url   TEXT,
            description  TEXT,
            webhook_url  TEXT,
            homepage_url TEXT,
            capabilities TEXT NOT NULL DEFAULT '[]',
            updated_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Per-bot slash command registry (one row per bot × command name).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_commands (
            pubkey           TEXT NOT NULL,
            name             TEXT NOT NULL,
            description      TEXT NOT NULL,
            args             TEXT,
            scope            TEXT NOT NULL DEFAULT 'channel',
            privileged       INTEGER NOT NULL DEFAULT 0,
            cooldown_seconds INTEGER NOT NULL DEFAULT 3,
            PRIMARY KEY (pubkey, name)
        )",
    )
    .execute(pool)
    .await?;

    // Event subscriptions per bot: channel_id uses '' (empty string) as sentinel
    // for hub-scope subscriptions (i.e. not channel-scoped). SQLite PRIMARY KEY
    // constraints cannot use expressions like COALESCE, so we store '' instead of NULL
    // and treat '' as "no channel filter" in the application layer.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_subscriptions (
            bot_pubkey  TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            channel_id  TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (bot_pubkey, event_type, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    // Per-bot channel scope restriction. Empty table = hub-wide access (default).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_channel_scope (
            bot_pubkey TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            PRIMARY KEY (bot_pubkey, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    // Interactive message components (buttons, selects) attached to bot messages.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_components (
            id            TEXT PRIMARY KEY,
            message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            row_idx       INTEGER NOT NULL,
            component_idx INTEGER NOT NULL,
            type          TEXT NOT NULL,
            config_json   TEXT NOT NULL,
            expires_at    INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // Native audit log. Separate sequence counter table because SQLite
    // AUTOINCREMENT is only clean on INTEGER PRIMARY KEY tables.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_audit_seq (
            id  INTEGER PRIMARY KEY,
            seq INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT OR IGNORE INTO hub_audit_seq VALUES(1, 0)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_audit_log (
            id            TEXT PRIMARY KEY,
            seq           INTEGER NOT NULL,
            event_type    TEXT NOT NULL,
            at            INTEGER NOT NULL,
            actor_pubkey  TEXT,
            target_pubkey TEXT,
            channel_id    TEXT,
            payload_json  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Incoming webhooks: a secret URL that external services POST messages to.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webhooks (
            id                TEXT PRIMARY KEY,
            channel_id        TEXT NOT NULL REFERENCES channels(id),
            secret_token_hash TEXT NOT NULL,
            display_name      TEXT NOT NULL,
            avatar_url        TEXT,
            created_by_pubkey TEXT NOT NULL,
            rate_limit        INTEGER NOT NULL DEFAULT 5,
            active            INTEGER NOT NULL DEFAULT 1,
            created_at        INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Self-service bot system ----
    // Standalone bots table with webhook and hashed token support.
    // The bot's public_key is also inserted into users (is_bot=1) so that
    // message FK constraints and the member listing continue to work.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bots (
            public_key   TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            token_hash   TEXT NOT NULL,
            webhook_url  TEXT,
            created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_slash_commands (
            id          TEXT PRIMARY KEY,
            bot_pubkey  TEXT NOT NULL REFERENCES bots(public_key) ON DELETE CASCADE,
            command     TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            UNIQUE(bot_pubkey, command)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_event_queue (
            id          TEXT PRIMARY KEY,
            bot_pubkey  TEXT NOT NULL REFERENCES bots(public_key) ON DELETE CASCADE,
            event_type  TEXT NOT NULL,
            payload     TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            delivered   INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // Add expires_at and expiry_warned_at to sessions for token-expiry push.
    // These columns are optional: NULL expires_at = session never expires.
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN expires_at INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN expiry_warned_at INTEGER")
        .execute(pool)
        .await;

    // Index on seq for hub_audit_log to speed up cursor pagination and replay.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_seq ON hub_audit_log(seq)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON hub_audit_log(event_type)",
    )
    .execute(pool)
    .await?;

    // FTS5 virtual table mirroring messages.content for fast full-text search.
    sqlx::query(
        "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
         USING fts5(content, content='messages', content_rowid='rowid')",
    )
    .execute(pool)
    .await?;

    // Keep FTS5 in sync with the messages table.
    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS messages_ai
         AFTER INSERT ON messages BEGIN
           INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS messages_ad
         AFTER DELETE ON messages BEGIN
           INSERT INTO messages_fts(messages_fts, rowid, content)
           VALUES ('delete', old.rowid, old.content);
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS messages_au
         AFTER UPDATE ON messages BEGIN
           INSERT INTO messages_fts(messages_fts, rowid, content)
           VALUES ('delete', old.rowid, old.content);
           INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
         END",
    )
    .execute(pool)
    .await?;

    // Back-fill existing messages into the FTS5 index (safe to run repeatedly).
    sqlx::query(
        "INSERT OR IGNORE INTO messages_fts(rowid, content)
         SELECT rowid, content FROM messages
         WHERE rowid NOT IN (SELECT rowid FROM messages_fts)",
    )
    .execute(pool)
    .await?;

    // ---- Feature: Moderation enhancements ----

    // min_talk_power on channels (0 = anyone can talk in voice)
    let _ = sqlx::query(
        "ALTER TABLE channels ADD COLUMN min_talk_power INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // talk_power on roles (0 = no elevated talk power)
    let _ = sqlx::query(
        "ALTER TABLE roles ADD COLUMN talk_power INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // Per-channel voice mutes (channel_id + pubkey PK, distinct from hub-wide voice_mutes)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_voice_mutes (
            channel_id TEXT NOT NULL,
            pubkey     TEXT NOT NULL,
            muted_by   TEXT NOT NULL,
            muted_at   TEXT NOT NULL,
            PRIMARY KEY (channel_id, pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // Raise-hand requests for users below the min_talk_power threshold
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS raise_hand_requests (
            id           TEXT PRIMARY KEY,
            channel_id   TEXT NOT NULL,
            pubkey       TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            UNIQUE (channel_id, pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Feature: Forum channel type ----
    // channel_type discriminant: 'text' (default) or 'forum'.
    let _ = sqlx::query(
        "ALTER TABLE channels ADD COLUMN channel_type TEXT NOT NULL DEFAULT 'text'",
    )
    .execute(pool)
    .await;

    // Posts table (forum content entries).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS posts (
            id               TEXT PRIMARY KEY,
            channel_id       TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            author_pubkey    TEXT NOT NULL,
            title            TEXT NOT NULL,
            body             TEXT NOT NULL,
            created_at       INTEGER NOT NULL,
            edited_at        INTEGER,
            is_pinned        INTEGER NOT NULL DEFAULT 0,
            is_locked        INTEGER NOT NULL DEFAULT 0,
            reply_count      INTEGER NOT NULL DEFAULT 0,
            last_activity_at INTEGER NOT NULL,
            deleted_at       INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_channel_activity
         ON posts (channel_id, is_pinned DESC, last_activity_at DESC)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_author
         ON posts (author_pubkey)",
    )
    .execute(pool)
    .await?;

    // Post replies table (threaded replies under a post).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_replies (
            id            TEXT PRIMARY KEY,
            post_id       TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            author_pubkey TEXT NOT NULL,
            body          TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            edited_at     INTEGER,
            reply_to_id   TEXT REFERENCES post_replies(id) ON DELETE SET NULL,
            deleted_at    INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_post_replies_post
         ON post_replies (post_id, created_at)",
    )
    .execute(pool)
    .await?;

    // FTS5 virtual table covering post titles and bodies (replies use empty title).
    sqlx::query(
        "CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
            title, body, post_id UNINDEXED, channel_id UNINDEXED
        )",
    )
    .execute(pool)
    .await?;

    // FTS5 triggers: posts
    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS posts_fts_ai
         AFTER INSERT ON posts
         WHEN new.deleted_at IS NULL BEGIN
           INSERT INTO posts_fts(post_id, channel_id, title, body)
           VALUES (new.id, new.channel_id, new.title, new.body);
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS posts_fts_au
         AFTER UPDATE ON posts BEGIN
           DELETE FROM posts_fts WHERE post_id = old.id;
           INSERT INTO posts_fts(post_id, channel_id, title, body)
           SELECT new.id, new.channel_id, new.title, new.body
           WHERE new.deleted_at IS NULL;
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS posts_fts_ad
         AFTER DELETE ON posts BEGIN
           DELETE FROM posts_fts WHERE post_id = old.id;
         END",
    )
    .execute(pool)
    .await?;

    // FTS5 triggers: post_replies (indexed with empty title)
    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS post_replies_fts_ai
         AFTER INSERT ON post_replies
         WHEN new.deleted_at IS NULL BEGIN
           INSERT INTO posts_fts(post_id, channel_id, title, body)
           SELECT new.post_id, p.channel_id, '', new.body
           FROM posts p WHERE p.id = new.post_id;
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS post_replies_fts_au
         AFTER UPDATE ON post_replies BEGIN
           DELETE FROM posts_fts WHERE post_id = old.post_id AND body = old.body AND title = '';
           INSERT INTO posts_fts(post_id, channel_id, title, body)
           SELECT new.post_id, p.channel_id, '', new.body
           FROM posts p WHERE p.id = new.post_id AND new.deleted_at IS NULL;
         END",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS post_replies_fts_ad
         AFTER DELETE ON post_replies BEGIN
           DELETE FROM posts_fts WHERE post_id = old.post_id AND body = old.body AND title = '';
         END",
    )
    .execute(pool)
    .await?;

    // Seed new permissions into builtin-everyone and builtin-owner roles.
    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'create_posts')")
        .execute(pool).await?;
    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'manage_posts')")
        .execute(pool).await?;

    // ---- Feature: Self-tags (#12) ----
    // Seed hub_tags and hub_nsfw into hub_settings. JSON array of strings.
    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('hub_tags', '[]')",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO hub_settings (key, value) VALUES ('hub_nsfw', 'false')",
    )
    .execute(pool)
    .await?;

    // ---- Feature: Badge federation (#13) ----
    // Pending badge offers received from other hubs (unauthenticated push).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS badge_offers (
            id               TEXT PRIMARY KEY,
            from_hub_pubkey  TEXT NOT NULL,
            from_hub_url     TEXT NOT NULL,
            label            TEXT NOT NULL,
            note             TEXT,
            payload          TEXT NOT NULL,
            signature        TEXT NOT NULL,
            created_at       TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Accepted badges this hub holds and presents in /info.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_badges (
            id             TEXT PRIMARY KEY,
            issuer_pubkey  TEXT NOT NULL,
            issuer_url     TEXT NOT NULL,
            label          TEXT NOT NULL,
            payload        TEXT NOT NULL,
            signature      TEXT NOT NULL,
            accepted_at    TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Badges this hub has issued to other hubs.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issued_badges (
            id                  TEXT PRIMARY KEY,
            recipient_hub_url   TEXT NOT NULL,
            recipient_hub_pubkey TEXT NOT NULL,
            label               TEXT NOT NULL,
            payload             TEXT NOT NULL,
            signature           TEXT NOT NULL,
            issued_at           TEXT NOT NULL,
            expires_at          TEXT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Gaming Tier 2: session persistence + shared KV ----
    // game_sessions: one row per live (or recently ended) session. The snapshot
    // blob is written only when the game calls voxply:game:snapshot; otherwise
    // authoritative state is purely in-memory.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_sessions (
            id           TEXT PRIMARY KEY,
            channel_id   TEXT NOT NULL,
            game_id      TEXT NOT NULL,
            host_pubkey  TEXT NOT NULL,
            state_json   TEXT NOT NULL DEFAULT '{}',
            created_at   TEXT NOT NULL,
            ended_at     TEXT
        )",
    )
    .execute(pool)
    .await?;

    // game_shared_kv: community-axis leaderboard / shared world per
    // (session_id, key). session_id scoping keeps different game instances
    // independent; the client layer maps game_id + channel_id to session_id.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_shared_kv (
            session_id TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (session_id, key)
        )",
    )
    .execute(pool)
    .await?;

    // Seed start_game permission into builtin-everyone role so all members can
    // start sessions by default; admins can restrict via role management.
    sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'start_game')")
        .execute(pool).await?;

    tracing::info!("Database migrations complete");
    Ok(())
}
