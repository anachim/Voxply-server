use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN, BAN_MEMBERS, KICK_MEMBERS, MUTE_MEMBERS, TIMEOUT_MEMBERS};
use crate::routes::moderation_models::*;
use crate::state::AppState;

async fn require_can_moderate(
    state: &AppState,
    actor_key: &str,
    target_key: &str,
    permission: &str,
) -> Result<(), (StatusCode, String)> {
    let actor_perms = permissions::user_permissions(&state.db, actor_key).await?;
    actor_perms.require(permission)?;

    let target_perms = permissions::user_permissions(&state.db, target_key).await?;
    if target_perms.max_priority >= actor_perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot moderate a user with equal or higher priority".to_string(),
        ));
    }
    Ok(())
}

// --- Ban ---

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<BanRequest>,
) -> Result<(StatusCode, Json<BanResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, BAN_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR REPLACE INTO bans (target_public_key, banned_by, reason, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Delete their sessions so they're immediately logged out
    sqlx::query("DELETE FROM sessions WHERE public_key = ?")
        .bind(&req.target_public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Banned user: {}", &req.target_public_key[..16]);

    // Publish member.banned audit event.
    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let target = req.target_public_key.clone();
        let reason = req.reason.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "member.banned",
                Some(&actor),
                Some(&target),
                None,
                serde_json::json!({ "reason": reason }),
            ).await;
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(BanResponse {
            target_public_key: req.target_public_key,
            banned_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    sqlx::query("DELETE FROM bans WHERE target_public_key = ?")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_bans(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<BanResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    let rows = sqlx::query_as::<_, BanRow>(
        "SELECT target_public_key, banned_by, reason, created_at FROM bans ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BanResponse {
                target_public_key: r.target_public_key,
                banned_by: r.banned_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Mute ---

pub async fn mute_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<MuteRequest>,
) -> Result<(StatusCode, Json<MuteResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, MUTE_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR REPLACE INTO mutes (target_public_key, muted_by, reason, expires_at, created_at) VALUES (?, ?, ?, NULL, ?)",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Muted user: {}", &req.target_public_key[..16]);

    Ok((
        StatusCode::CREATED,
        Json(MuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            expires_at: None,
            created_at: now,
        }),
    ))
}

pub async fn unmute_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM mutes WHERE target_public_key = ?")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_mutes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<MuteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, MuteRow>(
        "SELECT target_public_key, muted_by, reason, expires_at, created_at FROM mutes ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| MuteResponse {
                target_public_key: r.target_public_key,
                muted_by: r.muted_by,
                reason: r.reason,
                expires_at: r.expires_at,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Timeout ---

pub async fn timeout_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<TimeoutRequest>,
) -> Result<(StatusCode, Json<MuteResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, TIMEOUT_MEMBERS)
        .await?;

    let now = crate::auth::handlers::unix_timestamp();
    let expires_at = now + req.duration_seconds as i64;

    sqlx::query(
        "INSERT OR REPLACE INTO mutes (target_public_key, muted_by, reason, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(&expires_at)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Timed out user: {} for {}s",
        &req.target_public_key[..16],
        req.duration_seconds
    );

    Ok((
        StatusCode::CREATED,
        Json(MuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            expires_at: Some(expires_at),
            created_at: now,
        }),
    ))
}

// --- Kick ---

pub async fn kick_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<KickRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, KICK_MEMBERS).await?;

    // Delete their sessions to force re-auth
    sqlx::query("DELETE FROM sessions WHERE public_key = ?")
        .bind(&req.target_public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Kicked user: {}", &req.target_public_key[..16]);

    // Publish member.kicked audit event.
    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let target = req.target_public_key.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "member.kicked",
                Some(&actor),
                Some(&target),
                None,
                serde_json::json!({}),
            ).await;
        });
    }

    Ok(StatusCode::OK)
}

// --- Channel Ban ---

pub async fn channel_ban(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<ChannelBanRequest>,
) -> Result<(StatusCode, Json<ChannelBanResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, MUTE_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR REPLACE INTO channel_bans (channel_id, target_public_key, banned_by, reason, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id)
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(ChannelBanResponse {
            channel_id,
            target_public_key: req.target_public_key,
            banned_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn list_channel_bans(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<ChannelBanResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, ChannelBanRow>(
        "SELECT channel_id, target_public_key, banned_by, reason, created_at
         FROM channel_bans WHERE channel_id = ? ORDER BY created_at DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ChannelBanResponse {
                channel_id: r.channel_id,
                target_public_key: r.target_public_key,
                banned_by: r.banned_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn channel_unban(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, target_key)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM channel_bans WHERE channel_id = ? AND target_public_key = ?")
        .bind(&channel_id)
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// --- Voice Mute ---

pub async fn voice_mute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<VoiceMuteRequest>,
) -> Result<(StatusCode, Json<VoiceMuteResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.target_public_key, MUTE_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR REPLACE INTO voice_mutes (target_public_key, muted_by, reason, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(VoiceMuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn voice_unmute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM voice_mutes WHERE target_public_key = ?")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_voice_mutes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<VoiceMuteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, VoiceMuteRow>(
        "SELECT target_public_key, muted_by, reason, created_at FROM voice_mutes ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| VoiceMuteResponse {
                target_public_key: r.target_public_key,
                muted_by: r.muted_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Talk Power ---

pub async fn set_talk_power(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<SetTalkPowerRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query(
        "INSERT INTO channel_settings (channel_id, min_talk_power) VALUES (?, ?)
         ON CONFLICT(channel_id) DO UPDATE SET min_talk_power = ?",
    )
    .bind(&channel_id)
    .bind(req.min_talk_power)
    .bind(req.min_talk_power)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn get_talk_power(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<TalkPowerResponse>, (StatusCode, String)> {
    let min_talk_power: i64 = sqlx::query_scalar(
        "SELECT min_talk_power FROM channel_settings WHERE channel_id = ?",
    )
    .bind(&channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .unwrap_or(0);

    Ok(Json(TalkPowerResponse {
        channel_id,
        min_talk_power,
    }))
}

// DB row types

#[derive(sqlx::FromRow)]
struct BanRow {
    target_public_key: String,
    banned_by: String,
    reason: Option<String>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct MuteRow {
    target_public_key: String,
    muted_by: String,
    reason: Option<String>,
    expires_at: Option<i64>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct ChannelBanRow {
    channel_id: String,
    target_public_key: String,
    banned_by: String,
    reason: Option<String>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct VoiceMuteRow {
    target_public_key: String,
    muted_by: String,
    reason: Option<String>,
    created_at: i64,
}

// --- Helpers for enforcement (used by other modules) ---

pub async fn is_banned(db: &sqlx::SqlitePool, public_key: &str) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bans WHERE target_public_key = ?",
    )
    .bind(public_key)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_muted(db: &sqlx::SqlitePool, public_key: &str) -> Result<bool, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // Check for permanent mute (no expires_at) or active timeout (expires_at > now)
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mutes WHERE target_public_key = ? AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(public_key)
    .bind(&now)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_channel_banned(
    db: &sqlx::SqlitePool,
    channel_id: &str,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_bans WHERE channel_id = ? AND target_public_key = ?",
    )
    .bind(channel_id)
    .bind(public_key)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_voice_muted(
    db: &sqlx::SqlitePool,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM voice_mutes WHERE target_public_key = ?",
    )
    .bind(public_key)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}
