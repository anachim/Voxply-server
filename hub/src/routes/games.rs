//! Tier 2 party-multiplayer game session routes.
//!
//! Session lifecycle: create → join → (state patches) → end/delete.
//! In-memory state lives in `AppState::active_game_sessions`; the DB rows in
//! `game_sessions` are written for durability (snapshot opt-in) and for the
//! authoritative "is this session still open?" check.  The shared KV table
//! (`game_shared_kv`) stores community-axis leaderboard/world data.
//!
//! All WS broadcast goes through the existing `state.chat_tx` broadcast
//! channel using `ChatEvent::Game` so the WS dispatcher filters by channel
//! subscription automatically.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::{AppState, GameSessionState};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for installing a game (Tier 1 minimal admin route).
/// Only the fields required to create a `hub_games` row. Extended install
/// (manifest-URL fetch, capability grants) is the full Tier 1 admin surface
/// which is designed but not yet built — this endpoint covers the minimal path
/// used by the Tier 2 session tests and the inline-manifest install path.
#[derive(Deserialize)]
pub struct InstallGameRequest {
    pub name: String,
    pub entry_url: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub min_players: Option<i64>,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Serialize)]
pub struct InstalledGameResponse {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    pub version: String,
    pub description: Option<String>,
    pub thumbnail_url: Option<String>,
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub game_id: String,
    /// The channel this session is anchored to.
    pub channel_id: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub channel_id: String,
    pub game_id: String,
    pub host_pubkey: String,
    pub players: Vec<String>,
    pub state_json: serde_json::Value,
    pub created_at: String,
    pub ended_at: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchStateRequest {
    pub patch: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SetKvRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct KvResponse {
    pub session_id: String,
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Helper: broadcast a WsServerMessage to all channel subscribers via chat_tx.
// ---------------------------------------------------------------------------
fn broadcast_game_event(state: &AppState, channel_id: &str, msg: WsServerMessage) {
    let event = ChatEvent::Game {
        channel_id: channel_id.to_string(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&msg).unwrap().as_str());
    let _ = state.chat_tx.send((event, json));
}

// ---------------------------------------------------------------------------
// POST /admin/games  (Tier 1 minimal install — manage_games required)
// ---------------------------------------------------------------------------
/// Install a game on this hub. Uses the game's `entry_url` to derive a stable
/// `id` if none is supplied (SHA-256 prefix). This is the inline-manifest path
/// described in the design doc; the full manifest-URL fetch and catalog browse
/// paths are deferred Tier 1 work.
pub async fn install_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InstallGameRequest>,
) -> Result<(StatusCode, Json<InstalledGameResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Derive id from entry_url hash if not supplied explicitly.
    let game_id = req.id.unwrap_or_else(|| {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(req.entry_url.as_bytes());
        format!("game-{}", hex::encode(&hash[..8]))
    });
    let version = req.version.unwrap_or_else(|| "1.0.0".to_string());
    let min_players = req.min_players.unwrap_or(1);
    let max_players = req.max_players.unwrap_or(1);
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO hub_games
            (id, name, description, version, entry_url, thumbnail_url, author,
             min_players, max_players, installed_by, installed_at, manifest_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             description = excluded.description,
             version = excluded.version,
             entry_url = excluded.entry_url,
             thumbnail_url = excluded.thumbnail_url,
             author = excluded.author,
             min_players = excluded.min_players,
             max_players = excluded.max_players",
    )
    .bind(&game_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&version)
    .bind(&req.entry_url)
    .bind(&req.thumbnail_url)
    .bind(&req.author)
    .bind(min_players)
    .bind(max_players)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(InstalledGameResponse {
            id: game_id,
            name: req.name,
            entry_url: req.entry_url,
            version,
            description: req.description,
            thumbnail_url: req.thumbnail_url,
            author: req.author,
            min_players,
            max_players,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /channels/:channel_id/game-sessions
// ---------------------------------------------------------------------------
/// Create a new session for the given game in the given channel.
/// Requires `start_game` permission. Also checks that the game is installed
/// on this hub (present in `hub_games`).
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<SessionResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::START_GAME)?;

    // Verify the game is installed.
    let game_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM hub_games WHERE id = ?")
            .bind(&req.game_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if game_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Game not found on this hub".to_string()));
    }

    // Verify the channel exists.
    let ch_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let session_id = Uuid::new_v4().to_string();
    let now = chrono_now();

    // Persist to DB (state_json starts as empty object; updated by state patches).
    sqlx::query(
        "INSERT INTO game_sessions (id, channel_id, game_id, host_pubkey, state_json, created_at)
         VALUES (?, ?, ?, ?, '{}', ?)",
    )
    .bind(&session_id)
    .bind(&channel_id)
    .bind(&req.game_id)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Insert into in-memory map.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        sessions.insert(
            session_id.clone(),
            GameSessionState {
                id: session_id.clone(),
                channel_id: channel_id.clone(),
                game_id: req.game_id.clone(),
                host_pubkey: user.public_key.clone(),
                players: {
                    let mut s = HashSet::new();
                    s.insert(user.public_key.clone());
                    s
                },
                in_memory_state: serde_json::Value::Object(Default::default()),
            },
        );
    }

    // Broadcast to channel subscribers.
    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GameSessionCreated {
            session_id: session_id.clone(),
            channel_id: channel_id.clone(),
            game_id: req.game_id.clone(),
            host_pubkey: user.public_key.clone(),
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(SessionResponse {
            id: session_id,
            channel_id,
            game_id: req.game_id,
            host_pubkey: user.public_key,
            players: vec![],
            state_json: serde_json::Value::Object(Default::default()),
            created_at: now,
            ended_at: None,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/join
// ---------------------------------------------------------------------------
pub async fn join_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<(StatusCode, Json<SessionResponse>), (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    // Add player in-memory.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.players.insert(user.public_key.clone());
        }
    }

    let channel_id = row.channel_id.clone();

    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GameSessionJoined {
            session_id: session_id.clone(),
            player_pubkey: user.public_key.clone(),
        },
    );

    Ok((
        StatusCode::OK,
        Json(session_row_to_response(row, &state, &session_id)),
    ))
}

// ---------------------------------------------------------------------------
// GET /game-sessions/:sid
// ---------------------------------------------------------------------------
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;
    Ok(Json(session_row_to_response(row, &state, &session_id)))
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/state  (host only)
// ---------------------------------------------------------------------------
pub async fn patch_state(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
    Json(req): Json<PatchStateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    if row.host_pubkey != user.public_key {
        // Admin can also patch.
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        if !perms.has(permissions::ADMIN) {
            return Err((StatusCode::FORBIDDEN, "Only the host can patch session state".to_string()));
        }
    }

    // Merge patch into DB state_json. We do a simple JSON merge: fetch current,
    // merge top-level keys from the patch, write back. The hub never interprets
    // the payload — it is opaque from the game's perspective.
    let current_json: String = sqlx::query_scalar(
        "SELECT state_json FROM game_sessions WHERE id = ? AND ended_at IS NULL",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Session not found or ended".to_string()))?;

    let mut current: serde_json::Value =
        serde_json::from_str(&current_json).unwrap_or(serde_json::Value::Object(Default::default()));

    if let (Some(obj), Some(patch_obj)) = (current.as_object_mut(), req.patch.as_object()) {
        for (k, v) in patch_obj {
            obj.insert(k.clone(), v.clone());
        }
    } else {
        current = req.patch.clone();
    }

    let new_json = serde_json::to_string(&current).unwrap();
    sqlx::query("UPDATE game_sessions SET state_json = ? WHERE id = ?")
        .bind(&new_json)
        .bind(&session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Update in-memory state too.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.in_memory_state = current;
        }
    }

    broadcast_game_event(
        &state,
        &row.channel_id,
        WsServerMessage::GameStateUpdated {
            session_id: session_id.clone(),
            patch: req.patch,
        },
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/shared-kv/:key
// ---------------------------------------------------------------------------
pub async fn set_shared_kv(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path((session_id, key)): Path<(String, String)>,
    Json(req): Json<SetKvRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify the session exists and is open.
    let _ = fetch_open_session(&state, &session_id).await?;

    let now = chrono_now();
    sqlx::query(
        "INSERT INTO game_shared_kv (session_id, key, value, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(session_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(&session_id)
    .bind(&key)
    .bind(&req.value)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /game-sessions/:sid/shared-kv/:key
// ---------------------------------------------------------------------------
pub async fn get_shared_kv(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path((session_id, key)): Path<(String, String)>,
) -> Result<Json<KvResponse>, (StatusCode, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT value, updated_at FROM game_shared_kv WHERE session_id = ? AND key = ?",
    )
    .bind(&session_id)
    .bind(&key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        Some((value, updated_at)) => Ok(Json(KvResponse {
            session_id,
            key,
            value,
            updated_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "Key not found".to_string())),
    }
}

// ---------------------------------------------------------------------------
// DELETE /game-sessions/:sid  (end session, host or admin)
// ---------------------------------------------------------------------------
pub async fn end_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    if row.host_pubkey != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        if !perms.has(permissions::ADMIN) {
            return Err((StatusCode::FORBIDDEN, "Only the host or an admin can end the session".to_string()));
        }
    }

    let now = chrono_now();
    sqlx::query("UPDATE game_sessions SET ended_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Remove from in-memory map.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        sessions.remove(&session_id);
    }

    broadcast_game_event(
        &state,
        &row.channel_id,
        WsServerMessage::GameSessionEnded {
            session_id: session_id.clone(),
        },
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct SessionRow {
    channel_id: String,
    game_id: String,
    host_pubkey: String,
    state_json: String,
    created_at: String,
    ended_at: Option<String>,
}

async fn fetch_open_session(
    state: &AppState,
    session_id: &str,
) -> Result<SessionRow, (StatusCode, String)> {
    let row: Option<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT channel_id, game_id, host_pubkey, state_json, created_at, ended_at
         FROM game_sessions WHERE id = ?",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        None => Err((StatusCode::NOT_FOUND, "Session not found".to_string())),
        Some((channel_id, game_id, host_pubkey, state_json, created_at, ended_at)) => {
            if ended_at.is_some() {
                return Err((StatusCode::GONE, "Session has ended".to_string()));
            }
            Ok(SessionRow {
                channel_id,
                game_id,
                host_pubkey,
                state_json,
                created_at,
                ended_at,
            })
        }
    }
}

fn session_row_to_response(row: SessionRow, state: &AppState, session_id: &str) -> SessionResponse {
    let players: Vec<String> = {
        let sessions = state.active_game_sessions.lock().unwrap();
        sessions
            .get(session_id)
            .map(|s| s.players.iter().cloned().collect())
            .unwrap_or_default()
    };
    let state_json: serde_json::Value =
        serde_json::from_str(&row.state_json).unwrap_or(serde_json::Value::Object(Default::default()));
    SessionResponse {
        id: session_id.to_string(),
        channel_id: row.channel_id,
        game_id: row.game_id,
        host_pubkey: row.host_pubkey,
        players,
        state_json,
        created_at: row.created_at,
        ended_at: row.ended_at,
    }
}

fn chrono_now() -> String {
    // Use the same unix-seconds string pattern used elsewhere in the hub for
    // TEXT timestamp columns.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    secs.to_string()
}
