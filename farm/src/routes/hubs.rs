/// Farm-side hub management routes.
///
/// GET  /farm/hubs               — list hubs (public → public-only; authed → owned + public)
/// POST /farm/hubs               — create a hub (authenticated)
/// GET  /farm/hubs/:hub_id       — single hub info
/// PATCH /farm/hubs/:hub_id/suspend — suspend/unsuspend (farm admin)
/// DELETE /farm/hubs/:hub_id     — delete (farm admin or owner)
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::state::FarmState;
use crate::token::verify_token;

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Extract and verify a Bearer farm token. Returns the `sub` (canonical pubkey) on success.
fn require_auth(
    headers: &HeaderMap,
    farm_pubkey: &str,
) -> Result<crate::token::FarmTokenPayload, (StatusCode, Json<serde_json::Value>)> {
    let token_str = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing_token"})),
            )
        })?;

    verify_token(farm_pubkey, token_str).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
    })
}

/// Returns the admin pubkey stored in the `farms` singleton row, or `None`.
async fn get_admin_pubkey(db: &sqlx::SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

fn generate_hub_id() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Shared response shape
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HubEntry {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub visibility: String,
    pub hub_url: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<i64>,
}

fn hub_url(farm_url: &str, hub_id: &str) -> String {
    format!("{}/hub/{}", farm_url.trim_end_matches('/'), hub_id)
}

// ---------------------------------------------------------------------------
// GET /farm/hubs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ListHubsResponse {
    pub hubs: Vec<HubEntry>,
}

pub async fn list_hubs(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListHubsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let authed_sub = require_auth(&headers, &farm_pubkey).ok().map(|p| p.sub);

    let rows: Vec<(String, String, Option<String>, String, i64, Option<i64>, String)> =
        if let Some(ref sub) = authed_sub {
            // Authenticated: return public hubs + hubs the user owns.
            sqlx::query_as(
                "SELECT id, name, description, visibility, created_at, suspended_at, owner_pubkey
                 FROM hubs
                 WHERE deleted_at IS NULL
                   AND (visibility = 'public' OR owner_pubkey = ?)",
            )
            .bind(sub)
            .fetch_all(&state.db)
            .await
        } else {
            // Unauthenticated: public hubs only (and only if directory_public is set).
            let dir_public: bool =
                sqlx::query_scalar::<_, i64>("SELECT directory_public FROM farms WHERE id = 1")
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten()
                    .map(|v| v != 0)
                    .unwrap_or(false);

            if !dir_public {
                return Ok(Json(ListHubsResponse { hubs: vec![] }));
            }

            sqlx::query_as(
                "SELECT id, name, description, visibility, created_at, suspended_at, owner_pubkey
                 FROM hubs
                 WHERE deleted_at IS NULL AND visibility = 'public'",
            )
            .fetch_all(&state.db)
            .await
        }
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    let hubs = rows
        .into_iter()
        .map(|(id, name, description, visibility, created_at, suspended_at, _owner)| HubEntry {
            hub_url: hub_url(&state.farm_url, &id),
            id,
            name,
            description,
            visibility,
            created_at,
            suspended_at,
        })
        .collect();

    Ok(Json(ListHubsResponse { hubs }))
}

// ---------------------------------------------------------------------------
// POST /farm/hubs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateHubRequest {
    pub name: String,
    pub description: Option<String>,
    pub visibility: Option<String>,
}

#[derive(Serialize)]
pub struct CreateHubResponse {
    pub id: String,
    pub hub_url: String,
}

pub async fn create_hub(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<CreateHubRequest>,
) -> Result<(StatusCode, Json<CreateHubResponse>), (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // -----------------------------------------------------------------------
    // Phase 3A: Enforce creation policy and quota before doing any real work.
    // -----------------------------------------------------------------------
    {
        let policy_row: Option<(String, i64, i64)> = sqlx::query_as(
            "SELECT creation_policy, max_hubs_per_user, max_hubs_total
             FROM farms WHERE id = 1",
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

        if let Some((creation_policy, max_hubs_per_user, max_hubs_total)) = policy_row {
            let admin_pubkey = get_admin_pubkey(&state.db).await;
            let is_admin = admin_pubkey.as_deref() == Some(payload.sub.as_str());

            match creation_policy.as_str() {
                "disabled" => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({"error": "hub_creation_disabled"})),
                    ));
                }
                "admin_only" => {
                    if !is_admin {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "admin_only"})),
                        ));
                    }
                }
                "open" => {
                    // Per-user quota check.
                    if max_hubs_per_user > 0 {
                        let owned: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM hubs WHERE owner_pubkey = ? AND deleted_at IS NULL",
                        )
                        .bind(&payload.sub)
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"error": format!("db_error: {e}")})),
                            )
                        })?;

                        if owned >= max_hubs_per_user {
                            return Err((
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({"error": "user_quota_exceeded"})),
                            ));
                        }
                    }

                    // Farm-wide quota check.
                    if max_hubs_total > 0 {
                        let total: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM hubs WHERE deleted_at IS NULL",
                        )
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"error": format!("db_error: {e}")})),
                            )
                        })?;

                        if total >= max_hubs_total {
                            return Err((
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({"error": "farm_quota_exceeded"})),
                            ));
                        }
                    }
                }
                _ => {
                    // Unknown policy value — treat as admin_only (safe default).
                    if !is_admin {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "admin_only"})),
                        ));
                    }
                }
            }
        }
        // If the farms row doesn't exist yet (first-start race), fall through and
        // allow creation — the admin can configure policy once the row is seeded.
    }

    // Validate name: 1-64 chars, alphanumeric + spaces + hyphens.
    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_name", "details": "must be 1-64 chars"})),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "invalid_name", "details": "only alphanumeric, spaces, hyphens"}),
            ),
        ));
    }

    let visibility = match req.visibility.as_deref().unwrap_or("private") {
        "public" => "public",
        _ => "private",
    };

    // Generate a unique hub_id.
    let hub_id = loop {
        let candidate = generate_hub_id();
        let exists: Option<String> =
            sqlx::query_scalar("SELECT id FROM hubs WHERE id = ?")
                .bind(&candidate)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("db_error: {e}")})),
                    )
                })?;
        if exists.is_none() {
            break candidate;
        }
    };

    let now = unix_now();

    // Determine the DB path: use `VOXPLY_HUBS_DIR` env var or fall back to CWD/hubs/<id>.
    let hubs_dir = std::env::var("VOXPLY_HUBS_DIR").unwrap_or_else(|_| "hubs".to_string());
    let db_path = format!("{}/{}.db", hubs_dir.trim_end_matches('/'), hub_id);

    // Ensure the hubs directory exists.
    if let Err(e) = std::fs::create_dir_all(&hubs_dir) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("cannot create hubs dir: {e}")})),
        ));
    }

    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, description, visibility, db_path, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&hub_id)
    .bind(&payload.sub)
    .bind(&name)
    .bind(&req.description)
    .bind(visibility)
    .bind(&db_path)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    // Spawn the hub child process.
    match state
        .hub_manager
        .allocate_and_spawn(&state.db, &hub_id, &db_path)
        .await
    {
        Ok(port) => tracing::info!(hub_id, port, "Hub spawned for new hub"),
        Err(e) => tracing::warn!(hub_id, error = %e, "Hub spawn failed (row created, process not running)"),
    }

    let url = hub_url(&state.farm_url, &hub_id);
    Ok((StatusCode::CREATED, Json(CreateHubResponse { id: hub_id, hub_url: url })))
}

// ---------------------------------------------------------------------------
// GET /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

pub async fn get_hub(
    Path(hub_id): Path<String>,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<HubEntry>, (StatusCode, Json<serde_json::Value>)> {
    let row: Option<(String, Option<String>, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT name, description, visibility, created_at, suspended_at
         FROM hubs WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let (name, description, visibility, created_at, suspended_at) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "hub_not_found"})),
        )
    })?;

    Ok(Json(HubEntry {
        hub_url: hub_url(&state.farm_url, &hub_id),
        id: hub_id,
        name,
        description,
        visibility,
        created_at,
        suspended_at,
    }))
}

// ---------------------------------------------------------------------------
// PATCH /farm/hubs/:hub_id/suspend
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct SuspendResponse {
    pub id: String,
    pub suspended_at: Option<i64>,
}

pub async fn suspend_hub(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<SuspendRequest>,
) -> Result<Json<SuspendResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // Only farm admin may suspend.
    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(&payload.sub) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM hubs WHERE id = ? AND deleted_at IS NULL")
            .bind(&hub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "hub_not_found"})),
        ));
    }

    let now = unix_now();
    sqlx::query(
        "UPDATE hubs SET suspended_at = ?, suspension_reason = ? WHERE id = ?",
    )
    .bind(now)
    .bind(&req.reason)
    .bind(&hub_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(SuspendResponse {
        id: hub_id,
        suspended_at: Some(now),
    }))
}

// ---------------------------------------------------------------------------
// DELETE /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

pub async fn delete_hub(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // Admin or owner may delete.
    let admin_pubkey = get_admin_pubkey(&state.db).await;
    let is_admin = admin_pubkey.as_deref() == Some(&payload.sub);

    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_pubkey FROM hubs WHERE id = ? AND deleted_at IS NULL")
            .bind(&hub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    let (owner_pubkey,) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "hub_not_found"})),
        )
    })?;

    if !is_admin && payload.sub != owner_pubkey {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }

    // Stop the hub process if running.
    if let Err(e) = state.hub_manager.stop_hub(&hub_id).await {
        tracing::warn!(hub_id, error = %e, "Failed to stop hub process on delete (continuing)");
    }

    // Tombstone the row (leave DB file for operator).
    let now = unix_now();
    sqlx::query("UPDATE hubs SET deleted_at = ? WHERE id = ?")
        .bind(now)
        .bind(&hub_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
