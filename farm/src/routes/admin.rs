/// Farm admin routes — settings, user management, quota.
///
/// GET  /farm/settings                      — read full farm settings (admin)
/// PATCH /farm/settings                     — update farm settings (admin)
/// GET  /farm/me/hub-quota                  — current user's hub-creation eligibility (authed)
/// GET  /farm/users                         — paginated farm-user index (admin)
/// POST /farm/users/:pubkey/revoke-sessions — revoke all sessions for a user (admin)
/// GET  /farm/public-info                   — narrow discovery probe (unauthenticated)
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::FarmState;
use crate::token::verify_token;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Extract and verify a Bearer farm token. Returns the payload on success.
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

/// Load the admin pubkey from the farms singleton row.
async fn get_admin_pubkey(db: &sqlx::SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

/// Require a valid farm session whose `sub` matches `farms.admin_pubkey`.
async fn require_admin(
    headers: &HeaderMap,
    state: &FarmState,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(headers, &farm_pubkey)?;

    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(payload.sub.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }
    Ok(payload.sub)
}

// ---------------------------------------------------------------------------
// Shared DB row type for the farms singleton
// ---------------------------------------------------------------------------

/// All Phase-3 policy fields from the `farms` row.
#[allow(dead_code)]
struct FarmRow {
    name: String,
    description: Option<String>,
    directory_public: i64,
    creation_policy: String,
    max_hubs_per_user: i64,
    max_hubs_total: i64,
    allow_discovery_listing: i64,
    languages: String,
    tags: String,
    country: Option<String>,
    region: Option<String>,
    admin_pubkey: Option<String>,
}

async fn fetch_farm_row(
    db: &sqlx::SqlitePool,
) -> Result<FarmRow, (StatusCode, Json<serde_json::Value>)> {
    let row: Option<(
        String,
        Option<String>,
        i64,
        String,
        i64,
        i64,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT name, description, directory_public,
                creation_policy, max_hubs_per_user, max_hubs_total,
                allow_discovery_listing, languages, tags,
                country, region, admin_pubkey
         FROM farms WHERE id = 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let row = row.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "farm_row_missing"})),
        )
    })?;

    Ok(FarmRow {
        name: row.0,
        description: row.1,
        directory_public: row.2,
        creation_policy: row.3,
        max_hubs_per_user: row.4,
        max_hubs_total: row.5,
        allow_discovery_listing: row.6,
        languages: row.7,
        tags: row.8,
        country: row.9,
        region: row.10,
        admin_pubkey: row.11,
    })
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const VALID_TAGS: &[&str] = &[
    "gaming",
    "professional",
    "creative",
    "education",
    "community",
    "18plus",
];

fn validate_creation_policy(v: &str) -> bool {
    matches!(v, "open" | "admin_only" | "disabled")
}

/// BCP-47 basic validation: 2-letter lowercase codes only.
fn validate_language(code: &str) -> bool {
    code.len() == 2 && code.chars().all(|c| c.is_ascii_lowercase())
}

fn validate_tags(tags: &[String]) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if tags.len() > 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_tag", "details": "max 3 tags"})),
        ));
    }
    for tag in tags {
        if !VALID_TAGS.contains(&tag.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_tag", "details": format!("unknown tag: {tag}")})),
            ));
        }
    }
    Ok(())
}

fn validate_languages(langs: &[String]) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if langs.is_empty() || langs.len() > 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_value", "details": "languages must be 1-5 items"})),
        ));
    }
    for lang in langs {
        if !validate_language(lang) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_value", "details": format!("invalid BCP-47 code: {lang}")})),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /farm/settings
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FarmSettingsResponse {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub directory_public: bool,
    pub creation_policy: String,
    pub max_hubs_per_user: i64,
    pub max_hubs_total: i64,
    pub allow_discovery_listing: bool,
    pub languages: serde_json::Value,
    pub tags: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_pubkey: Option<String>,
}

pub async fn get_settings(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<FarmSettingsResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    let row = fetch_farm_row(&state.db).await?;

    let languages: serde_json::Value = serde_json::from_str(&row.languages).unwrap_or_else(|_| {
        serde_json::json!(["en"])
    });
    let tags: serde_json::Value = serde_json::from_str(&row.tags).unwrap_or_else(|_| {
        serde_json::json!([])
    });

    Ok(Json(FarmSettingsResponse {
        name: row.name,
        description: row.description,
        directory_public: row.directory_public != 0,
        creation_policy: row.creation_policy,
        max_hubs_per_user: row.max_hubs_per_user,
        max_hubs_total: row.max_hubs_total,
        allow_discovery_listing: row.allow_discovery_listing != 0,
        languages,
        tags,
        country: row.country,
        region: row.region,
        admin_pubkey: row.admin_pubkey,
    }))
}

// ---------------------------------------------------------------------------
// PATCH /farm/settings
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PatchSettingsRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub directory_public: Option<bool>,
    pub creation_policy: Option<String>,
    pub max_hubs_per_user: Option<i64>,
    pub max_hubs_total: Option<i64>,
    pub allow_discovery_listing: Option<bool>,
    pub languages: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub country: Option<String>,
    pub region: Option<String>,
}

pub async fn patch_settings(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<PatchSettingsRequest>,
) -> Result<Json<FarmSettingsResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    // Validate fields before touching the DB.
    if let Some(ref policy) = req.creation_policy {
        if !validate_creation_policy(policy) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_value", "details": "creation_policy must be open, admin_only, or disabled"})),
            ));
        }
    }
    if let Some(ref tags) = req.tags {
        validate_tags(tags)?;
    }
    if let Some(ref langs) = req.languages {
        validate_languages(langs)?;
    }

    // Build the UPDATE statement dynamically from whichever fields were provided.
    // We always UPDATE at least one column so the query is never trivially empty.
    let row = fetch_farm_row(&state.db).await?;

    let new_name = req.name.unwrap_or(row.name);
    let new_description = req.description.or(row.description);
    let new_directory_public = req
        .directory_public
        .map(|b| b as i64)
        .unwrap_or(row.directory_public);
    let new_creation_policy = req.creation_policy.unwrap_or(row.creation_policy);
    let new_max_per_user = req.max_hubs_per_user.unwrap_or(row.max_hubs_per_user);
    let new_max_total = req.max_hubs_total.unwrap_or(row.max_hubs_total);
    let new_allow_discovery = req
        .allow_discovery_listing
        .map(|b| b as i64)
        .unwrap_or(row.allow_discovery_listing);
    let new_languages = req
        .languages
        .map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "[\"en\"]".to_string()))
        .unwrap_or(row.languages);
    let new_tags = req
        .tags
        .map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or(row.tags);
    let new_country = req.country.or(row.country);
    let new_region = req.region.or(row.region);

    sqlx::query(
        "UPDATE farms SET
            name = ?,
            description = ?,
            directory_public = ?,
            creation_policy = ?,
            max_hubs_per_user = ?,
            max_hubs_total = ?,
            allow_discovery_listing = ?,
            languages = ?,
            tags = ?,
            country = ?,
            region = ?
         WHERE id = 1",
    )
    .bind(&new_name)
    .bind(&new_description)
    .bind(new_directory_public)
    .bind(&new_creation_policy)
    .bind(new_max_per_user)
    .bind(new_max_total)
    .bind(new_allow_discovery)
    .bind(&new_languages)
    .bind(&new_tags)
    .bind(&new_country)
    .bind(&new_region)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let languages_val: serde_json::Value =
        serde_json::from_str(&new_languages).unwrap_or_else(|_| serde_json::json!(["en"]));
    let tags_val: serde_json::Value =
        serde_json::from_str(&new_tags).unwrap_or_else(|_| serde_json::json!([]));

    Ok(Json(FarmSettingsResponse {
        name: new_name,
        description: new_description,
        directory_public: new_directory_public != 0,
        creation_policy: new_creation_policy,
        max_hubs_per_user: new_max_per_user,
        max_hubs_total: new_max_total,
        allow_discovery_listing: new_allow_discovery != 0,
        languages: languages_val,
        tags: tags_val,
        country: new_country,
        region: new_region,
        admin_pubkey: row.admin_pubkey,
    }))
}

// ---------------------------------------------------------------------------
// GET /farm/me/hub-quota
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HubQuotaResponse {
    pub creation_policy: String,
    pub hubs_owned: i64,
    pub max_hubs_per_user: i64,
    pub quota_remaining: Option<i64>,
    pub farm_hubs_total: i64,
    pub max_hubs_total: i64,
    pub farm_quota_remaining: Option<i64>,
}

pub async fn me_hub_quota(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<HubQuotaResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    let row = fetch_farm_row(&state.db).await?;

    let hubs_owned: i64 = sqlx::query_scalar(
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

    let farm_hubs_total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE deleted_at IS NULL")
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    let quota_remaining = if row.max_hubs_per_user == 0 {
        None
    } else {
        Some((row.max_hubs_per_user - hubs_owned).max(0))
    };

    let farm_quota_remaining = if row.max_hubs_total == 0 {
        None
    } else {
        Some((row.max_hubs_total - farm_hubs_total).max(0))
    };

    Ok(Json(HubQuotaResponse {
        creation_policy: row.creation_policy,
        hubs_owned,
        max_hubs_per_user: row.max_hubs_per_user,
        quota_remaining,
        farm_hubs_total,
        max_hubs_total: row.max_hubs_total,
        farm_quota_remaining,
    }))
}

// ---------------------------------------------------------------------------
// GET /farm/users
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListUsersQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct UserEntry {
    pub public_key: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub hubs_owned: i64,
    pub active_sessions: i64,
}

#[derive(Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<UserEntry>,
    pub total: i64,
}

pub async fn list_users(
    headers: HeaderMap,
    Query(query): Query<ListUsersQuery>,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListUsersResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    let limit = query.limit.unwrap_or(50).min(200).max(1);
    let now = unix_now();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM farm_users")
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    // Cursor-based pagination: cursor is a public_key; return rows where public_key > cursor.
    let rows: Vec<(String, i64, i64, i64, i64)> = if let Some(ref cursor) = query.cursor {
        sqlx::query_as(
            "SELECT u.public_key, u.first_seen_at, u.last_seen_at,
                    COUNT(DISTINCT h.id) AS hubs_owned,
                    COUNT(DISTINCT s.jti) AS active_sessions
             FROM farm_users u
             LEFT JOIN hubs h ON h.owner_pubkey = u.public_key AND h.deleted_at IS NULL
             LEFT JOIN farm_sessions s ON s.public_key = u.public_key
                 AND s.revoked_at IS NULL AND s.expires_at > ?
             WHERE u.public_key > ?
             GROUP BY u.public_key
             ORDER BY u.public_key
             LIMIT ?",
        )
        .bind(now)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            "SELECT u.public_key, u.first_seen_at, u.last_seen_at,
                    COUNT(DISTINCT h.id) AS hubs_owned,
                    COUNT(DISTINCT s.jti) AS active_sessions
             FROM farm_users u
             LEFT JOIN hubs h ON h.owner_pubkey = u.public_key AND h.deleted_at IS NULL
             LEFT JOIN farm_sessions s ON s.public_key = u.public_key
                 AND s.revoked_at IS NULL AND s.expires_at > ?
             GROUP BY u.public_key
             ORDER BY u.public_key
             LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let users = rows
        .into_iter()
        .map(
            |(public_key, first_seen_at, last_seen_at, hubs_owned, active_sessions)| UserEntry {
                public_key,
                first_seen_at,
                last_seen_at,
                hubs_owned,
                active_sessions,
            },
        )
        .collect();

    Ok(Json(ListUsersResponse { users, total }))
}

// ---------------------------------------------------------------------------
// POST /farm/users/:pubkey/revoke-sessions
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RevokeSessionsResponse {
    pub revoked: u64,
}

pub async fn revoke_user_sessions(
    Path(pubkey): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<RevokeSessionsResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    // Verify the user exists.
    let exists: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM farm_users WHERE public_key = ?")
            .bind(&pubkey)
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
            Json(serde_json::json!({"error": "user_not_found"})),
        ));
    }

    let now = unix_now();

    // Mark all non-expired, non-already-revoked sessions as revoked.
    let result = sqlx::query(
        "UPDATE farm_sessions
         SET revoked_at = ?, revoked_manually = 1
         WHERE public_key = ?
           AND revoked_at IS NULL
           AND expires_at > ?",
    )
    .bind(now)
    .bind(&pubkey)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(RevokeSessionsResponse {
        revoked: result.rows_affected(),
    }))
}

// ---------------------------------------------------------------------------
// GET /farm/public-info
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PublicInfoResponse {
    pub kind: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub creation_policy: String,
    pub hub_count: i64,
    pub max_hubs_total: i64,
    pub allow_discovery_listing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub languages: serde_json::Value,
    pub tags: serde_json::Value,
}

pub async fn public_info(
    State(state): State<Arc<FarmState>>,
) -> Result<Json<PublicInfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    let row = fetch_farm_row(&state.db).await?;

    if row.allow_discovery_listing == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "discovery_disabled"})),
        ));
    }

    let hub_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE deleted_at IS NULL")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let languages: serde_json::Value = serde_json::from_str(&row.languages).unwrap_or_else(|_| {
        serde_json::json!(["en"])
    });
    let tags: serde_json::Value = serde_json::from_str(&row.tags).unwrap_or_else(|_| {
        serde_json::json!([])
    });

    Ok(Json(PublicInfoResponse {
        kind: "voxply-farm-public",
        name: row.name,
        description: row.description,
        creation_policy: row.creation_policy,
        hub_count,
        max_hubs_total: row.max_hubs_total,
        allow_discovery_listing: row.allow_discovery_listing != 0,
        country: row.country,
        region: row.region,
        languages,
        tags,
    }))
}
