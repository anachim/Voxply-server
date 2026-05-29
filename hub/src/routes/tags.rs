use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

/// Reserved tag words that imply third-party attestation.
/// These are blocked as self-tags because badges (Part 2) provide that
/// cryptographically; allowing self-assertion would create obvious confusion.
const RESERVED_TAGS: &[&str] = &["verified", "certified", "official", "partner", "admin"];

/// Max self-tags per hub (listing-stuffing cap from the design doc).
const MAX_TAGS: usize = 12;

#[derive(Serialize)]
pub struct TagsResponse {
    pub tags: Vec<String>,
}

#[derive(Deserialize)]
pub struct PatchTagsRequest {
    pub tags: Vec<String>,
}

/// Normalise a single tag: lowercase + trim. Returns an error string
/// when the tag violates the character/length/reserved rules.
fn normalise_tag(raw: &str) -> Result<String, String> {
    let t = raw.trim().to_lowercase();
    if t.is_empty() || t.len() > 32 {
        return Err(format!(
            "Tag '{}' must be 1–32 characters",
            raw.trim()
        ));
    }
    // After normalisation only [a-z0-9-] are allowed.
    if !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!(
            "Tag '{}' may only contain a–z, 0–9, and hyphens",
            t
        ));
    }
    if RESERVED_TAGS.contains(&t.as_str()) {
        return Err(format!(
            "Tag '{}' is reserved and cannot be used as a self-tag",
            t
        ));
    }
    Ok(t)
}

/// GET /admin/settings/tags
pub async fn get_tags(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<TagsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let tags = load_tags(&state).await?;
    Ok(Json(TagsResponse { tags }))
}

/// PATCH /admin/settings/tags
pub async fn patch_tags(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PatchTagsRequest>,
) -> Result<Json<TagsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    if req.tags.len() > MAX_TAGS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("A hub may have at most {MAX_TAGS} self-tags"),
        ));
    }

    let mut normalised = Vec::with_capacity(req.tags.len());
    for raw in &req.tags {
        let t = normalise_tag(raw)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        normalised.push(t);
    }

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    normalised.retain(|t| seen.insert(t.clone()));

    let json_val = serde_json::to_string(&normalised)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialise error: {e}")))?;

    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES ('hub_tags', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&json_val)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(TagsResponse { tags: normalised }))
}

/// Load the current self-tags from hub_settings. Returns an empty vec if
/// the row is absent (fresh DB before the seed runs) or malformed JSON.
pub async fn load_tags(state: &AppState) -> Result<Vec<String>, (StatusCode, String)> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'hub_tags'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(raw
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default())
}

/// Load the current nsfw flag from hub_settings.
pub async fn load_nsfw(state: &AppState) -> bool {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_nsfw'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(false)
}
