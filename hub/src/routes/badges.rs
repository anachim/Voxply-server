use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// The canonical badge payload that the issuer signs.
/// Stored as JSON text in both `badge_offers` and `hub_badges`.
#[derive(Serialize, Deserialize, Clone)]
pub struct BadgePayload {
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub subject_pubkey: String,
    pub label: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

/// A badge as served on /info (payload + detached signature).
#[derive(Serialize, Deserialize, Clone)]
pub struct BadgeEnvelope {
    pub payload: BadgePayload,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Admin: pending badge offers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PendingBadgeResponse {
    pub id: String,
    pub from_hub_pubkey: String,
    pub from_hub_url: String,
    pub label: String,
    pub note: Option<String>,
    pub payload: BadgePayload,
    pub created_at: String,
}

/// GET /badges/pending
pub async fn list_pending(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<PendingBadgeResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, BadgeOfferRow>(
        "SELECT id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at
         FROM badge_offers ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out: Result<Vec<_>, _> = rows
        .into_iter()
        .map(|r| {
            let payload: BadgePayload = serde_json::from_str(&r.payload)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Payload parse error: {e}")))?;
            Ok(PendingBadgeResponse {
                id: r.id,
                from_hub_pubkey: r.from_hub_pubkey,
                from_hub_url: r.from_hub_url,
                label: r.label,
                note: r.note,
                payload,
                created_at: r.created_at,
            })
        })
        .collect();

    Ok(Json(out?))
}

/// POST /badges/pending/:id/accept
/// Verifies the signature, moves the offer to hub_badges.
pub async fn accept_pending(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let row = sqlx::query_as::<_, BadgeOfferRow>(
        "SELECT id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at
         FROM badge_offers WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Pending badge offer not found".to_string()))?;

    // Re-verify signature before accepting.
    let payload_bytes = row.payload.as_bytes();
    let sig_bytes = hex::decode(&row.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex in stored offer".to_string()))?;
    voxply_identity::verify_signature(&row.from_hub_pubkey, payload_bytes, &sig_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Badge signature verification failed".to_string()))?;

    // Also verify subject_pubkey matches our own hub.
    let payload: BadgePayload = serde_json::from_str(&row.payload)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Payload parse error: {e}")))?;
    let our_pubkey = state.hub_identity.public_key_hex();
    if payload.subject_pubkey != our_pubkey {
        return Err((StatusCode::BAD_REQUEST, "Badge subject does not match this hub".to_string()));
    }

    let accepted_at = crate::auth::handlers::unix_timestamp_iso();

    let badge_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO hub_badges (id, issuer_pubkey, issuer_url, label, payload, signature, accepted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&badge_id)
    .bind(&row.from_hub_pubkey)
    .bind(&row.from_hub_url)
    .bind(&row.label)
    .bind(&row.payload)
    .bind(&row.signature)
    .bind(&accepted_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM badge_offers WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /badges/pending/:id/decline
pub async fn decline_pending(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let affected = sqlx::query("DELETE FROM badge_offers WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if affected == 0 {
        return Err((StatusCode::NOT_FOUND, "Pending badge offer not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Admin: accepted badges this hub holds
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HeldBadgeResponse {
    pub id: String,
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub label: String,
    pub payload: BadgePayload,
    pub accepted_at: String,
}

/// GET /badges
pub async fn list_badges(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<HeldBadgeResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, HubBadgeRow>(
        "SELECT id, issuer_pubkey, issuer_url, label, payload, signature, accepted_at
         FROM hub_badges ORDER BY accepted_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out: Result<Vec<_>, _> = rows
        .into_iter()
        .map(|r| {
            let payload: BadgePayload = serde_json::from_str(&r.payload)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Payload parse error: {e}")))?;
            Ok(HeldBadgeResponse {
                id: r.id,
                issuer_pubkey: r.issuer_pubkey,
                issuer_url: r.issuer_url,
                label: r.label,
                payload,
                accepted_at: r.accepted_at,
            })
        })
        .collect();

    Ok(Json(out?))
}

/// DELETE /badges/:id
pub async fn delete_badge(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let affected = sqlx::query("DELETE FROM hub_badges WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if affected == 0 {
        return Err((StatusCode::NOT_FOUND, "Badge not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Admin: issue a badge to another hub
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IssueBadgeRequest {
    pub recipient_hub_url: String,
    pub label: String,
    pub note: Option<String>,
    pub expires_days: Option<u32>,
}

#[derive(Serialize)]
pub struct IssuedBadgeResponse {
    pub id: String,
    pub recipient_hub_url: String,
    pub recipient_hub_pubkey: String,
    pub label: String,
    pub payload: BadgePayload,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

/// POST /admin/badges/issue
///
/// Fetches the recipient hub's /info, builds the badge payload, signs it
/// with our hub keypair, POSTs it to the recipient's /federation/badge-offer,
/// and records the issued badge locally.
pub async fn issue_badge(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<IssueBadgeRequest>,
) -> Result<(StatusCode, Json<IssuedBadgeResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let recipient_url = req.recipient_hub_url.trim_end_matches('/').to_string();

    // Fetch the recipient hub's public key from its /info endpoint.
    let recipient_info = state
        .federation_client
        .get_info(&recipient_url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Cannot reach recipient hub: {e}")))?;

    let our_pubkey = state.hub_identity.public_key_hex();
    let our_url = load_hub_url(&state).await;
    let issued_at = crate::auth::handlers::unix_timestamp_iso();

    let expires_at: Option<String> = req.expires_days.map(|days| {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expire_secs = secs + (days as u64) * 86400;
        iso_from_unix(expire_secs)
    });

    let payload = BadgePayload {
        issuer_pubkey: our_pubkey.clone(),
        issuer_url: our_url.clone(),
        subject_pubkey: recipient_info.public_key.clone(),
        label: req.label.clone(),
        issued_at: issued_at.clone(),
        expires_at: expires_at.clone(),
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialise error: {e}")))?;

    let sig = state.hub_identity.sign(payload_json.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    // Push the badge offer to the recipient hub (best-effort; error bubbles up).
    state
        .federation_client
        .post_badge_offer(
            &recipient_url,
            &our_pubkey,
            &our_url,
            &req.label,
            req.note.as_deref(),
            &payload_json,
            &sig_hex,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to deliver badge offer: {e}")))?;

    // Record the issued badge locally.
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO issued_badges
         (id, recipient_hub_url, recipient_hub_pubkey, label, payload, signature, issued_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&recipient_url)
    .bind(&recipient_info.public_key)
    .bind(&req.label)
    .bind(&payload_json)
    .bind(&sig_hex)
    .bind(&issued_at)
    .bind(&expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Issued badge '{}' to {} ({})",
        req.label,
        recipient_url,
        &recipient_info.public_key[..16]
    );

    Ok((
        StatusCode::CREATED,
        Json(IssuedBadgeResponse {
            id,
            recipient_hub_url: recipient_url,
            recipient_hub_pubkey: recipient_info.public_key,
            label: req.label,
            payload,
            issued_at,
            expires_at,
        }),
    ))
}

/// GET /admin/badges/issued
pub async fn list_issued(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<IssuedBadgeResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, IssuedBadgeRow>(
        "SELECT id, recipient_hub_url, recipient_hub_pubkey, label, payload, signature, issued_at, expires_at
         FROM issued_badges ORDER BY issued_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out: Result<Vec<_>, _> = rows
        .into_iter()
        .map(|r| {
            let payload: BadgePayload = serde_json::from_str(&r.payload)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Payload parse error: {e}")))?;
            Ok(IssuedBadgeResponse {
                id: r.id,
                recipient_hub_url: r.recipient_hub_url,
                recipient_hub_pubkey: r.recipient_hub_pubkey,
                label: r.label,
                payload,
                issued_at: r.issued_at,
                expires_at: r.expires_at,
            })
        })
        .collect();

    Ok(Json(out?))
}

// ---------------------------------------------------------------------------
// Load accepted badges for /info (public, non-expired only)
// ---------------------------------------------------------------------------

/// Returns accepted badge envelopes for inclusion in the /info response.
/// Only non-expired badges are returned (based on the `expires_at` field
/// in the payload; NULL expires_at = never expires).
pub async fn load_active_badges(state: &AppState) -> Vec<BadgeEnvelope> {
    let rows = sqlx::query_as::<_, HubBadgeRow>(
        "SELECT id, issuer_pubkey, issuer_url, label, payload, signature, accepted_at
         FROM hub_badges ORDER BY accepted_at",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let now_iso = crate::auth::handlers::unix_timestamp_iso();

    rows.into_iter()
        .filter_map(|r| {
            let payload: BadgePayload = serde_json::from_str(&r.payload).ok()?;
            // Filter expired badges.
            if let Some(ref exp) = payload.expires_at {
                if exp.as_str() <= now_iso.as_str() {
                    return None;
                }
            }
            Some(BadgeEnvelope {
                payload,
                signature: r.signature,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the configured hub URL from hub_settings (key = 'hub_url').
/// Falls back to an empty string when not set so the badge payload is still
/// syntactically valid; the Tauri client or startup script should populate
/// this before issuing badges.
async fn load_hub_url(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Convert a Unix timestamp (seconds) to a simple ISO-8601 string.
fn iso_from_unix(secs: u64) -> String {
    // Reuse the same Gregorian decomposition as directory.rs.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let jdn = days + 2_440_588;
    let l = jdn + 68_569;
    let n = (4 * l) / 146_097;
    let l = l - (146_097 * n + 3) / 4;
    let year_i = (4_000 * (l + 1)) / 1_461_001;
    let l = l - (1_461 * year_i) / 4 + 31;
    let month_i = (80 * l) / 2_447;
    let day = l - (2_447 * month_i) / 80;
    let l = month_i / 11;
    let month = month_i + 2 - 12 * l;
    let year = 100 * (n - 49) + year_i + l;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

// ---------------------------------------------------------------------------
// sqlx row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct BadgeOfferRow {
    pub id: String,
    pub from_hub_pubkey: String,
    pub from_hub_url: String,
    pub label: String,
    pub note: Option<String>,
    pub payload: String,
    pub signature: String,
    pub created_at: String,
}

#[derive(sqlx::FromRow)]
struct HubBadgeRow {
    pub id: String,
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub label: String,
    pub payload: String,
    pub signature: String,
    pub accepted_at: String,
}

#[derive(sqlx::FromRow)]
struct IssuedBadgeRow {
    pub id: String,
    pub recipient_hub_url: String,
    pub recipient_hub_pubkey: String,
    pub label: String,
    pub payload: String,
    #[allow(dead_code)]
    pub signature: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
}
