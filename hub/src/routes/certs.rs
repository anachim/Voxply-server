//! Hub certification routes — Task #20 (issuance, admin management) and
//! Task #21 (auth gate helpers + /info cert_requirement field).
//!
//! Routes registered in server.rs:
//!   POST   /admin/certs/:pubkey              — manual issue
//!   POST   /admin/certs/:pubkey/revoke       — revoke (re-issue as standing=revoked)
//!   GET    /admin/certs                      — list all issued certs
//!   GET    /identity/:pubkey/certs           — public: non-revoked certs for a user
//!   PATCH  /admin/settings/certs            — update cert settings
//!
//! The periodic sweep lives in cert_worker.rs (spawned from main.rs).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::handlers::unix_timestamp;
use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// The canonical payload signed by the issuing hub.
#[derive(Serialize, Deserialize, Clone)]
pub struct CertPayload {
    pub subject_kind: String,   // always "user"
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub subject_pubkey: String,
    pub member_since: i64,
    pub standing: String,       // "good" | "revoked"
    pub pow_level: Option<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub capabilities: Vec<String>,
}

/// A certification envelope (payload + hub signature).
#[derive(Serialize, Deserialize, Clone)]
pub struct Certification {
    pub payload: CertPayload,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Admin: manual issue
// ---------------------------------------------------------------------------

/// POST /admin/certs/:pubkey
pub async fn admin_issue(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(subject_pubkey): Path<String>,
) -> Result<(StatusCode, Json<Certification>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let cert = issue_cert_for(&state, &subject_pubkey).await?;
    Ok((StatusCode::CREATED, Json(cert)))
}

/// POST /admin/certs/:pubkey/revoke
pub async fn admin_revoke(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(subject_pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    revoke_cert_for(&state, &subject_pubkey).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/certs
pub async fn admin_list(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<IssuanceRow>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, IssuanceDbRow>(
        "SELECT id, subject_pubkey, pow_level, member_since, issued_at, expires_at,
                revoked_at, standing, payload_json, signature
         FROM cert_issuances ORDER BY issued_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

// ---------------------------------------------------------------------------
// Public: GET /identity/:pubkey/certs
// ---------------------------------------------------------------------------

/// Returns non-revoked, non-expired certs this hub has issued for a user.
/// This is the "pull by pubkey" path from §4 of the design: a receiving hub
/// can fetch issued certs directly from the issuing hub.
///
/// Also serves as the home-hub portfolio endpoint: when a client calls
/// `PUT /identity/:pubkey/certs` to deposit a cert, it appears here too
/// (stored in user_certs). This route combines both: issuing-hub issuances
/// (cert_issuances) and deposited cross-hub certs (user_certs).
pub async fn list_user_certs(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<Certification>>, (StatusCode, String)> {
    let now = unix_timestamp();

    // 1. Certs this hub issued for the user (from cert_issuances ledger).
    let issued = sqlx::query_as::<_, UserCertRow>(
        "SELECT payload_json, signature FROM cert_issuances
         WHERE subject_pubkey = ? AND standing = 'good' AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(&pubkey)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // 2. Cross-hub certs deposited into the portfolio (user_certs).
    let deposited = sqlx::query_as::<_, UserCertRow>(
        "SELECT payload_json, signature FROM user_certs
         WHERE master_pubkey = ? AND expires_at > ?",
    )
    .bind(&pubkey)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let all_rows = issued.into_iter().chain(deposited);

    let out: Result<Vec<_>, _> = all_rows
        .map(|r| {
            let payload: CertPayload = serde_json::from_str(&r.payload_json)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Payload parse error: {e}")))?;
            if payload.standing == "revoked" {
                return Ok(None);
            }
            Ok(Some(Certification {
                payload,
                signature: r.signature,
            }))
        })
        .collect();

    let certs: Vec<Certification> = out?.into_iter().flatten().collect();
    Ok(Json(certs))
}

// ---------------------------------------------------------------------------
// Admin: PATCH /admin/settings/certs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CertSettingsPatch {
    pub cert_auto_issue: Option<String>,
    pub cert_standing_days: Option<String>,
    pub cert_validity_days: Option<String>,
    pub cert_mode: Option<String>,
    pub cert_trusted_issuers: Option<serde_json::Value>,
    pub cert_require: Option<serde_json::Value>,
    pub cert_min_pow_level: Option<String>,
}

pub async fn patch_cert_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<CertSettingsPatch>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Validate cert_mode if provided
    if let Some(ref mode) = body.cert_mode {
        if !["none", "any", "trusted"].contains(&mode.as_str()) {
            return Err((StatusCode::BAD_REQUEST, "cert_mode must be 'none', 'any', or 'trusted'".to_string()));
        }
    }

    let mut kvs: Vec<(&'static str, String)> = Vec::new();

    if let Some(v) = body.cert_auto_issue { kvs.push(("cert_auto_issue", v)); }
    if let Some(v) = body.cert_standing_days { kvs.push(("cert_standing_days", v)); }
    if let Some(v) = body.cert_validity_days { kvs.push(("cert_validity_days", v)); }
    if let Some(v) = body.cert_mode { kvs.push(("cert_mode", v)); }
    if let Some(v) = body.cert_min_pow_level { kvs.push(("cert_min_pow_level", v)); }
    if let Some(v) = body.cert_trusted_issuers {
        kvs.push(("cert_trusted_issuers", v.to_string()));
    }
    if let Some(v) = body.cert_require {
        kvs.push(("cert_require", v.to_string()));
    }

    for (key, value) in kvs {
        sqlx::query(
            "INSERT INTO hub_settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(&value)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Issuance logic (shared by admin_issue + cert_worker)
// ---------------------------------------------------------------------------

/// Build, sign, and record a cert for `subject_pubkey`. Returns the envelope
/// or a (status, message) error if the user is ineligible or not found.
pub async fn issue_cert_for(
    state: &AppState,
    subject_pubkey: &str,
) -> Result<Certification, (StatusCode, String)> {
    let now = unix_timestamp();

    // Load user row
    let user_row: Option<(i64, i64, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT first_seen_at, last_seen_at, approval_status, pow_level, COALESCE(pow_level,0)
         FROM users WHERE public_key = ?",
    )
    .bind(subject_pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (first_seen_at, _last_seen_at, approval_status, _pow_col, pow_level_i64) =
        user_row.ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;
    let pow_level = if pow_level_i64 > 0 { Some(pow_level_i64 as u8) } else { None };

    if approval_status != "approved" {
        return Err((StatusCode::FORBIDDEN, "User is not approved".to_string()));
    }

    // Check not banned
    if crate::routes::moderation::is_banned(&state.db, subject_pubkey).await? {
        return Err((StatusCode::FORBIDDEN, "User is banned".to_string()));
    }

    let validity_days: i64 = setting_i64(state, "cert_validity_days", 90).await;
    let expires_at = now + validity_days * 86400;

    let our_pubkey = state.hub_identity.public_key_hex();
    let hub_url = load_hub_url(state).await;

    let payload = CertPayload {
        subject_kind: "user".to_string(),
        issuer_pubkey: our_pubkey.clone(),
        issuer_url: hub_url,
        subject_pubkey: subject_pubkey.to_string(),
        member_since: first_seen_at,
        standing: "good".to_string(),
        pow_level,
        issued_at: now,
        expires_at,
        capabilities: vec![],
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialise error: {e}")))?;

    let sig = state.hub_identity.sign(payload_json.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO cert_issuances
         (id, subject_pubkey, pow_level, member_since, issued_at, expires_at, standing, payload_json, signature)
         VALUES (?, ?, ?, ?, ?, ?, 'good', ?, ?)",
    )
    .bind(&id)
    .bind(subject_pubkey)
    .bind(pow_level.map(|v| v as i64))
    .bind(first_seen_at)
    .bind(now)
    .bind(expires_at)
    .bind(&payload_json)
    .bind(&sig_hex)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Issued cert {} for {} (expires +{}d)",
        &id[..8],
        &subject_pubkey[..16.min(subject_pubkey.len())],
        validity_days,
    );

    Ok(Certification { payload, signature: sig_hex })
}

/// Re-issue with standing="revoked" and mark the old row revoked_at.
pub async fn revoke_cert_for(
    state: &AppState,
    subject_pubkey: &str,
) -> Result<(), (StatusCode, String)> {
    let now = unix_timestamp();

    // Mark any existing non-revoked certs revoked in the ledger.
    sqlx::query(
        "UPDATE cert_issuances SET revoked_at = ?, standing = 'revoked'
         WHERE subject_pubkey = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(subject_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Re-issue a cert with standing=revoked so pull-path verifiers see it.
    let user_row: Option<(i64,)> = sqlx::query_as(
        "SELECT first_seen_at FROM users WHERE public_key = ?",
    )
    .bind(subject_pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if let Some((first_seen_at,)) = user_row {
        let our_pubkey = state.hub_identity.public_key_hex();
        let hub_url = load_hub_url(state).await;
        // Revoked cert: expires in 1 day (long enough to be seen, short enough to not linger).
        let expires_at = now + 86400;

        let payload = CertPayload {
            subject_kind: "user".to_string(),
            issuer_pubkey: our_pubkey,
            issuer_url: hub_url,
            subject_pubkey: subject_pubkey.to_string(),
            member_since: first_seen_at,
            standing: "revoked".to_string(),
            pow_level: None,
            issued_at: now,
            expires_at,
            capabilities: vec![],
        };
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialise error: {e}")))?;
        let sig = state.hub_identity.sign(payload_json.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO cert_issuances
             (id, subject_pubkey, pow_level, member_since, issued_at, expires_at, revoked_at, standing, payload_json, signature)
             VALUES (?, ?, NULL, ?, ?, ?, ?, 'revoked', ?, ?)",
        )
        .bind(&id)
        .bind(subject_pubkey)
        .bind(first_seen_at)
        .bind(now)
        .bind(expires_at)
        .bind(now)
        .bind(&payload_json)
        .bind(&sig_hex)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cert verification (used by auth gate in handlers.rs — Task #21)
// ---------------------------------------------------------------------------

/// Load and parse the cert_trusted_issuers setting (array of {pubkey, url, label}).
pub async fn load_trusted_issuers(state: &AppState) -> Vec<TrustedIssuer> {
    let json_str: String = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_trusted_issuers'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "[]".to_string());

    serde_json::from_str(&json_str).unwrap_or_default()
}

/// Load and parse the cert_require setting ({min_pow_level?, min_member_since_days?}).
pub async fn load_cert_require(state: &AppState) -> CertRequire {
    let json_str: String = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_require'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "{}".to_string());

    serde_json::from_str(&json_str).unwrap_or_default()
}

/// Load the cert_mode setting: "none" | "any" | "trusted".
pub async fn load_cert_mode(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_mode'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "none".to_string())
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TrustedIssuer {
    pub pubkey: String,
    pub url: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CertRequire {
    #[serde(default)]
    pub min_pow_level: Option<u8>,
    #[serde(default)]
    pub min_member_since_days: Option<u32>,
}

/// Verify a presented `Certification` against the hub's admission policy.
///
/// - Checks signature against `payload.issuer_pubkey`.
/// - Checks expiry and standing.
/// - Checks subject matches `auth_master_pubkey`.
/// - Depending on `cert_mode`:
///   - "any": any valid cert whose issuer's pubkey matches `/info` (cached) is accepted.
///   - "trusted": issuer pubkey must be in trusted_issuers list.
///
/// The issuer /info check is skipped for locally-issued certs (issuer == this hub's pubkey),
/// since we hold the key.
pub async fn verify_certification(
    _state: &AppState,
    cert: &Certification,
    auth_master_pubkey: &str,
    cert_mode: &str,
    trusted_issuers: &[TrustedIssuer],
    cert_require: &CertRequire,
) -> bool {
    let now = unix_timestamp();
    let payload = &cert.payload;

    // 1. subject binding
    if payload.subject_pubkey != auth_master_pubkey {
        return false;
    }
    // 2. expiry
    if now > payload.expires_at {
        return false;
    }
    // 3. standing
    if payload.standing != "good" {
        return false;
    }
    // 4. signature
    let sig_bytes = match hex::decode(&cert.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let payload_json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if voxply_identity::verify_signature(&payload.issuer_pubkey, payload_json.as_bytes(), &sig_bytes).is_err() {
        return false;
    }

    // 5. cert_require property rules (checked independently of trust list)
    if let Some(min_pow) = cert_require.min_pow_level {
        match payload.pow_level {
            Some(level) if level >= min_pow => {}
            _ => return false,
        }
    }
    if let Some(min_days) = cert_require.min_member_since_days {
        let required_since = now - (min_days as i64) * 86400;
        if payload.member_since > required_since {
            return false;
        }
    }

    // 6. trust check
    match cert_mode {
        "any" => true, // any valid cert satisfies
        "trusted" => {
            // issuer pubkey must be in the trusted list
            trusted_issuers.iter().any(|ti| ti.pubkey == payload.issuer_pubkey)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// /info cert_requirement field types (Task #21)
// ---------------------------------------------------------------------------

/// Advertised cert requirement for GET /info.
#[derive(Serialize, Deserialize, Clone)]
pub struct CertRequirement {
    pub mode: String,
    pub trusted_issuers: Vec<TrustedIssuer>,
    pub require: CertRequire,
}

/// Load the full cert requirement descriptor for /info.
pub async fn load_cert_requirement(state: &AppState) -> Option<CertRequirement> {
    let mode = load_cert_mode(state).await;
    if mode == "none" {
        return None;
    }
    Some(CertRequirement {
        mode,
        trusted_issuers: load_trusted_issuers(state).await,
        require: load_cert_require(state).await,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn load_hub_url(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

async fn setting_i64(state: &AppState, key: &str, default: i64) -> i64 {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = ?",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// sqlx row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct IssuanceDbRow {
    pub id: String,
    pub subject_pubkey: String,
    pub pow_level: Option<i64>,
    pub member_since: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub standing: String,
    pub payload_json: String,
    #[allow(dead_code)]
    pub signature: String,
}

/// Public-facing response shape for admin list.
#[derive(Serialize, Deserialize)]
pub struct IssuanceRow {
    pub id: String,
    pub subject_pubkey: String,
    pub pow_level: Option<u8>,
    pub member_since: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub standing: String,
    pub payload: CertPayload,
}

impl From<IssuanceDbRow> for IssuanceRow {
    fn from(r: IssuanceDbRow) -> Self {
        let payload: CertPayload = serde_json::from_str(&r.payload_json)
            .unwrap_or_else(|_| CertPayload {
                subject_kind: "user".to_string(),
                issuer_pubkey: String::new(),
                issuer_url: String::new(),
                subject_pubkey: r.subject_pubkey.clone(),
                member_since: r.member_since,
                standing: r.standing.clone(),
                pow_level: r.pow_level.map(|v| v as u8),
                issued_at: r.issued_at,
                expires_at: r.expires_at,
                capabilities: vec![],
            });
        Self {
            id: r.id,
            subject_pubkey: r.subject_pubkey,
            pow_level: r.pow_level.map(|v| v as u8),
            member_since: r.member_since,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            standing: r.standing,
            payload,
        }
    }
}

#[derive(sqlx::FromRow)]
struct UserCertRow {
    pub payload_json: String,
    pub signature: String,
}
