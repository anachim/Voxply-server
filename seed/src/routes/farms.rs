/// Farm discovery aggregator routes.
///
/// POST   /farms/register — register or refresh a farm listing
/// DELETE /farms/register — deregister a farm by proving ownership
/// GET    /farms          — public catalog of registered farms
use std::sync::Arc;

use axum::extract::{Query, RawQuery, State};
use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::state::SeedState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn bad_request(code: &str) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": code})),
    )
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": format!("internal: {detail}")})),
    )
}

/// Verify an Ed25519 signature over `message` with `pubkey_hex`.
///
/// Returns `Err(ApiError)` on any verification failure.
fn ed25519_verify(pubkey_hex: &str, message: &[u8], sig_hex: &str) -> Result<(), ApiError> {
    let pub_bytes = hex::decode(pubkey_hex).map_err(|_| bad_request("invalid_pubkey_hex"))?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| bad_request("invalid_pubkey_length"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(|_| bad_request("invalid_pubkey"))?;

    let sig_bytes = hex::decode(sig_hex).map_err(|_| bad_request("invalid_signature_hex"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| bad_request("invalid_signature_length"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| bad_request("signature_mismatch"))
}

// ---------------------------------------------------------------------------
// Public-info response shape from the farm's /farm/public-info endpoint.
// We only decode the fields we need.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FarmPublicInfo {
    #[allow(dead_code)]
    kind: Option<String>,
    /// The farm's Ed25519 public key.
    public_key: Option<String>,
    /// Must be true for the farm to appear in the directory.
    allow_discovery_listing: Option<bool>,
    /// Number of hosted hubs.
    hub_count: Option<i64>,
    /// Farm-wide hub cap; null/absent = unlimited.
    max_hubs_total: Option<i64>,
}

/// Fetch and parse `{farm_url}/farm/public-info`.
///
/// Returns `Err(ApiError)` if the farm is unreachable, returns non-200, or
/// does not allow discovery listing.
async fn fetch_public_info(
    client: &reqwest::Client,
    farm_url: &str,
) -> Result<FarmPublicInfo, ApiError> {
    let url = format!("{}/farm/public-info", farm_url.trim_end_matches('/'));

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|_| bad_request("farm_not_reachable"))?;

    if !response.status().is_success() {
        return Err(bad_request("farm_not_accepting_listing"));
    }

    let info: FarmPublicInfo = response
        .json()
        .await
        .map_err(|_| bad_request("farm_invalid_public_info"))?;

    if !info.allow_discovery_listing.unwrap_or(false) {
        return Err(bad_request("farm_not_accepting_listing"));
    }

    Ok(info)
}

/// Compute `capacity_pct` from `hub_count` and `max_hubs_total`.
///
/// Returns `None` when `max_hubs_total` is null or zero (unlimited).
fn compute_capacity_pct(hub_count: i64, max_hubs_total: Option<i64>) -> Option<i64> {
    let cap = max_hubs_total?;
    if cap <= 0 {
        return None;
    }
    Some(((hub_count * 100) / cap).min(100))
}

// ---------------------------------------------------------------------------
// POST /farms/register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub farm_url: String,
    pub farm_pubkey: String,
    pub name: String,
    pub description: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub languages: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    /// Hex Ed25519 signature of `farm_pubkey | nonce` — used to prove key ownership.
    /// For registration we validate ownership by verifying the farm calls back with
    /// matching `public_key`. The signed_nonce field is accepted but we rely on the
    /// callback verification as the authoritative proof.
    pub signed_nonce: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub registered: bool,
    pub last_verified_at: i64,
}

pub async fn register(
    State(state): State<Arc<SeedState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    // Basic input validation.
    if req.farm_url.is_empty() {
        return Err(bad_request("missing_farm_url"));
    }
    if req.farm_pubkey.len() != 64 {
        return Err(bad_request("invalid_farm_pubkey"));
    }
    if req.name.trim().is_empty() {
        return Err(bad_request("missing_name"));
    }

    // Step 1 & 2: Call back to the farm and verify pubkey matches.
    let public_info = fetch_public_info(&state.http_client, &req.farm_url).await?;

    if let Some(ref remote_pk) = public_info.public_key {
        if remote_pk != &req.farm_pubkey {
            return Err(bad_request("pubkey_mismatch"));
        }
    } else {
        return Err(bad_request("farm_missing_public_key"));
    }

    // Step 3: Geo-verification.
    // TODO: add geo-verification using a maxminddb or similar IP-geolocation DB.
    // For v1 we always set geo_unverified = 0 (treat all as verified).
    let geo_unverified: i64 = 0;

    // Step 4: Upsert the farm row.
    let now = unix_now();

    let hub_count = public_info.hub_count.unwrap_or(0);
    let max_hubs_total = public_info.max_hubs_total;
    let capacity_pct = compute_capacity_pct(hub_count, max_hubs_total);

    let languages_json = req
        .languages
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[\"en\"]".to_string()))
        .unwrap_or_else(|| "[\"en\"]".to_string());

    let tags_json = req
        .tags
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    sqlx::query(
        "INSERT INTO registered_farms
            (farm_url, farm_pubkey, name, description, country, region,
             languages, tags, hub_count, max_hubs_total, capacity_pct,
             geo_unverified, last_verified_at, registered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(farm_url) DO UPDATE SET
            farm_pubkey         = excluded.farm_pubkey,
            name                = excluded.name,
            description         = excluded.description,
            country             = excluded.country,
            region              = excluded.region,
            languages           = excluded.languages,
            tags                = excluded.tags,
            hub_count           = excluded.hub_count,
            max_hubs_total      = excluded.max_hubs_total,
            capacity_pct        = excluded.capacity_pct,
            geo_unverified      = excluded.geo_unverified,
            last_verified_at    = excluded.last_verified_at",
    )
    .bind(&req.farm_url)
    .bind(&req.farm_pubkey)
    .bind(req.name.trim())
    .bind(&req.description)
    .bind(&req.country)
    .bind(&req.region)
    .bind(&languages_json)
    .bind(&tags_json)
    .bind(hub_count)
    .bind(max_hubs_total)
    .bind(capacity_pct)
    .bind(geo_unverified)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| internal(e))?;

    Ok(Json(RegisterResponse {
        registered: true,
        last_verified_at: now,
    }))
}

// ---------------------------------------------------------------------------
// DELETE /farms/register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeregisterRequest {
    pub farm_url: String,
    pub farm_pubkey: String,
    /// Random hex nonce (32+ bytes recommended).
    pub nonce: String,
    /// Ed25519 signature over `farm_pubkey_bytes | nonce_bytes`.
    pub signature: String,
}

#[derive(Serialize)]
pub struct DeregisterResponse {
    pub deregistered: bool,
}

pub async fn deregister(
    State(state): State<Arc<SeedState>>,
    Json(req): Json<DeregisterRequest>,
) -> Result<Json<DeregisterResponse>, ApiError> {
    if req.farm_pubkey.len() != 64 {
        return Err(bad_request("invalid_farm_pubkey"));
    }

    // The message signed is `farm_pubkey_bytes || nonce_bytes`.
    let pubkey_bytes =
        hex::decode(&req.farm_pubkey).map_err(|_| bad_request("invalid_farm_pubkey_hex"))?;
    let nonce_bytes =
        hex::decode(&req.nonce).map_err(|_| bad_request("invalid_nonce_hex"))?;

    let mut message = Vec::with_capacity(pubkey_bytes.len() + nonce_bytes.len());
    message.extend_from_slice(&pubkey_bytes);
    message.extend_from_slice(&nonce_bytes);

    ed25519_verify(&req.farm_pubkey, &message, &req.signature)?;

    // Verify the farm_url is actually in our DB with this pubkey.
    let stored_pk: Option<String> = sqlx::query_scalar(
        "SELECT farm_pubkey FROM registered_farms WHERE farm_url = ?",
    )
    .bind(&req.farm_url)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal(e))?;

    match stored_pk {
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not_listed"})),
            ))
        }
        Some(pk) if pk != req.farm_pubkey => {
            return Err(bad_request("pubkey_mismatch"));
        }
        _ => {}
    }

    sqlx::query("DELETE FROM registered_farms WHERE farm_url = ?")
        .bind(&req.farm_url)
        .execute(&state.db)
        .await
        .map_err(|e| internal(e))?;

    Ok(Json(DeregisterResponse {
        deregistered: true,
    }))
}

// ---------------------------------------------------------------------------
// GET /farms
// ---------------------------------------------------------------------------

/// Query parameters for the farms listing (scalar fields only).
/// Repeated `?tag=` values are extracted separately via `RawQuery`.
#[derive(Deserialize, Default)]
pub struct FarmsQuery {
    /// Filter by ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// Filter by region string (e.g. "EU-West").
    pub region: Option<String>,
    /// Filter to farms whose `languages` array contains this BCP-47 code.
    pub language: Option<String>,
}

#[derive(Serialize)]
pub struct FarmEntry {
    pub farm_url: String,
    pub farm_pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub hub_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_pct: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub languages: serde_json::Value,
    pub tags: serde_json::Value,
    pub geo_unverified: bool,
    pub last_verified_at: i64,
    /// Present when the farm's last_verified_at is older than 24 hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Serialize)]
pub struct FarmsResponse {
    pub farms: Vec<FarmEntry>,
    pub generated_at: i64,
}

/// Row returned from the registered_farms DB query.
#[derive(sqlx::FromRow)]
struct FarmRow {
    farm_url: String,
    farm_pubkey: String,
    name: String,
    description: Option<String>,
    hub_count: i64,
    max_hubs_total: Option<i64>,
    capacity_pct: Option<i64>,
    country: Option<String>,
    region: Option<String>,
    languages: String,
    tags: String,
    geo_unverified: i64,
    last_verified_at: i64,
}

/// Parse all occurrences of `key=value` from a URL-encoded query string.
fn extract_repeated_param(raw: Option<&str>, key: &str) -> Vec<String> {
    let raw = match raw {
        Some(r) => r,
        None => return vec![],
    };
    raw.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key {
                Some(
                    percent_decode(v)
                )
            } else {
                None
            }
        })
        .collect()
}

/// Minimal percent-decode for query parameter values (handles + as space, %XX sequences).
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let byte = ((hi << 4) | lo) as u8;
                result.push(byte as char);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(' ');
            i += 1;
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

pub async fn list_farms(
    RawQuery(raw_query): RawQuery,
    Query(query): Query<FarmsQuery>,
    State(state): State<Arc<SeedState>>,
) -> Result<Json<FarmsResponse>, ApiError> {
    // Extract all ?tag= values (repeatable, AND logic).
    let required_tags = extract_repeated_param(raw_query.as_deref(), "tag");
    let now = unix_now();
    // Entries stale for more than 24 hours are included but flagged.
    let stale_threshold = now - 86400;

    // Build query with filters. We use SQLite json_each() for array containment.
    // The base query loads all farms then we apply optional filters in Rust for
    // the tag multi-value AND case (simpler and correct vs. chaining CTEs).
    //
    // For country/region/language we filter in SQL for efficiency.
    // For tags (repeatable, AND) we post-filter in Rust.

    // Base SQL — always fetches all rows matching country/region/language filters.
    let rows: Vec<FarmRow> = if let Some(ref country) = query.country {
        if let Some(ref language) = query.language {
            if let Some(ref region) = query.region {
                sqlx::query_as(
                    "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                            f.hub_count, f.max_hubs_total, f.capacity_pct,
                            f.country, f.region, f.languages, f.tags,
                            f.geo_unverified, f.last_verified_at
                     FROM registered_farms f
                     WHERE f.country = ?
                       AND f.region = ?
                       AND EXISTS (
                           SELECT 1 FROM json_each(f.languages)
                           WHERE json_each.value = ?
                       )
                     ORDER BY f.last_verified_at DESC",
                )
                .bind(country)
                .bind(region)
                .bind(language)
                .fetch_all(&state.db)
                .await
            } else {
                sqlx::query_as(
                    "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                            f.hub_count, f.max_hubs_total, f.capacity_pct,
                            f.country, f.region, f.languages, f.tags,
                            f.geo_unverified, f.last_verified_at
                     FROM registered_farms f
                     WHERE f.country = ?
                       AND EXISTS (
                           SELECT 1 FROM json_each(f.languages)
                           WHERE json_each.value = ?
                       )
                     ORDER BY f.last_verified_at DESC",
                )
                .bind(country)
                .bind(language)
                .fetch_all(&state.db)
                .await
            }
        } else if let Some(ref region) = query.region {
            sqlx::query_as(
                "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                        f.hub_count, f.max_hubs_total, f.capacity_pct,
                        f.country, f.region, f.languages, f.tags,
                        f.geo_unverified, f.last_verified_at
                 FROM registered_farms f
                 WHERE f.country = ? AND f.region = ?
                 ORDER BY f.last_verified_at DESC",
            )
            .bind(country)
            .bind(region)
            .fetch_all(&state.db)
            .await
        } else {
            sqlx::query_as(
                "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                        f.hub_count, f.max_hubs_total, f.capacity_pct,
                        f.country, f.region, f.languages, f.tags,
                        f.geo_unverified, f.last_verified_at
                 FROM registered_farms f
                 WHERE f.country = ?
                 ORDER BY f.last_verified_at DESC",
            )
            .bind(country)
            .fetch_all(&state.db)
            .await
        }
    } else if let Some(ref language) = query.language {
        if let Some(ref region) = query.region {
            sqlx::query_as(
                "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                        f.hub_count, f.max_hubs_total, f.capacity_pct,
                        f.country, f.region, f.languages, f.tags,
                        f.geo_unverified, f.last_verified_at
                 FROM registered_farms f
                 WHERE f.region = ?
                   AND EXISTS (
                       SELECT 1 FROM json_each(f.languages)
                       WHERE json_each.value = ?
                   )
                 ORDER BY f.last_verified_at DESC",
            )
            .bind(region)
            .bind(language)
            .fetch_all(&state.db)
            .await
        } else {
            sqlx::query_as(
                "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                        f.hub_count, f.max_hubs_total, f.capacity_pct,
                        f.country, f.region, f.languages, f.tags,
                        f.geo_unverified, f.last_verified_at
                 FROM registered_farms f
                 WHERE EXISTS (
                     SELECT 1 FROM json_each(f.languages)
                     WHERE json_each.value = ?
                 )
                 ORDER BY f.last_verified_at DESC",
            )
            .bind(language)
            .fetch_all(&state.db)
            .await
        }
    } else if let Some(ref region) = query.region {
        sqlx::query_as(
            "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                    f.hub_count, f.max_hubs_total, f.capacity_pct,
                    f.country, f.region, f.languages, f.tags,
                    f.geo_unverified, f.last_verified_at
             FROM registered_farms f
             WHERE f.region = ?
             ORDER BY f.last_verified_at DESC",
        )
        .bind(region)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            "SELECT f.farm_url, f.farm_pubkey, f.name, f.description,
                    f.hub_count, f.max_hubs_total, f.capacity_pct,
                    f.country, f.region, f.languages, f.tags,
                    f.geo_unverified, f.last_verified_at
             FROM registered_farms f
             ORDER BY f.last_verified_at DESC",
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| internal(e))?;

    // required_tags is already extracted above from the raw query string.

    let farms: Vec<FarmEntry> = rows
        .into_iter()
        .filter_map(|row| {
            // Parse the tags JSON array for post-filtering.
            let tags_val: serde_json::Value =
                serde_json::from_str(&row.tags).unwrap_or_else(|_| serde_json::json!([]));
            let tag_strs: Vec<&str> = tags_val
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect()
                })
                .unwrap_or_default();

            // All required tags must be present.
            for req_tag in &required_tags {
                if !tag_strs.contains(&req_tag.as_str()) {
                    return None;
                }
            }

            let languages_val: serde_json::Value =
                serde_json::from_str(&row.languages).unwrap_or_else(|_| serde_json::json!(["en"]));

            // capacity_pct: omit when max_hubs_total is null/0 (unlimited).
            let capacity_pct = row.capacity_pct.filter(|_| {
                row.max_hubs_total.map(|v| v > 0).unwrap_or(false)
            });

            let stale = if row.last_verified_at < stale_threshold {
                Some(true)
            } else {
                None
            };

            Some(FarmEntry {
                farm_url: row.farm_url,
                farm_pubkey: row.farm_pubkey,
                name: row.name,
                description: row.description,
                hub_count: row.hub_count,
                capacity_pct,
                country: row.country,
                region: row.region,
                languages: languages_val,
                tags: tags_val,
                geo_unverified: row.geo_unverified != 0,
                last_verified_at: row.last_verified_at,
                stale,
            })
        })
        .collect();

    Ok(Json(FarmsResponse {
        farms,
        generated_at: now,
    }))
}
