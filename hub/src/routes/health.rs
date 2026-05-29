use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

pub async fn info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let min_security_level: u32 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_security_level'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let min_pow_level: u8 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_pow_level'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let invite_only: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'invite_only'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|v| v == "true")
    .unwrap_or(false);

    let challenge_mode: String = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'challenge_mode'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "off".to_string());

    let branding = crate::routes::hub::read_branding(&state).await;

    Json(InfoResponse {
        name: branding.name,
        description: branding.description,
        icon: branding.icon,
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_key: state.hub_identity.public_key_hex(),
        min_security_level,
        min_pow_level,
        invite_only,
        challenge_mode,
        farm_url: state.farm_url.clone(),
    })
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    pub version: String,
    pub public_key: String,
    pub min_security_level: u32,
    /// Minimum PoW level required to authenticate via the structured
    /// `pow_proof` field in `/auth/verify`. 0 means no PoW required.
    pub min_pow_level: u8,
    pub invite_only: bool,
    #[serde(default)]
    pub challenge_mode: String,
    /// URL of the farm this hub is paired with, or null for self-contained auth.
    /// Clients see this field and route `/auth/*` calls to the farm when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub farm_url: Option<String>,
}
