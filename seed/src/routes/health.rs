use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct InfoResponse {
    pub kind: &'static str,
    pub role: &'static str,
    pub version: &'static str,
}

/// GET /info
///
/// Public endpoint so operators can probe what they are running.
pub async fn info() -> Json<InfoResponse> {
    Json(InfoResponse {
        kind: "voxply-seed",
        role: "discovery",
        version: env!("CARGO_PKG_VERSION"),
    })
}
