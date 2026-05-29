use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::federation::models::{
    AddPeerRequest, FederatedChannelResponse, FederatedMessageResponse, PeerInfo,
};
use crate::permissions;
use crate::state::AppState;

pub async fn add_peer(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AddPeerRequest>,
) -> Result<(StatusCode, Json<PeerInfo>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let url = req.url.trim_end_matches('/').to_string();

    // Discover the remote hub
    let info = state
        .federation_client
        .get_info(&url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Cannot reach peer: {e}")))?;

    // Authenticate our hub to the remote hub
    let token = state
        .federation_client
        .authenticate(&url, &state.hub_identity)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Handshake failed: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();

    // Store the peer in DB
    sqlx::query(
        "INSERT INTO peers (public_key, name, url, added_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(public_key) DO UPDATE SET name = ?, url = ?",
    )
    .bind(&info.public_key)
    .bind(&info.name)
    .bind(&url)
    .bind(&now)
    .bind(&info.name)
    .bind(&url)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Cache the session token in memory
    state
        .peer_tokens
        .write()
        .await
        .insert(info.public_key.clone(), token);

    tracing::info!("Peered with hub '{}' ({})", info.name, &info.public_key[..16]);

    Ok((
        StatusCode::CREATED,
        Json(PeerInfo {
            public_key: info.public_key,
            name: info.name,
            url,
            added_at: now,
        }),
    ))
}

pub async fn list_peers(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<PeerInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, PeerRow>(
        "SELECT public_key, name, url, added_at FROM peers ORDER BY added_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let peers = rows
        .into_iter()
        .map(|r| PeerInfo {
            public_key: r.public_key,
            name: r.name,
            url: r.url,
            added_at: r.added_at,
        })
        .collect();

    Ok(Json(peers))
}

pub async fn peer_channels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(peer_key): Path<String>,
) -> Result<Json<Vec<FederatedChannelResponse>>, (StatusCode, String)> {
    // Look up peer URL and token
    let peer = get_peer(&state, &peer_key).await?;
    let token = get_peer_token(&state, &peer_key).await?;

    // Fetch channels from remote hub
    let channels = state
        .federation_client
        .get_channels(&peer.url, &token)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to fetch channels: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    let mut result = Vec::new();

    for ch in channels {
        let fed_id = format!("{}:{}", &peer_key[..16], &ch.id);

        // Cache in DB (upsert)
        sqlx::query(
            "INSERT INTO federated_channels (id, peer_public_key, remote_id, name, created_at, last_synced_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(peer_public_key, remote_id) DO UPDATE SET name = ?, last_synced_at = ?",
        )
        .bind(&fed_id)
        .bind(&peer_key)
        .bind(&ch.id)
        .bind(&ch.name)
        .bind(&ch.created_at)
        .bind(&now)
        .bind(&ch.name)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        result.push(FederatedChannelResponse {
            id: fed_id,
            peer_public_key: peer_key.clone(),
            remote_id: ch.id,
            name: ch.name,
            created_at: ch.created_at,
        });
    }

    Ok(Json(result))
}

pub async fn all_federated_channels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<FederatedChannelResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, FedChannelRow>(
        "SELECT id, peer_public_key, remote_id, name, created_at FROM federated_channels ORDER BY name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let channels = rows
        .into_iter()
        .map(|r| FederatedChannelResponse {
            id: r.id,
            peer_public_key: r.peer_public_key,
            remote_id: r.remote_id,
            name: r.name,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(channels))
}

pub async fn federated_messages(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(fed_channel_id): Path<String>,
) -> Result<Json<Vec<FederatedMessageResponse>>, (StatusCode, String)> {
    // Look up the federated channel to find peer + remote channel ID
    let fed_ch = sqlx::query_as::<_, FedChannelRow>(
        "SELECT id, peer_public_key, remote_id, name, created_at FROM federated_channels WHERE id = ?",
    )
    .bind(&fed_channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Federated channel not found".to_string()))?;

    let peer = get_peer(&state, &fed_ch.peer_public_key).await?;
    let token = get_peer_token(&state, &fed_ch.peer_public_key).await?;

    // Fetch messages from remote hub
    let messages = state
        .federation_client
        .get_messages(&peer.url, &token, &fed_ch.remote_id)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to fetch messages: {e}")))?;

    // Cache in DB
    for msg in &messages {
        let local_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO federated_messages (id, fed_channel_id, remote_id, sender, content, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&local_id)
        .bind(&fed_channel_id)
        .bind(&msg.id)
        .bind(&msg.sender)
        .bind(&msg.content)
        .bind(&msg.created_at)
        .execute(&state.db)
        .await;
    }

    let result = messages
        .into_iter()
        .map(|m| FederatedMessageResponse {
            id: m.id.clone(),
            remote_id: m.id,
            sender: m.sender,
            content: m.content,
            created_at: m.created_at,
        })
        .collect();

    Ok(Json(result))
}

pub async fn send_federated_message(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(fed_channel_id): Path<String>,
    Json(req): Json<crate::routes::chat_models::SendMessageRequest>,
) -> Result<(StatusCode, Json<FederatedMessageResponse>), (StatusCode, String)> {
    let fed_ch = sqlx::query_as::<_, FedChannelRow>(
        "SELECT id, peer_public_key, remote_id, name, created_at FROM federated_channels WHERE id = ?",
    )
    .bind(&fed_channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Federated channel not found".to_string()))?;

    let peer = get_peer(&state, &fed_ch.peer_public_key).await?;
    let token = get_peer_token(&state, &fed_ch.peer_public_key).await?;

    let msg = state
        .federation_client
        .send_message(&peer.url, &token, &fed_ch.remote_id, &req.content)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to send message: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(FederatedMessageResponse {
            id: msg.id.clone(),
            remote_id: msg.id,
            sender: msg.sender,
            content: msg.content,
            created_at: msg.created_at,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Federation: badge-offer endpoint (unauthenticated, signature is the auth)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BadgeOfferRequest {
    /// Hex Ed25519 public key of the hub sending the offer.
    pub from_hub_pubkey: String,
    /// Self-reported URL of the issuer hub (informational, not trusted for routing).
    pub from_hub_url: String,
    /// Human-readable badge label.
    pub label: String,
    /// Optional human-readable note from the issuer.
    pub note: Option<String>,
    /// Canonical JSON payload (BadgePayload serialised deterministically).
    pub payload: String,
    /// Hex Ed25519 signature over `payload` bytes.
    pub signature: String,
}

/// POST /federation/badge-offer
///
/// Unauthenticated endpoint: anyone can POST here, but we require a valid
/// Ed25519 signature from `from_hub_pubkey` over `payload` bytes, and we
/// verify that `payload.subject_pubkey` matches this hub's own public key.
/// Valid offers land in `badge_offers` for the admin to accept or decline.
pub async fn receive_badge_offer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BadgeOfferRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1. Parse and validate payload shape.
    let payload: crate::routes::badges::BadgePayload =
        serde_json::from_str(&req.payload)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Malformed badge payload JSON".to_string()))?;

    // 2. Verify that the subject is this hub.
    let our_pubkey = state.hub_identity.public_key_hex();
    if payload.subject_pubkey != our_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "Badge subject_pubkey does not match this hub".to_string(),
        ));
    }

    // 3. Verify Ed25519 signature: from_hub_pubkey signs the payload bytes.
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    voxply_identity::verify_signature(&req.from_hub_pubkey, req.payload.as_bytes(), &sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Badge signature verification failed".to_string()))?;

    // 4. Also validate that the issuer_pubkey in the payload matches from_hub_pubkey.
    if payload.issuer_pubkey != req.from_hub_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "payload.issuer_pubkey does not match from_hub_pubkey".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = crate::auth::handlers::unix_timestamp_iso();

    sqlx::query(
        "INSERT INTO badge_offers
         (id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.from_hub_pubkey)
    .bind(&req.from_hub_url)
    .bind(&req.label)
    .bind(&req.note)
    .bind(&req.payload)
    .bind(&req.signature)
    .bind(&created_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Received badge offer '{}' from {} ({})",
        req.label,
        req.from_hub_url,
        &req.from_hub_pubkey[..16.min(req.from_hub_pubkey.len())]
    );

    Ok(StatusCode::CREATED)
}

// Helpers

async fn get_peer(state: &AppState, peer_key: &str) -> Result<PeerRow, (StatusCode, String)> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT public_key, name, url, added_at FROM peers WHERE public_key = ?",
    )
    .bind(peer_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Peer not found".to_string()))
}

async fn get_peer_token(state: &AppState, peer_key: &str) -> Result<String, (StatusCode, String)> {
    state
        .peer_tokens
        .read()
        .await
        .get(peer_key)
        .cloned()
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "No active session with this peer. Re-add the peer to re-authenticate.".to_string(),
        ))
}

#[derive(sqlx::FromRow)]
struct PeerRow {
    public_key: String,
    name: String,
    url: String,
    added_at: i64,
}

#[derive(sqlx::FromRow)]
struct FedChannelRow {
    id: String,
    peer_public_key: String,
    remote_id: String,
    name: String,
    created_at: i64,
}
