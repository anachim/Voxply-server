use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, mpsc, RwLock};
use voxply_identity::Identity;

use crate::federation::client::FederationClient;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DmEvent {
    Message {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        content: String,
        timestamp: i64,
    },
    Typing {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        typing: bool,
    },
}

impl DmEvent {
    pub fn conversation_id(&self) -> &str {
        match self {
            DmEvent::Message { conversation_id, .. }
            | DmEvent::Typing { conversation_id, .. } => conversation_id,
        }
    }
    pub fn sender(&self) -> &str {
        match self {
            DmEvent::Message { sender, .. } | DmEvent::Typing { sender, .. } => sender,
        }
    }
}

/// Metadata for a single active screen-share stream.
#[derive(Clone)]
pub struct ScreenStreamMeta {
    pub kind: String,
    pub mime: String,
    pub has_audio: bool,
    pub sharer_pubkey: String,
    /// Cached WebM init segment for late joiners. Set on the first chunk
    /// where `is_init == true`.
    pub init_chunk: Option<Bytes>,
    /// Wall time when this stream was registered. Used to distinguish
    /// "share started before I subscribed" (push needed) from
    /// "share started after I subscribed" (broadcast delivers it).
    pub started_at: Instant,
}

/// All active streams in one channel.
pub struct ActiveShare {
    /// stream_id → metadata
    pub streams: HashMap<String, ScreenStreamMeta>,
}

/// A screen-share chunk broadcast to all WS connections.
#[derive(Clone)]
pub struct ScreenChunkEvent {
    pub channel_id: String,
    pub stream_id: String,
    pub sharer_pubkey: String,
    pub seq: u32,
    pub is_init: bool,
    pub data: Bytes,
}

pub struct AppState {
    pub hub_name: String,
    pub hub_identity: Identity,
    pub db: SqlitePool,
    pub pending_challenges: RwLock<HashMap<String, PendingChallenge>>,
    pub chat_tx: broadcast::Sender<ChatEvent>,
    pub federation_client: FederationClient,
    pub peer_tokens: RwLock<HashMap<String, String>>,
    /// Plain HTTP client for outbound requests that don't go through the
    /// federation protocol (e.g. sending push invites to foreign hubs).
    pub http_client: reqwest::Client,
    // Voice: channel_id → {public_key → udp_addr}
    pub voice_channels: RwLock<HashMap<String, HashMap<String, SocketAddr>>>,
    pub voice_udp_port: u16,
    pub voice_event_tx: broadcast::Sender<(String, WsServerMessage)>,
    // DM relay: broadcast DMs to all WS clients (they filter by conversation membership)
    pub dm_tx: broadcast::Sender<DmEvent>,
    // Online users: public_key set (updated by WS connect/disconnect)
    pub online_users: RwLock<std::collections::HashSet<String>>,
    /// Active screen-share sessions: channel_id → ActiveShare.
    /// In-memory only — cleared on process restart.
    pub screen_shares: RwLock<HashMap<String, ActiveShare>>,
    /// Broadcast channel carrying binary chunk events to all WS connections.
    pub screen_share_tx: broadcast::Sender<ScreenChunkEvent>,
    /// Active bot WS sessions: bot_pubkey → mpsc sender for pre-serialised
    /// JSON text frames. Bots use a separate channel from the regular WS
    /// broadcast so we can push targeted hub_event messages without looping
    /// through every connected client.
    pub bot_sessions: RwLock<HashMap<String, mpsc::Sender<String>>>,
}

pub struct PendingChallenge {
    pub challenge_bytes: Vec<u8>,
    pub expires_at: Instant,
}
