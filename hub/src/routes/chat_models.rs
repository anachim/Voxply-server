use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub is_category: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChannelResponse {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub parent_id: Option<String>,
    pub is_category: bool,
    pub display_order: i64,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub custom_icon_svg: Option<String>,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct UpdateChannelRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Tri-state: absent = don't touch, `Some(Some(id))` = set parent,
    /// `Some(None)` = move to top level.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub parent_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub icon: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub color: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub custom_icon_svg: Option<Option<String>>,
}

/// Lets us distinguish "field missing" from "field explicitly null" in JSON.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// One inline attachment carried with a message. We embed bytes directly
/// (base64) rather than introducing a separate storage subsystem; the per-
/// message size cap below keeps this from getting out of hand.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    /// Base64-encoded file bytes (no data: URI prefix).
    pub data_b64: String,
}

/// Hard cap per message, summed across all attachments. 3 MB of base64
/// is roughly 2.25 MB of binary -- enough for screenshots, small images,
/// short clips, but bounded so the DB and WS frames don't get crushed.
pub const MAX_ATTACHMENTS_BYTES: usize = 3 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Optional parent message id to thread under.
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// Minimal preview of a parent message. We embed it in replies so the
/// client can render "replying to X" without a second fetch. If the
/// parent is gone, this is None and the reply renders alone.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReplyContext {
    pub message_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content_preview: String,
}

/// Aggregated reaction count for one emoji on one message. `me` flags
/// whether the requesting user is one of the reactors so the client can
/// render the toggle state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReactionSummary {
    pub emoji: String,
    pub count: i64,
    pub me: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageResponse {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: String,
    pub created_at: i64,
    #[serde(default)]
    pub edited_at: Option<i64>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub reactions: Vec<ReactionSummary>,
    #[serde(default)]
    pub reply_to: Option<ReplyContext>,
    /// When set, only the named user should see this message.
    /// NULL / None = normal broadcast. Used for ephemeral bot replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_to_pubkey: Option<String>,
}

#[derive(Deserialize)]
pub struct ReactionRequest {
    pub emoji: String,
}

#[derive(Serialize, Deserialize)]
pub struct EditMessageRequest {
    pub content: String,
}

#[derive(Clone, Debug)]
pub enum ChatEvent {
    New { channel_id: String, message: MessageResponse },
    Edited { channel_id: String, message: MessageResponse },
    Deleted { channel_id: String, message_id: String },
    /// Reactions changed on a message. We send the full per-message
    /// summary list rather than diffs so the client can replace the
    /// counts atomically without bookkeeping. `me` is intentionally
    /// false here -- it's per-viewer, the client recomputes it.
    ReactionsUpdated {
        channel_id: String,
        message_id: String,
        reactions: Vec<ReactionSummary>,
    },
    /// Ephemeral typing indicator. We piggyback on the chat broadcast
    /// channel since the WS dispatcher already has subscription filtering;
    /// the dispatcher skips echoing this back to the sender.
    Typing {
        channel_id: String,
        public_key: String,
        display_name: Option<String>,
        typing: bool,
    },
    ScreenShareStarted {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    ScreenShareStopped {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
    },
}

impl ChatEvent {
    pub fn channel_id(&self) -> &str {
        match self {
            ChatEvent::New { channel_id, .. }
            | ChatEvent::Edited { channel_id, .. }
            | ChatEvent::Deleted { channel_id, .. }
            | ChatEvent::ReactionsUpdated { channel_id, .. }
            | ChatEvent::Typing { channel_id, .. }
            | ChatEvent::ScreenShareStarted { channel_id, .. }
            | ChatEvent::ScreenShareStopped { channel_id, .. } => channel_id,
        }
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub before: Option<String>,
    pub limit: Option<i64>,
    /// Optional search query: if present, filter messages by content LIKE
    /// %q% (case-insensitive on SQLite). Pagination via before still works.
    pub q: Option<String>,
}

#[derive(Deserialize)]
pub struct WsParams {
    pub token: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum WsClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { channel_id: String },
    #[serde(rename = "unsubscribe")]
    Unsubscribe { channel_id: String },
    #[serde(rename = "voice_join")]
    VoiceJoin { channel_id: String, udp_port: u16 },
    #[serde(rename = "voice_leave")]
    VoiceLeave { channel_id: String },
    #[serde(rename = "voice_speaking")]
    VoiceSpeaking { channel_id: String, speaking: bool },
    #[serde(rename = "typing")]
    Typing { channel_id: String, typing: bool },
    #[serde(rename = "dm_typing")]
    DmTyping { conversation_id: String, typing: bool },
    #[serde(rename = "screen_share_start")]
    ScreenShareStart {
        channel_id: String,
        stream_id: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    #[serde(rename = "screen_share_chunk")]
    ScreenShareChunk {
        channel_id: String,
        stream_id: String,
        seq: u32,
        is_init: bool,
    },
    #[serde(rename = "screen_share_stop")]
    ScreenShareStop {
        channel_id: String,
        stream_id: String,
    },
    /// Bot sends this after connecting to request replay of missed events.
    #[serde(rename = "resume")]
    Resume { since_seq: i64 },
    /// User or bot interaction with a message component (button, select).
    #[serde(rename = "component_interaction")]
    ComponentInteraction {
        message_id: String,
        custom_id: String,
        #[serde(default)]
        values: Vec<String>,
    },
}

#[derive(Serialize, Clone)]
#[serde(tag = "type")]
pub enum WsServerMessage {
    #[serde(rename = "message")]
    ChatMessage {
        channel_id: String,
        message: MessageResponse,
    },
    #[serde(rename = "message_edited")]
    MessageEdited {
        channel_id: String,
        message: MessageResponse,
    },
    #[serde(rename = "message_deleted")]
    MessageDeleted {
        channel_id: String,
        message_id: String,
    },
    #[serde(rename = "reactions_updated")]
    ReactionsUpdated {
        channel_id: String,
        message_id: String,
        reactions: Vec<ReactionSummary>,
    },
    #[serde(rename = "typing")]
    Typing {
        channel_id: String,
        public_key: String,
        display_name: Option<String>,
        typing: bool,
    },
    #[serde(rename = "voice_joined")]
    VoiceJoined {
        channel_id: String,
        hub_udp_port: u16,
        participants: Vec<VoiceParticipantInfo>,
    },
    #[serde(rename = "voice_participant_joined")]
    VoiceParticipantJoined {
        channel_id: String,
        participant: VoiceParticipantInfo,
    },
    #[serde(rename = "voice_participant_left")]
    VoiceParticipantLeft {
        channel_id: String,
        public_key: String,
    },
    #[serde(rename = "voice_participant_speaking")]
    VoiceParticipantSpeaking {
        channel_id: String,
        public_key: String,
        speaking: bool,
    },
    /// Generic error message, shown to the user as a toast. `context` is a
    /// short machine-readable hint (e.g. "voice_join") so the client can
    /// route the message contextually if it wants.
    #[serde(rename = "error")]
    Error {
        context: String,
        message: String,
    },
    #[serde(rename = "dm")]
    DirectMessage {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        content: String,
        timestamp: i64,
    },
    #[serde(rename = "dm_typing")]
    DmTyping {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        typing: bool,
    },
    #[serde(rename = "screen_share_started")]
    ScreenShareStarted {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    #[serde(rename = "screen_share_chunk")]
    ScreenShareChunkOut {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        seq: u32,
        is_init: bool,
    },
    #[serde(rename = "screen_share_stopped")]
    ScreenShareStopped {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
    },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VoiceParticipantInfo {
    pub public_key: String,
    pub display_name: Option<String>,
}
