use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::routes::chat_models::{
    VoiceParticipantInfo, WsClientMessage, WsParams, WsServerMessage,
};
use crate::state::{ActiveShare, AppState, ScreenChunkEvent};

// ---------------------------------------------------------------------------
// Component interaction rate-limit store (in-memory, no external dep).
// Key: (user_pubkey, custom_id); Value: last interaction instant.
// ---------------------------------------------------------------------------
tokio::task_local! {
    // Not used across tasks; the HashMap is held per WS connection below.
}

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM sessions WHERE token = ?")
            .bind(&params.token)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let public_key = public_key
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;

    let is_revoked: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM subkey_revocations WHERE subkey_pubkey = ?",
    )
    .bind(&public_key)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if is_revoked {
        return Err((StatusCode::UNAUTHORIZED, "Key has been revoked".to_string()));
    }

    tracing::info!("WebSocket connected: {}", &public_key[..16.min(public_key.len())]);

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, public_key)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, public_key: String) {
    // Determine whether this connection belongs to a bot.
    let is_bot: bool = sqlx::query_scalar::<_, i64>(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&public_key)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0)
        != 0;

    state.online_users.write().await.insert(public_key.clone());

    let (mut ws_tx, mut ws_rx) = socket.split();

    // For bots we use an mpsc channel so that the events module can push
    // hub_event frames without going through the broadcast flood.
    // For regular users we keep the existing broadcast approach.
    let (bot_tx, mut bot_rx): (mpsc::Sender<String>, mpsc::Receiver<String>) =
        mpsc::channel(256);

    if is_bot {
        state.bot_sessions.write().await.insert(public_key.clone(), bot_tx.clone());
    }

    let mut chat_rx = state.chat_tx.subscribe();
    let chat_rx_since = std::time::Instant::now();
    let mut dm_rx = state.dm_tx.subscribe();
    let mut voice_rx = state.voice_event_tx.subscribe();
    let mut screen_share_rx = state.screen_share_tx.subscribe();
    let mut voice_channel: Option<String> = None;
    let mut pending_chunk: Option<(String, String, u32, bool)> = None;

    // Per-connection component interaction rate-limit map.
    // Key: (user_pubkey, custom_id). Value: last interaction instant.
    let mut component_rate_limit: HashMap<(String, String), Instant> = HashMap::new();

    // Load DM conversation memberships.
    let my_conversations: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT conversation_id FROM conversation_members WHERE public_key = ?",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Auto-subscribe to non-banned channels.
    let mut subscribed: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT id FROM channels
         WHERE is_category = 0
           AND id NOT IN (
               SELECT channel_id FROM channel_bans WHERE target_public_key = ?
           )",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Send `hello` with live_seq.
    {
        let live_seq = crate::bots::events::current_seq(&state).await;
        let hello = serde_json::json!({
            "type": "hello",
            "live_seq": live_seq,
        });
        let _ = ws_tx.send(Message::Text(hello.to_string().into())).await;
    }

    // Push in-progress screen shares to this client.
    {
        let shares = state.screen_shares.read().await;
        for channel_id in &subscribed {
            if let Some(active) = shares.get(channel_id) {
                for (stream_id, meta) in &active.streams {
                    if meta.started_at >= chat_rx_since {
                        continue;
                    }
                    let started = WsServerMessage::ScreenShareStarted {
                        channel_id: channel_id.clone(),
                        stream_id: stream_id.clone(),
                        sharer_pubkey: meta.sharer_pubkey.clone(),
                        kind: meta.kind.clone(),
                        mime: meta.mime.clone(),
                        has_audio: meta.has_audio,
                    };
                    let json = serde_json::to_string(&started).unwrap();
                    let _ = ws_tx.send(Message::Text(json.into())).await;
                    if let Some(init_bytes) = &meta.init_chunk {
                        let chunk_envelope = WsServerMessage::ScreenShareChunkOut {
                            channel_id: channel_id.clone(),
                            stream_id: stream_id.clone(),
                            sharer_pubkey: meta.sharer_pubkey.clone(),
                            seq: 0,
                            is_init: true,
                        };
                        let json = serde_json::to_string(&chunk_envelope).unwrap();
                        let _ = ws_tx.send(Message::Text(json.into())).await;
                        let _ = ws_tx.send(Message::Binary(init_bytes.to_vec().into())).await;
                    }
                }
            }
        }
    }

    // Replay buffer: accumulates live events during a bot replay pass.
    let mut replay_buffer: Vec<String> = Vec::new();
    #[allow(unused_assignments)]
    let mut is_replaying = false;

    loop {
        tokio::select! {
            result = chat_rx.recv() => {
                match result {
                    Ok((event, pre_json)) => {
                        if subscribed.contains(event.channel_id()) {
                            if let crate::routes::chat_models::ChatEvent::Typing {
                                public_key: sender_key, ..
                            } = &event
                            {
                                if sender_key == &public_key {
                                    continue;
                                }
                            }
                            if let crate::routes::chat_models::ChatEvent::New { message: ref m, .. } = &event {
                                if let Some(ref vtp) = m.visible_to_pubkey {
                                    if vtp != &public_key {
                                        continue;
                                    }
                                }
                            }
                            let json = pre_json.to_string();
                            if is_replaying {
                                replay_buffer.push(json);
                            } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged, missed {n} messages");
                    }
                    Err(_) => break,
                }
            }

            // Bot-targeted push messages (hub_event, token_expiring_soon, etc.)
            bot_msg = bot_rx.recv() => {
                match bot_msg {
                    Some(json) => {
                        if is_replaying {
                            replay_buffer.push(json);
                        } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }

            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsClientMessage>(&text) {
                            Ok(WsClientMessage::Subscribe { channel_id }) => {
                                let newly_subscribed = subscribed.insert(channel_id.clone());
                                if !newly_subscribed { continue; }
                                let shares = state.screen_shares.read().await;
                                if let Some(active) = shares.get(&channel_id) {
                                    for (stream_id, meta) in &active.streams {
                                        let started = WsServerMessage::ScreenShareStarted {
                                            channel_id: channel_id.clone(),
                                            stream_id: stream_id.clone(),
                                            sharer_pubkey: meta.sharer_pubkey.clone(),
                                            kind: meta.kind.clone(),
                                            mime: meta.mime.clone(),
                                            has_audio: meta.has_audio,
                                        };
                                        let json = serde_json::to_string(&started).unwrap();
                                        if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                            break;
                                        }
                                        if let Some(init_bytes) = &meta.init_chunk {
                                            let chunk_envelope = WsServerMessage::ScreenShareChunkOut {
                                                channel_id: channel_id.clone(),
                                                stream_id: stream_id.clone(),
                                                sharer_pubkey: meta.sharer_pubkey.clone(),
                                                seq: 0,
                                                is_init: true,
                                            };
                                            let json = serde_json::to_string(&chunk_envelope).unwrap();
                                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                                break;
                                            }
                                            if ws_tx
                                                .send(Message::Binary(init_bytes.to_vec().into()))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(WsClientMessage::Unsubscribe { channel_id }) => {
                                subscribed.remove(&channel_id);
                            }
                            Ok(WsClientMessage::VoiceJoin { channel_id, udp_port }) => {
                                let is_muted = crate::routes::moderation::is_voice_muted(
                                    &state.db, &public_key,
                                )
                                .await
                                .unwrap_or(false);
                                if is_muted {
                                    let err = WsServerMessage::Error {
                                        context: "voice_join".to_string(),
                                        message: "You are voice-muted on this hub.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }

                                let min_talk_power: i64 = sqlx::query_scalar(
                                    "SELECT min_talk_power FROM channel_settings WHERE channel_id = ?",
                                )
                                .bind(&channel_id)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten()
                                .unwrap_or(0);

                                if min_talk_power > 0 {
                                    let perms = crate::permissions::user_permissions(
                                        &state.db, &public_key,
                                    )
                                    .await;
                                    let user_priority = perms
                                        .as_ref()
                                        .map(|p| p.max_priority)
                                        .unwrap_or(0);
                                    if user_priority < min_talk_power {
                                        let err = WsServerMessage::Error {
                                            context: "voice_join".to_string(),
                                            message: format!(
                                                "This channel requires role priority {} to talk; you have {}.",
                                                min_talk_power, user_priority
                                            ),
                                        };
                                        let _ = ws_tx
                                            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                            .await;
                                        continue;
                                    }
                                }

                                let client_addr: SocketAddr =
                                    format!("127.0.0.1:{udp_port}").parse().unwrap();

                                state.voice_channels.write().await
                                    .entry(channel_id.clone())
                                    .or_default()
                                    .insert(public_key.clone(), client_addr);
                                state.voice_addr_map.write().await
                                    .insert(client_addr, (channel_id.clone(), public_key.clone()));

                                voice_channel = Some(channel_id.clone());

                                let participants = get_voice_participants(&state, &channel_id).await;

                                let msg = WsServerMessage::VoiceJoined {
                                    channel_id: channel_id.clone(),
                                    hub_udp_port: state.voice_udp_port,
                                    participants: participants.clone(),
                                };
                                let json = serde_json::to_string(&msg).unwrap();
                                let _ = ws_tx.send(Message::Text(json.into())).await;

                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();

                                let _ = state.voice_event_tx.send((
                                    channel_id.clone(),
                                    WsServerMessage::VoiceParticipantJoined {
                                        channel_id: voice_channel.clone().unwrap(),
                                        participant: VoiceParticipantInfo {
                                            public_key: public_key.clone(),
                                            display_name: display_name.clone(),
                                        },
                                    },
                                ));

                                // Publish member.joined audit event.
                                {
                                    let state_c = state.clone();
                                    let pk = public_key.clone();
                                    let ch = channel_id.clone();
                                    let dn = display_name;
                                    tokio::spawn(async move {
                                        crate::bots::events::publish_hub_event(
                                            &state_c,
                                            "member.joined",
                                            Some(&pk),
                                            None,
                                            Some(&ch),
                                            serde_json::json!({ "display_name": dn }),
                                        ).await;
                                    });
                                }

                                tracing::info!("Voice join: {} in channel", &public_key[..16.min(public_key.len())]);
                            }
                            Ok(WsClientMessage::VoiceLeave { channel_id }) => {
                                leave_voice(&state, &public_key, &channel_id).await;
                                voice_channel = None;
                                // Publish member.left audit event.
                                {
                                    let state_c = state.clone();
                                    let pk = public_key.clone();
                                    let ch = channel_id.clone();
                                    tokio::spawn(async move {
                                        crate::bots::events::publish_hub_event(
                                            &state_c,
                                            "member.left",
                                            Some(&pk),
                                            None,
                                            Some(&ch),
                                            serde_json::json!({}),
                                        ).await;
                                    });
                                }
                                tracing::info!("Voice leave: {}", &public_key[..16.min(public_key.len())]);
                            }
                            Ok(WsClientMessage::VoiceSpeaking { channel_id, speaking }) => {
                                let _ = state.voice_event_tx.send((
                                    channel_id.clone(),
                                    WsServerMessage::VoiceParticipantSpeaking {
                                        channel_id,
                                        public_key: public_key.clone(),
                                        speaking,
                                    },
                                ));
                            }
                            Ok(WsClientMessage::Typing { channel_id, typing }) => {
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();
                                let ev = crate::routes::chat_models::ChatEvent::Typing {
                                    channel_id: channel_id.clone(),
                                    public_key: public_key.clone(),
                                    display_name: display_name.clone(),
                                    typing,
                                };
                                let ws_msg = WsServerMessage::Typing {
                                    channel_id,
                                    public_key: public_key.clone(),
                                    display_name,
                                    typing,
                                };
                                let json: std::sync::Arc<str> = std::sync::Arc::from(
                                    serde_json::to_string(&ws_msg).unwrap().as_str(),
                                );
                                let _ = state.chat_tx.send((ev, json));
                            }
                            Ok(WsClientMessage::DmTyping { conversation_id, typing }) => {
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();
                                let _ = state.dm_tx.send(crate::state::DmEvent::Typing {
                                    conversation_id,
                                    sender: public_key.clone(),
                                    sender_name: display_name,
                                    typing,
                                });
                            }

                            Ok(WsClientMessage::ScreenShareStart { channel_id, stream_id, kind, mime, has_audio }) => {
                                {
                                    let shares = state.screen_shares.read().await;
                                    if let Some(active) = shares.get(&channel_id) {
                                        let other_sharer = active.streams.values()
                                            .any(|m| m.sharer_pubkey != public_key);
                                        if other_sharer {
                                            let err = WsServerMessage::Error {
                                                context: "screen_share".to_string(),
                                                message: "Someone else is already sharing in this channel.".to_string(),
                                            };
                                            let _ = ws_tx
                                                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                                .await;
                                            continue;
                                        }
                                    }
                                }
                                {
                                    let mut shares = state.screen_shares.write().await;
                                    let active = shares.entry(channel_id.clone()).or_insert_with(|| ActiveShare {
                                        streams: std::collections::HashMap::new(),
                                    });
                                    active.streams.insert(stream_id.clone(), crate::state::ScreenStreamMeta {
                                        kind: kind.clone(),
                                        mime: mime.clone(),
                                        has_audio,
                                        sharer_pubkey: public_key.clone(),
                                        init_chunk: None,
                                        started_at: std::time::Instant::now(),
                                    });
                                }
                                {
                                    let ev = crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: public_key.clone(),
                                        kind: kind.clone(),
                                        mime: mime.clone(),
                                        has_audio,
                                    };
                                    let ws_msg = WsServerMessage::ScreenShareStarted {
                                        channel_id,
                                        stream_id,
                                        sharer_pubkey: public_key.clone(),
                                        kind,
                                        mime,
                                        has_audio,
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&ws_msg).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                            }

                            Ok(WsClientMessage::ScreenShareChunk { channel_id, stream_id, seq, is_init }) => {
                                pending_chunk = Some((channel_id, stream_id, seq, is_init));
                            }

                            Ok(WsClientMessage::ScreenShareStop { channel_id, stream_id }) => {
                                {
                                    let mut shares = state.screen_shares.write().await;
                                    if let Some(active) = shares.get_mut(&channel_id) {
                                        active.streams.remove(&stream_id);
                                        if active.streams.is_empty() {
                                            shares.remove(&channel_id);
                                        }
                                    }
                                }
                                {
                                    let ev = crate::routes::chat_models::ChatEvent::ScreenShareStopped {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: public_key.clone(),
                                    };
                                    let ws_msg = WsServerMessage::ScreenShareStopped {
                                        channel_id,
                                        stream_id,
                                        sharer_pubkey: public_key.clone(),
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&ws_msg).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                            }

                            Ok(WsClientMessage::Resume { since_seq }) => {
                                // Only bots can resume (they're the only consumers of hub_event).
                                if !is_bot {
                                    continue;
                                }

                                is_replaying = true;
                                let _ = is_replaying; // suppress lint: read across tokio::select! arms

                                let live_seq = crate::bots::events::current_seq(&state).await;

                                // Clone the bot_tx so replay_events_for_bot can push directly.
                                let replay_tx = bot_tx.clone();
                                let result = crate::bots::events::replay_events_for_bot(
                                    &state,
                                    &public_key,
                                    since_seq,
                                    &replay_tx,
                                ).await;

                                is_replaying = false;

                                match result {
                                    crate::bots::events::ReplayResult::Unavailable {
                                        earliest_seq,
                                        earliest_at,
                                    } => {
                                        let msg = serde_json::json!({
                                            "type": "replay_unavailable",
                                            "earliest_seq": earliest_seq,
                                            "earliest_at": earliest_at,
                                        });
                                        if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                    crate::bots::events::ReplayResult::Complete { replayed } => {
                                        let msg = serde_json::json!({
                                            "type": "replay_complete",
                                            "replayed": replayed,
                                            "live_from_seq": live_seq,
                                        });
                                        if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }

                                // Flush buffered live events that arrived during replay.
                                for buffered in replay_buffer.drain(..) {
                                    if ws_tx.send(Message::Text(buffered.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }

                            Ok(WsClientMessage::ComponentInteraction {
                                message_id,
                                custom_id,
                                values,
                            }) => {
                                // Rate-limit: 1 interaction per (user, custom_id) per 3 seconds.
                                let rl_key = (public_key.clone(), custom_id.clone());
                                let now_inst = Instant::now();
                                if let Some(last) = component_rate_limit.get(&rl_key) {
                                    if now_inst.duration_since(*last) < Duration::from_secs(3) {
                                        let err = WsServerMessage::Error {
                                            context: "component_interaction".to_string(),
                                            message: "Please wait before interacting again.".to_string(),
                                        };
                                        let _ = ws_tx
                                            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                            .await;
                                        continue;
                                    }
                                }
                                component_rate_limit.insert(rl_key, now_inst);
                                // Opportunistic cleanup so the map doesn't grow forever.
                                if component_rate_limit.len() > 500 {
                                    component_rate_limit.retain(|_, t| now_inst.duration_since(*t) < Duration::from_secs(60));
                                }

                                let state_c = state.clone();
                                let pk = public_key.clone();
                                tokio::spawn(async move {
                                    crate::bots::dispatch::dispatch_component(
                                        &state_c,
                                        &message_id,
                                        &custom_id,
                                        &values,
                                        &pk,
                                    ).await;
                                });
                            }

                            Err(_) => {}
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if let Some((ch_id, st_id, seq, is_init)) = pending_chunk.take() {
                            let chunk_bytes = bytes::Bytes::from(data.to_vec());
                            if is_init {
                                let mut shares = state.screen_shares.write().await;
                                if let Some(active) = shares.get_mut(&ch_id) {
                                    if let Some(meta) = active.streams.get_mut(&st_id) {
                                        meta.init_chunk = Some(chunk_bytes.clone());
                                    }
                                }
                            }
                            let _ = state.screen_share_tx.send(ScreenChunkEvent {
                                channel_id: ch_id,
                                stream_id: st_id,
                                sharer_pubkey: public_key.clone(),
                                seq,
                                is_init,
                                data: chunk_bytes,
                            });
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            voice_result = voice_rx.recv() => {
                if let Ok((channel_id, msg)) = voice_result {
                    if voice_channel.as_deref() == Some(channel_id.as_str()) {
                        let is_self = match &msg {
                            WsServerMessage::VoiceParticipantSpeaking { public_key: pk, .. } => pk == &public_key,
                            WsServerMessage::VoiceParticipantJoined { participant, .. } => participant.public_key == public_key,
                            WsServerMessage::VoiceParticipantLeft { public_key: pk, .. } => pk == &public_key,
                            _ => false,
                        };
                        if !is_self {
                            let json = serde_json::to_string(&msg).unwrap();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }

            dm_result = dm_rx.recv() => {
                if let Ok(dm) = dm_result {
                    if dm.sender() == public_key
                        || !my_conversations.contains(dm.conversation_id())
                    {
                        continue;
                    }
                    let msg = match dm {
                        crate::state::DmEvent::Message { conversation_id, sender, sender_name, content, timestamp } => {
                            WsServerMessage::DirectMessage {
                                conversation_id, sender, sender_name, content, timestamp,
                            }
                        }
                        crate::state::DmEvent::Typing { conversation_id, sender, sender_name, typing } => {
                            WsServerMessage::DmTyping {
                                conversation_id, sender, sender_name, typing,
                            }
                        }
                    };
                    let json = serde_json::to_string(&msg).unwrap();
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            chunk_result = screen_share_rx.recv() => {
                match chunk_result {
                    Ok(ev) => {
                        if ev.sharer_pubkey != public_key
                            && subscribed.contains(&ev.channel_id)
                        {
                            let envelope = WsServerMessage::ScreenShareChunkOut {
                                channel_id: ev.channel_id,
                                stream_id: ev.stream_id,
                                sharer_pubkey: ev.sharer_pubkey,
                                seq: ev.seq,
                                is_init: ev.is_init,
                            };
                            let json = serde_json::to_string(&envelope).unwrap();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                            if ws_tx.send(Message::Binary(ev.data.to_vec().into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Screen-share client lagged, missed {n} chunks");
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // Clean up on disconnect.
    if let Some(ch_id) = voice_channel {
        leave_voice(&state, &public_key, &ch_id).await;
    }
    {
        let mut shares = state.screen_shares.write().await;
        for active in shares.values_mut() {
            active.streams.retain(|_, meta| meta.sharer_pubkey != public_key);
        }
        shares.retain(|_, active| !active.streams.is_empty());
    }
    if is_bot {
        state.bot_sessions.write().await.remove(&public_key);
    }
    state.online_users.write().await.remove(&public_key);

    tracing::info!("WebSocket disconnected: {}", &public_key[..16.min(public_key.len())]);
}

async fn leave_voice(state: &AppState, public_key: &str, channel_id: &str) {
    let removed_addr = {
        let mut channels = state.voice_channels.write().await;
        let addr = channels
            .get_mut(channel_id)
            .and_then(|participants| participants.remove(public_key));
        if let Some(participants) = channels.get(channel_id) {
            if participants.is_empty() {
                channels.remove(channel_id);
            }
        }
        addr
    };
    if let Some(addr) = removed_addr {
        state.voice_addr_map.write().await.remove(&addr);
    }

    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceParticipantLeft {
            channel_id: channel_id.to_string(),
            public_key: public_key.to_string(),
        },
    ));
}

async fn get_voice_participants(state: &AppState, channel_id: &str) -> Vec<VoiceParticipantInfo> {
    let channels = state.voice_channels.read().await;
    let Some(participants) = channels.get(channel_id) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for (pk, _addr) in participants {
        let display_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(pk)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        result.push(VoiceParticipantInfo {
            public_key: pk.clone(),
            display_name,
        });
    }
    result
}
