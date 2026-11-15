use core::time::Duration;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use falkon_core::crypto::{
    IdentityKeypair, RoomSecret, derive_room_psk, peer_id_from_pubkey, random_bytes,
};
use falkon_core::error::FalkonError;
use falkon_core::protocol::{
    ChatPayload, HistoryRetention, PeerId, PeerSummary, WireEnvelope, WireMessage,
};
use falkon_core::room::MAX_ACTIVE_HISTORY_MESSAGES;
use falkon_core::sanitize::{sanitize_message, sanitize_nick};
use falkon_core::security::{DEFAULT_REPLAY_WINDOW, ReplayGuard};

use crate::framing::IDLE_READ_TIMEOUT;
use crate::noise_channel::EncryptedChannel;
use crate::session::recv_room_salt;
use crate::transport::PeerTransport;

pub struct PeerConfig {
    pub connect_addr: String,
    pub nick: String,
    pub identity: IdentityKeypair,
    pub secret: RoomSecret,
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Status(String),
    Admitted {
        host_fingerprint: String,
        retention: HistoryRetention,
        history_shared: bool,
    },
    VoteRequested {
        candidate_id: PeerId,
        nick: String,
        fingerprint: String,
    },
    HistorySynced(Vec<ChatPayload>),
    ChatReceived(ChatPayload),
    PeersUpdated(Vec<PeerSummary>),
    Disconnected(String),
}

#[derive(Debug, Clone)]
pub enum PeerCommand {
    SendChat(String),
    CastVote {
        candidate_id: PeerId,
        allow_entry: bool,
        share_history: bool,
    },
    UpdateNick(String),
    Disconnect,
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run_peer<T: PeerTransport>(
    transport: Arc<T>,
    config: PeerConfig,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    event_tx: mpsc::Sender<PeerEvent>,
) -> Result<(), FalkonError> {
    let _ = event_tx
        .send(PeerEvent::Status(format!(
            "Conectando a {}...",
            config.connect_addr
        )))
        .await;

    let mut stream = transport.connect(&config.connect_addr).await?;
    let room_salt = recv_room_salt(&mut stream).await?;
    let psk = derive_room_psk(&config.secret, &room_salt)?;

    drop(config.secret);

    let channel = EncryptedChannel::connect_initiator(stream, &config.identity, &psk).await?;
    let host_fp = channel.remote_fingerprint().to_owned();
    let (mut sender, mut receiver) = channel.into_split();

    let mut my_nick = config.nick;
    let my_id = peer_id_from_pubkey(config.identity.public_key());
    let mut replay_guard = ReplayGuard::new(DEFAULT_REPLAY_WINDOW);

    sender
        .send_envelope(&WireEnvelope::new(WireMessage::JoinRequest {
            nick: my_nick.clone(),
        }))
        .await?;

    let _ = event_tx
        .send(PeerEvent::Status(format!(
            "Handshake OK (Host FP: {host_fp}). Aguardando votacao da sala..."
        )))
        .await;

    let decision_env = receiver.recv_envelope(Duration::from_secs(35)).await?;
    match decision_env.message {
        WireMessage::JoinDecision {
            accepted: true,
            history_shared,
            retention,
            ..
        } => {
            let _ = event_tx
                .send(PeerEvent::Admitted {
                    host_fingerprint: host_fp,
                    retention,
                    history_shared,
                })
                .await;
        }
        WireMessage::JoinDecision {
            accepted: false,
            reason,
            ..
        } => {
            let msg = reason.unwrap_or_else(|| "entrada negada".to_owned());
            let _ = event_tx.send(PeerEvent::Disconnected(msg)).await;
            return Err(FalkonError::InvalidState("entrada recusada"));
        }
        _ => {
            let _ = event_tx
                .send(PeerEvent::Disconnected(
                    "resposta inesperada no lobby".to_owned(),
                ))
                .await;
            return Err(FalkonError::InvalidState("protocolo invalido no lobby"));
        }
    }

    let (net_tx, mut net_rx) = mpsc::channel::<WireEnvelope>(64);
    let read_task = tokio::spawn(async move {
        while let Ok(env) = receiver.recv_envelope(IDLE_READ_TIMEOUT).await {
            if net_tx.send(env).await.is_err() {
                break;
            }
        }
    });

    let mut ping_tick = tokio::time::interval(Duration::from_secs(20));

    loop {
        tokio::select! {
            _ = ping_tick.tick() => {
                let res = sender
                    .send_envelope(&WireEnvelope::new(WireMessage::Ping { nonce: unix_secs_now() }))
                    .await;
                if res.is_err() {
                    let _ = event_tx.send(PeerEvent::Disconnected("conexao perdida".to_owned())).await;
                    break;
                }
            }

            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                match cmd {
                    PeerCommand::SendChat(raw) => {
                        if let Ok(body) = sanitize_message(&raw)
                            && let Ok(msg_id) = random_bytes::<16>()
                        {
                            let _ = replay_guard.check_and_insert(msg_id);
                            let payload = ChatPayload {
                                msg_id,
                                sender_id: my_id,
                                sender_nick: my_nick.clone(),
                                body,
                                sent_unix_secs: unix_secs_now(),
                            };
                            let env = WireEnvelope::new(WireMessage::Chat(payload.clone()));
                            if sender.send_envelope(&env).await.is_err() {
                                let _ = event_tx.send(PeerEvent::Disconnected("falha ao enviar".to_owned())).await;
                                break;
                            }
                            let _ = event_tx.send(PeerEvent::ChatReceived(payload)).await;
                        }
                    }
                    PeerCommand::CastVote { candidate_id, allow_entry, share_history } => {
                        let env = WireEnvelope::new(WireMessage::VoteResponse {
                            candidate_id,
                            allow_entry,
                            share_history,
                        });
                        if sender.send_envelope(&env).await.is_err() {
                            break;
                        }
                    }
                    PeerCommand::UpdateNick(raw_nick) => {
                        if let Ok(clean) = sanitize_nick(&raw_nick) {
                            my_nick = clean.clone();
                            let env = WireEnvelope::new(WireMessage::NickUpdate { new_nick: clean });
                            if sender.send_envelope(&env).await.is_err() {
                                break;
                            }
                        }
                    }
                    PeerCommand::Disconnect => break,
                }
            }

            maybe_env = net_rx.recv() => {
                let Some(env) = maybe_env else {
                    let _ = event_tx.send(PeerEvent::Disconnected("Host encerrou a sala.".to_owned())).await;
                    break;
                };
                match env.message {
                    WireMessage::Chat(mut payload) => {
                        if !replay_guard.check_and_insert(payload.msg_id) {
                            continue;
                        }
                        if let Ok(clean) = sanitize_message(&payload.body) {
                            payload.body = clean;
                            if let Ok(clean_nick) = sanitize_nick(&payload.sender_nick) {
                                payload.sender_nick = clean_nick;
                            }
                            let _ = event_tx.send(PeerEvent::ChatReceived(payload)).await;
                        }
                    }
                    WireMessage::HistorySync { messages } => {
                        let mut sanitized = Vec::with_capacity(
                            messages.len().min(MAX_ACTIVE_HISTORY_MESSAGES),
                        );
                        for mut m in messages.into_iter().take(MAX_ACTIVE_HISTORY_MESSAGES) {
                            if !replay_guard.check_and_insert(m.msg_id) {
                                continue;
                            }
                            if let Ok(clean) = sanitize_message(&m.body) {
                                m.body = clean;
                                if let Ok(clean_nick) = sanitize_nick(&m.sender_nick) {
                                    m.sender_nick = clean_nick;
                                }
                                sanitized.push(m);
                            }
                        }
                        let _ = event_tx.send(PeerEvent::HistorySynced(sanitized)).await;
                    }
                    WireMessage::VoteRequest { candidate_id, nick, fingerprint } => {
                        let clean_nick = sanitize_nick(&nick).unwrap_or_else(|_| "Candidato".to_owned());
                        let _ = event_tx.send(PeerEvent::VoteRequested {
                            candidate_id,
                            nick: clean_nick,
                            fingerprint,
                        }).await;
                    }
                    WireMessage::PeerList { peers } => {
                        let _ = event_tx.send(PeerEvent::PeersUpdated(peers)).await;
                    }
                    WireMessage::Ping { nonce } => {
                        let res = sender
                            .send_envelope(&WireEnvelope::new(WireMessage::Pong { nonce }))
                            .await;
                        if res.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    read_task.abort();
    Ok(())
}
