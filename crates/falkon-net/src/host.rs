use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use falkon_core::crypto::{IdentityKeypair, random_bytes};
use falkon_core::error::FalkonError;
use falkon_core::protocol::{
    ChatPayload, HistoryRetention, PeerId, PeerSummary, WireEnvelope, WireMessage,
};
use falkon_core::room::{AdmissionVote, EphemeralHistory, MAX_PENDING_CANDIDATES, VoteProgress};
use falkon_core::sanitize::{sanitize_message, sanitize_nick};

use crate::framing::IDLE_READ_TIMEOUT;
use crate::noise_channel::EncryptedChannel;
use crate::session::send_room_salt;
use crate::transport::{BoxedStream, PeerEndpoint, PeerTransport};

pub const MAX_ACTIVE_PEERS: usize = 16;
const PEER_OUTBOX_CAP: usize = 64;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

pub struct HostConfig {
    pub listen_addr: String,
    pub nick: String,
    pub retention: HistoryRetention,
    pub identity: IdentityKeypair,
    pub psk: Zeroizing<[u8; 32]>,
    pub room_salt: [u8; 16],
}

#[derive(Debug, Clone)]
pub enum HostEvent {
    Listening(String),
    SystemNotice(String),
    CandidateWaiting {
        candidate_id: PeerId,
        nick: String,
        fingerprint: String,
    },
    VoteResolved {
        candidate_id: PeerId,
        nick: String,
        accepted: bool,
        history_shared: bool,
    },
    ChatReceived(ChatPayload),
    PeersUpdated(Vec<PeerSummary>),
    HistoryPurged {
        removed: usize,
        remaining: usize,
    },
}

#[derive(Debug, Clone)]
pub enum HostCommand {
    SendChat(String),
    CastVote {
        candidate_id: PeerId,
        allow_entry: bool,
        share_history: bool,
    },
    UpdateNick(String),
    WipeAll,
    Shutdown,
}

enum InternalEvent {
    Incoming {
        stream: BoxedStream,
    },
    CandidateJoinedLobby {
        candidate_id: PeerId,
        nick: String,
        fingerprint: String,
        out_tx: mpsc::Sender<WireEnvelope>,
    },
    PeerEnvelope {
        peer_id: PeerId,
        envelope: WireEnvelope,
    },
    PeerDisconnected(PeerId),
}

struct ActivePeer {
    nick: String,
    fingerprint: String,
    out_tx: mpsc::Sender<WireEnvelope>,
}

struct PendingPeer {
    vote: AdmissionVote,
    out_tx: mpsc::Sender<WireEnvelope>,
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run_host<T: PeerTransport + 'static>(
    transport: Arc<T>,
    config: HostConfig,
    mut cmd_rx: mpsc::Receiver<HostCommand>,
    event_tx: mpsc::Sender<HostEvent>,
) -> Result<(), FalkonError> {
    let listener = transport.bind(&config.listen_addr).await?;
    let endpoint = listener.local_endpoint()?;
    let display_endpoint = match endpoint {
        PeerEndpoint::DirectTcp(addr) => addr.to_string(),
        PeerEndpoint::OnionV3(onion) => onion,
    };
    let _ = event_tx.send(HostEvent::Listening(display_endpoint)).await;

    let host_id = random_bytes::<16>()?;
    let mut host_nick = config.nick;
    let host_fp = config.identity.fingerprint();
    let host_identity = Arc::new(config.identity);
    let psk = Arc::new(config.psk);

    let (int_tx, mut int_rx) = mpsc::channel::<InternalEvent>(128);

    // Task dedicada ao accept() TCP (handshake Noise ocorre fora dela!)
    let accept_tx = int_tx.clone();
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _ep)) = listener.accept().await {
            if accept_tx
                .send(InternalEvent::Incoming { stream })
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut history = EphemeralHistory::new(config.retention);
    let mut active_peers: HashMap<PeerId, ActivePeer> = HashMap::new();
    let mut pending_peers: HashMap<PeerId, PendingPeer> = HashMap::new();

    let mut tick_1s = tokio::time::interval(Duration::from_secs(1));
    let mut ping_tick = tokio::time::interval(KEEPALIVE_INTERVAL);

    let initial_list = build_peer_list(host_id, &host_nick, &host_fp, &active_peers);
    let _ = event_tx.send(HostEvent::PeersUpdated(initial_list)).await;

    loop {
        tokio::select! {
            _ = tick_1s.tick() => {
                let now = Instant::now();
                let removed = history.purge_expired(now);
                if removed > 0 {
                    let _ = event_tx.send(HostEvent::HistoryPurged {
                        removed,
                        remaining: history.len(),
                    }).await;
                }

                let expired_ids: Vec<PeerId> = pending_peers
                    .iter()
                    .filter(|(_, p)| p.vote.is_expired(now))
                    .map(|(id, _)| *id)
                    .collect();

                for cid in expired_ids {
                    if let Some(pending) = pending_peers.remove(&cid) {
                        let _ = pending.out_tx.try_send(WireEnvelope::new(WireMessage::JoinDecision {
                            accepted: false,
                            history_shared: false,
                            retention: history.retention(),
                            reason: Some("votacao expirou".to_owned()),
                        }));
                        let _ = event_tx.send(HostEvent::VoteResolved {
                            candidate_id: cid,
                            nick: pending.vote.nick,
                            accepted: false,
                            history_shared: false,
                        }).await;
                    }
                }
            }

            _ = ping_tick.tick() => {
                let ping = WireEnvelope::new(WireMessage::Ping { nonce: unix_secs_now() });
                for peer in active_peers.values() {
                    let _ = peer.out_tx.try_send(ping.clone());
                }
            }

            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                match cmd {
                    HostCommand::SendChat(raw_text) => {
                        if let Ok(clean_body) = sanitize_message(&raw_text)
                            && let Ok(msg_id) = random_bytes::<16>()
                        {
                            let payload = ChatPayload {
                                msg_id,
                                sender_id: host_id,
                                sender_nick: host_nick.clone(),
                                body: clean_body,
                                sent_unix_secs: unix_secs_now(),
                            };
                            history.push(payload.clone(), Instant::now());
                            let env = WireEnvelope::new(WireMessage::Chat(payload.clone()));
                            broadcast_to_peers(&active_peers, &env, None);
                            let _ = event_tx.send(HostEvent::ChatReceived(payload)).await;
                        }
                    }
                    HostCommand::CastVote { candidate_id, allow_entry, share_history } => {
                        resolve_vote(
                            candidate_id,
                            host_id,
                            allow_entry,
                            share_history,
                            &mut pending_peers,
                            &mut active_peers,
                            &mut history,
                            host_id,
                            &host_nick,
                            &host_fp,
                            &event_tx,
                        ).await;
                    }
                    HostCommand::UpdateNick(raw_nick) => {
                        if let Ok(clean) = sanitize_nick(&raw_nick) {
                            host_nick = clean;
                            let list = build_peer_list(host_id, &host_nick, &host_fp, &active_peers);
                            let env = WireEnvelope::new(WireMessage::PeerList { peers: list.clone() });
                            broadcast_to_peers(&active_peers, &env, None);
                            let _ = event_tx.send(HostEvent::PeersUpdated(list)).await;
                        }
                    }
                    HostCommand::WipeAll => {
                        history.clear_all();
                        let _ = event_tx.send(HostEvent::SystemNotice(
                            "Historico ativo zerado na RAM. Encerrando sala.".to_owned()
                        )).await;
                        break;
                    }
                    HostCommand::Shutdown => {
                        history.clear_all();
                        break;
                    }
                }
            }

            maybe_int = int_rx.recv() => {
                let Some(ev) = maybe_int else {
                    break;
                };
                match ev {
                    InternalEvent::Incoming { mut stream } => {
                        if active_peers.len() >= MAX_ACTIVE_PEERS || pending_peers.len() >= MAX_PENDING_CANDIDATES {
                            let _ = event_tx.send(HostEvent::SystemNotice(
                                "Conexao recusada: limite de sala ou lobby atingido.".to_owned()
                            )).await;
                            continue;
                        }

                        let id_clone = Arc::clone(&host_identity);
                        let psk_clone = Arc::clone(&psk);
                        let tx_clone = int_tx.clone();
                        let room_salt = config.room_salt;

                        tokio::spawn(async move {
                            if send_room_salt(&mut stream, &room_salt).await.is_err() {
                                return;
                            }
                            let Ok(channel) = EncryptedChannel::accept_responder(stream, &id_clone, &psk_clone).await else {
                                return;
                            };

                            let (mut sender, mut receiver) = channel.into_split();
                            let fingerprint = receiver.remote_fingerprint().to_owned();

                            let Ok(first_env) = receiver.recv_envelope(Duration::from_secs(15)).await else {
                                return;
                            };
                            let WireMessage::JoinRequest { nick } = first_env.message else {
                                return;
                            };
                            let Ok(clean_nick) = sanitize_nick(&nick) else {
                                return;
                            };
                            let Ok(candidate_id) = random_bytes::<16>() else {
                                return;
                            };

                            let (out_tx, mut out_rx) = mpsc::channel::<WireEnvelope>(PEER_OUTBOX_CAP);

                            if tx_clone.send(InternalEvent::CandidateJoinedLobby {
                                candidate_id,
                                nick: clean_nick,
                                fingerprint,
                                out_tx,
                            }).await.is_err() {
                                return;
                            }

                            let writer_task = tokio::spawn(async move {
                                while let Some(env) = out_rx.recv().await {
                                    if sender.send_envelope(&env).await.is_err() {
                                        break;
                                    }
                                }
                            });

                            while let Ok(env) = receiver.recv_envelope(IDLE_READ_TIMEOUT).await {
                                if tx_clone.send(InternalEvent::PeerEnvelope {
                                    peer_id: candidate_id,
                                    envelope: env,
                                }).await.is_err() {
                                    break;
                                }
                            }

                            writer_task.abort();
                            let _ = tx_clone.send(InternalEvent::PeerDisconnected(candidate_id)).await;
                        });
                    }

                    InternalEvent::CandidateJoinedLobby { candidate_id, nick, fingerprint, out_tx } => {
                        if pending_peers.len() >= MAX_PENDING_CANDIDATES {
                            let _ = out_tx.try_send(WireEnvelope::new(WireMessage::JoinDecision {
                                accepted: false,
                                history_shared: false,
                                retention: history.retention(),
                                reason: Some("lobby cheio".to_owned()),
                            }));
                            continue;
                        }

                        let mut voters = HashSet::new();
                        voters.insert(host_id);
                        for pid in active_peers.keys() {
                            voters.insert(*pid);
                        }

                        if let Ok(vote) = AdmissionVote::new(
                            candidate_id,
                            nick.clone(),
                            fingerprint.clone(),
                            voters,
                            Instant::now(),
                        ) {
                            let vote_req = WireEnvelope::new(WireMessage::VoteRequest {
                                candidate_id,
                                nick: nick.clone(),
                                fingerprint: fingerprint.clone(),
                            });
                            broadcast_to_peers(&active_peers, &vote_req, None);
                            pending_peers.insert(candidate_id, PendingPeer { vote, out_tx });

                            let _ = event_tx.send(HostEvent::CandidateWaiting {
                                candidate_id,
                                nick,
                                fingerprint,
                            }).await;
                        }
                    }

                    InternalEvent::PeerEnvelope { peer_id, envelope } => {
                        if !active_peers.contains_key(&peer_id) {
                            continue;
                        }
                        match envelope.message {
                            WireMessage::Chat(mut payload) => {
                                if let Ok(clean_body) = sanitize_message(&payload.body)
                                    && let Some(sender_info) = active_peers.get(&peer_id)
                                {
                                    payload.sender_id = peer_id;
                                    payload.sender_nick = sender_info.nick.clone();
                                    payload.body = clean_body;
                                    history.push(payload.clone(), Instant::now());
                                    let relay = WireEnvelope::new(WireMessage::Chat(payload.clone()));
                                    broadcast_to_peers(&active_peers, &relay, Some(peer_id));
                                    let _ = event_tx.send(HostEvent::ChatReceived(payload)).await;
                                }
                            }
                            WireMessage::VoteResponse { candidate_id, allow_entry, share_history } => {
                                resolve_vote(
                                    candidate_id,
                                    peer_id,
                                    allow_entry,
                                    share_history,
                                    &mut pending_peers,
                                    &mut active_peers,
                                    &mut history,
                                    host_id,
                                    &host_nick,
                                    &host_fp,
                                    &event_tx,
                                ).await;
                            }
                            WireMessage::NickUpdate { new_nick } => {
                                if let Ok(clean) = sanitize_nick(&new_nick)
                                    && let Some(peer) = active_peers.get_mut(&peer_id)
                                {
                                    peer.nick = clean;
                                    let list = build_peer_list(host_id, &host_nick, &host_fp, &active_peers);
                                    let env = WireEnvelope::new(WireMessage::PeerList { peers: list.clone() });
                                    broadcast_to_peers(&active_peers, &env, None);
                                    let _ = event_tx.send(HostEvent::PeersUpdated(list)).await;
                                }
                            }
                            WireMessage::Ping { nonce } => {
                                if let Some(peer) = active_peers.get(&peer_id) {
                                    let _ = peer.out_tx.try_send(WireEnvelope::new(WireMessage::Pong { nonce }));
                                }
                            }
                            _ => {}
                        }
                    }

                    InternalEvent::PeerDisconnected(peer_id) => {
                        let _ = pending_peers.remove(&peer_id);
                        if let Some(removed) = active_peers.remove(&peer_id) {
                            let _ = event_tx.send(HostEvent::SystemNotice(
                                format!("{} saiu da sala.", removed.nick)
                            )).await;
                            let list = build_peer_list(host_id, &host_nick, &host_fp, &active_peers);
                            let env = WireEnvelope::new(WireMessage::PeerList { peers: list.clone() });
                            broadcast_to_peers(&active_peers, &env, None);
                            let _ = event_tx.send(HostEvent::PeersUpdated(list)).await;
                        }
                    }
                }
            }
        }
    }

    accept_task.abort();
    history.clear_all();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn resolve_vote(
    candidate_id: PeerId,
    voter_id: PeerId,
    allow_entry: bool,
    share_history: bool,
    pending_peers: &mut HashMap<PeerId, PendingPeer>,
    active_peers: &mut HashMap<PeerId, ActivePeer>,
    history: &mut EphemeralHistory,
    host_id: PeerId,
    host_nick: &str,
    host_fp: &str,
    event_tx: &mpsc::Sender<HostEvent>,
) {
    let now = Instant::now();
    let progress = {
        let Some(pending) = pending_peers.get_mut(&candidate_id) else {
            return;
        };
        match pending
            .vote
            .cast_vote(voter_id, allow_entry, share_history, now)
        {
            Ok(p) => p,
            Err(_) => return,
        }
    };

    match progress {
        VoteProgress::Pending => {}
        VoteProgress::TimedOut => {
            if let Some(pending) = pending_peers.remove(&candidate_id) {
                let _ = pending
                    .out_tx
                    .try_send(WireEnvelope::new(WireMessage::JoinDecision {
                        accepted: false,
                        history_shared: false,
                        retention: history.retention(),
                        reason: Some("tempo de votacao esgotado".to_owned()),
                    }));
                let _ = event_tx
                    .send(HostEvent::VoteResolved {
                        candidate_id,
                        nick: pending.vote.nick,
                        accepted: false,
                        history_shared: false,
                    })
                    .await;
            }
        }
        VoteProgress::Decided(outcome) => {
            let Some(pending) = pending_peers.remove(&candidate_id) else {
                return;
            };
            let candidate_nick = pending.vote.nick;
            let candidate_fp = pending.vote.fingerprint;

            if !outcome.allow_entry {
                let _ = pending
                    .out_tx
                    .try_send(WireEnvelope::new(WireMessage::JoinDecision {
                        accepted: false,
                        history_shared: false,
                        retention: history.retention(),
                        reason: Some("entrada recusada pela sala".to_owned()),
                    }));
                let _ = event_tx
                    .send(HostEvent::VoteResolved {
                        candidate_id,
                        nick: candidate_nick,
                        accepted: false,
                        history_shared: false,
                    })
                    .await;
                return;
            }

            let _ = pending
                .out_tx
                .try_send(WireEnvelope::new(WireMessage::JoinDecision {
                    accepted: true,
                    history_shared: outcome.share_history,
                    retention: history.retention(),
                    reason: None,
                }));

            if outcome.share_history {
                let snapshot = history.snapshot(now);
                if !snapshot.is_empty() {
                    let _ = pending
                        .out_tx
                        .try_send(WireEnvelope::new(WireMessage::HistorySync {
                            messages: snapshot,
                        }));
                }
            }

            active_peers.insert(
                candidate_id,
                ActivePeer {
                    nick: candidate_nick.clone(),
                    fingerprint: candidate_fp,
                    out_tx: pending.out_tx,
                },
            );

            let list = build_peer_list(host_id, host_nick, host_fp, active_peers);
            let env = WireEnvelope::new(WireMessage::PeerList {
                peers: list.clone(),
            });
            broadcast_to_peers(active_peers, &env, None);

            let _ = event_tx.send(HostEvent::PeersUpdated(list)).await;
            let _ = event_tx
                .send(HostEvent::VoteResolved {
                    candidate_id,
                    nick: candidate_nick,
                    accepted: true,
                    history_shared: outcome.share_history,
                })
                .await;
        }
    }
}

fn build_peer_list(
    host_id: PeerId,
    host_nick: &str,
    host_fp: &str,
    active_peers: &HashMap<PeerId, ActivePeer>,
) -> Vec<PeerSummary> {
    let mut list = Vec::with_capacity(1 + active_peers.len());
    list.push(PeerSummary {
        id: host_id,
        nick: host_nick.to_owned(),
        fingerprint: host_fp.to_owned(),
        is_host: true,
    });
    for (id, info) in active_peers {
        list.push(PeerSummary {
            id: *id,
            nick: info.nick.clone(),
            fingerprint: info.fingerprint.clone(),
            is_host: false,
        });
    }
    list
}

fn broadcast_to_peers(
    active_peers: &HashMap<PeerId, ActivePeer>,
    env: &WireEnvelope,
    exclude: Option<PeerId>,
) {
    for (pid, peer) in active_peers {
        if exclude == Some(*pid) {
            continue;
        }
        let _ = peer.out_tx.try_send(env.clone());
    }
}
