#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod app;
mod setup;
mod ui;

use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::style::Color;
use tokio::sync::mpsc;

use falkon_core::crypto::{IdentityKeypair, derive_room_psk, peer_id_from_pubkey, random_bytes};
use falkon_core::protocol::{ChatPayload, HistoryRetention};
use falkon_core::sanitize::sanitize_nick;
use falkon_net::host::{HostCommand, HostConfig, HostEvent, run_host};
use falkon_net::peer::{PeerCommand, PeerConfig, PeerEvent, run_peer};
use falkon_net::transport::DirectTcpTransport;

use crate::app::{AppState, PendingVotePrompt, help_lines};
use crate::setup::{StartupMode, prompt_room_secret, run_interactive_setup};
use crate::ui::draw_ui;

const EXAMPLES_HELP: &str = "\
EXEMPLOS DE USO:
  1) Abrir menu interativo (recomendado para iniciantes):
       falkon

  2) Mesmo computador (Host + Peer em 2 terminais):
       falkon --nick Clara --listen 127.0.0.1:7777 --retention 15s
       falkon --nick Mateus --connect 127.0.0.1:7777

  3) Rede local / Wi-Fi (Host aceitando conexoes da LAN):
       falkon --nick Clara --listen 0.0.0.0:7777 --retention 60s
       falkon --nick Mateus --connect IP_DO_HOST:7777

  4) Modo Preview local (testar interface sem rede):
       falkon --preview";

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RetentionArg {
    Never,
    #[value(name = "5s")]
    Secs5,
    #[value(name = "15s")]
    Secs15,
    #[value(name = "60s")]
    Secs60,
}

impl From<RetentionArg> for HistoryRetention {
    fn from(arg: RetentionArg) -> Self {
        match arg {
            RetentionArg::Never => Self::Never,
            RetentionArg::Secs5 => Self::Secs5,
            RetentionArg::Secs15 => Self::Secs15,
            RetentionArg::Secs60 => Self::Secs60,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "falkon",
    version,
    about = "Falkon — Chat P2P E2EE 100% Terminal",
    after_help = EXAMPLES_HELP
)]
struct Cli {
    /// Apelido exibido dentro do canal cifrado
    #[arg(long, default_value = "Anonimo")]
    nick: String,

    /// Abre uma sala como Host em IP:PORTA (ex.: 127.0.0.1:7777 ou 0.0.0.0:7777)
    #[arg(long, conflicts_with_all = ["connect", "preview"])]
    listen: Option<String>,

    /// Conecta a uma sala existente em IP:PORTA (ex.: 127.0.0.1:7777)
    #[arg(long, conflicts_with_all = ["listen", "preview"])]
    connect: Option<String>,

    /// Ciclo de limpeza do historico ativo quando atuando como Host
    #[arg(long, value_enum, default_value_t = RetentionArg::Secs15)]
    retention: RetentionArg,

    /// Abre direto o modo Preview offline sem rede
    #[arg(long)]
    preview: bool,
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

enum NetControl {
    Host(mpsc::Sender<HostCommand>),
    Peer(mpsc::Sender<PeerCommand>),
    Preview,
}

fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let _ = rlimit::Resource::CORE.set(0, 0);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    disable_core_dumps();

    let cli = Cli::parse();
    let default_nick = sanitize_nick(&cli.nick)?;
    let default_retention: HistoryRetention = cli.retention.into();

    let startup = match (cli.listen, cli.connect, cli.preview) {
        (Some(listen_addr), None, false) => {
            let Some(secret) = prompt_room_secret(true)? else {
                return Ok(());
            };
            StartupMode::Host {
                listen_addr,
                nick: default_nick,
                retention: default_retention,
                secret,
            }
        }
        (None, Some(connect_addr), false) => {
            let Some(secret) = prompt_room_secret(false)? else {
                return Ok(());
            };
            StartupMode::Peer {
                connect_addr,
                nick: default_nick,
                secret,
            }
        }
        (None, None, true) => StartupMode::Preview {
            nick: default_nick,
            retention: default_retention,
        },
        (None, None, false) => run_interactive_setup(&default_nick, default_retention)?,
        _ => StartupMode::Exit,
    };

    let identity = IdentityKeypair::generate()?;
    let my_fp = identity.fingerprint();
    let my_full_fp = identity.full_fingerprint();
    let my_peer_id = peer_id_from_pubkey(identity.public_key());

    let (nick, retention, net_ctrl, mut host_ev_rx, mut peer_ev_rx, mode_label, retention_known) =
        match startup {
            StartupMode::Exit => return Ok(()),
            StartupMode::Host {
                listen_addr,
                nick,
                retention,
                secret,
            } => {
                let room_salt = random_bytes::<16>()?;
                let psk = derive_room_psk(&secret, &room_salt)?;
                drop(secret);

                let (cmd_tx, cmd_rx) = mpsc::channel(64);
                let (ev_tx, ev_rx) = mpsc::channel(128);
                let transport = Arc::new(DirectTcpTransport);

                let cfg = HostConfig {
                    listen_addr: listen_addr.clone(),
                    nick: nick.clone(),
                    retention,
                    identity,
                    psk,
                    room_salt,
                };
                tokio::spawn(async move {
                    let _ = run_host(transport, cfg, cmd_rx, ev_tx).await;
                });

                (
                    nick,
                    retention,
                    NetControl::Host(cmd_tx),
                    Some(ev_rx),
                    None,
                    format!("HOST ({listen_addr})"),
                    true,
                )
            }
            StartupMode::Peer {
                connect_addr,
                nick,
                secret,
            } => {
                let (cmd_tx, cmd_rx) = mpsc::channel(64);
                let (ev_tx, ev_rx) = mpsc::channel(128);
                let transport = Arc::new(DirectTcpTransport);

                let cfg = PeerConfig {
                    connect_addr: connect_addr.clone(),
                    nick: nick.clone(),
                    identity,
                    secret,
                };
                tokio::spawn(async move {
                    let _ = run_peer(transport, cfg, cmd_rx, ev_tx).await;
                });

                (
                    nick,
                    default_retention,
                    NetControl::Peer(cmd_tx),
                    None,
                    Some(ev_rx),
                    format!("PEER -> {connect_addr}"),
                    false,
                )
            }
            StartupMode::Preview { nick, retention } => (
                nick,
                retention,
                NetControl::Preview,
                None,
                None,
                "PREVIEW LOCAL (sem rede)".to_owned(),
                true,
            ),
        };

    let mut app = AppState {
        my_peer_id,
        nick,
        fingerprint: my_fp,
        full_fingerprint: my_full_fp,
        mode_label,
        retention,
        retention_known,
        status_line: "Canal pronto.".to_owned(),
        disconnected: false,
        messages: VecDeque::new(),
        peers: Vec::new(),
        peer_colors: HashMap::new(),
        pending_votes: VecDeque::new(),
        input: String::new(),
        cursor_char_idx: 0,
        scroll_from_bottom: 0,
        should_quit: false,
    };
    let _ = app.ensure_peer_color(my_peer_id);

    app.push_notice(
        "SISTEMA",
        Color::DarkGray,
        "Interface Helena ativa. Digite /help para ver comandos e atalhos.".to_owned(),
    );

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard;
    let mut ui_tick = tokio::time::interval(Duration::from_millis(30));
    let mut purge_tick = tokio::time::interval(Duration::from_secs(1));

    while !app.should_quit {
        terminal.draw(|frame| draw_ui(frame, &mut app))?;

        tokio::select! {
            _ = ui_tick.tick() => {
                while event::poll(Duration::ZERO)? {
                    if let Event::Key(key) = event::read()?
                        && key.kind == KeyEventKind::Press
                    {
                        handle_key(key.code, &mut app, &net_ctrl).await;
                    }
                }
            }

            _ = purge_tick.tick() => {
                let removed = app.purge_expired_ui(Instant::now());
                if removed > 0 && matches!(net_ctrl, NetControl::Peer(_)) {
                    app.status_line = format!(
                        "Ciclo TTL: {removed} msg(s) zerada(s) da RAM e tela"
                    );
                }
            }

            ev = async {
                match &mut host_ev_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match ev {
                    Some(HostEvent::Listening(addr)) => {
                        app.mode_label = format!("HOST ({addr})");
                        app.status_line = format!("Ouvindo em {addr} (P2P-TCP)");
                        let tip = if let Some(port) = addr.strip_prefix("0.0.0.0:") {
                            format!(
                                "Sala aberta em {addr}. Mesmo PC: falkon --connect 127.0.0.1:{port} | LAN: use IP_DESTA_MAQUINA:{port}"
                            )
                        } else {
                            format!("Sala aberta em {addr}. Contatos conectam com: falkon --connect {addr}")
                        };
                        app.push_notice("HOST", Color::Cyan, tip);
                    }
                    Some(HostEvent::SystemNotice(msg)) => {
                        app.push_notice("SISTEMA", Color::DarkGray, msg);
                    }
                    Some(HostEvent::CandidateWaiting { candidate_id, nick, fingerprint }) => {
                        app.push_notice(
                            "LOBBY",
                            Color::Yellow,
                            format!("'{nick}' (FP: {fingerprint}) pediu entrada. Vote com F1/F2/F3!"),
                        );
                        app.pending_votes.push_back(PendingVotePrompt {
                            candidate_id,
                            nick,
                            fingerprint,
                        });
                    }
                    Some(HostEvent::VoteResolved { nick, accepted, history_shared, .. }) => {
                        let hist_txt = if history_shared { "com historico" } else { "sem historico" };
                        let status = if accepted {
                            format!("aprovado ({hist_txt})")
                        } else {
                            "recusado".to_owned()
                        };
                        app.push_notice("VOTACAO", Color::Yellow, format!("'{nick}' foi {status}."));
                    }
                    Some(HostEvent::ChatReceived(p)) => {
                        app.push_chat(p);
                    }
                    Some(HostEvent::PeersUpdated(list)) => {
                        app.sync_peers(list);
                    }
                    Some(HostEvent::HistoryPurged { removed, remaining }) => {
                        let _ = app.purge_expired_ui(Instant::now());
                        app.status_line = format!(
                            "Ciclo TTL: {removed} msg(s) zerada(s) da RAM e tela | Ativas: {remaining}"
                        );
                    }
                    None => {
                        app.disconnected = true;
                        app.status_line = "Motor Host encerrado.".to_owned();
                    }
                }
            }

            ev = async {
                match &mut peer_ev_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match ev {
                    Some(PeerEvent::Status(s)) => {
                        app.status_line = s.clone();
                        app.push_notice("REDE", Color::Cyan, s);
                    }
                    Some(PeerEvent::Admitted { host_fingerprint, retention, history_shared }) => {
                        app.retention = retention;
                        app.retention_known = true;
                        app.status_line = format!("Conectado ao Host ({host_fingerprint})");
                        let h = if history_shared { "Historico enviado" } else { "Sem historico anterior" };
                        app.push_notice(
                            "SALA",
                            Color::Green,
                            format!("Entrada aprovada! ({h} | Retencao: {})", retention.label()),
                        );
                    }
                    Some(PeerEvent::VoteRequested { candidate_id, nick, fingerprint }) => {
                        app.push_notice(
                            "LOBBY",
                            Color::Yellow,
                            format!("'{nick}' (FP: {fingerprint}) quer entrar. Vote com F1/F2/F3!"),
                        );
                        app.pending_votes.push_back(PendingVotePrompt {
                            candidate_id,
                            nick,
                            fingerprint,
                        });
                    }
                    Some(PeerEvent::HistorySynced(msgs)) => {
                        app.push_notice(
                            "HISTORICO",
                            Color::Cyan,
                            format!("{} mensagem(ns) recente(s):", msgs.len()),
                        );
                        for m in msgs {
                            app.push_chat(m);
                        }
                    }
                    Some(PeerEvent::ChatReceived(p)) => {
                        app.push_chat(p);
                    }
                    Some(PeerEvent::PeersUpdated(list)) => {
                        app.sync_peers(list);
                    }
                    Some(PeerEvent::Disconnected(reason)) => {
                        app.disconnected = true;
                        app.status_line = format!("Desconectado: {reason}");
                        app.push_notice("REDE", Color::Red, format!("Desconectado: {reason}"));
                    }
                    None => {
                        app.disconnected = true;
                        app.status_line = "Conexao encerrada.".to_owned();
                    }
                }
            }
        }
    }

    app.wipe_ram();
    Ok(())
}

async fn handle_key(code: KeyCode, app: &mut AppState, net: &NetControl) {
    match code {
        KeyCode::Esc => {
            send_shutdown(net, false).await;
            app.should_quit = true;
        }
        KeyCode::F(1) => cast_next_vote(app, net, true, true).await,
        KeyCode::F(2) => cast_next_vote(app, net, true, false).await,
        KeyCode::F(3) => cast_next_vote(app, net, false, false).await,
        KeyCode::Left => app.move_left(),
        KeyCode::Right => app.move_right(),
        KeyCode::Home => app.move_home(),
        KeyCode::End => app.move_end(),
        KeyCode::Up => app.scroll_up(1),
        KeyCode::Down => app.scroll_down(1),
        KeyCode::PageUp => app.scroll_up(5),
        KeyCode::PageDown => app.scroll_down(5),
        KeyCode::Backspace => app.backspace(),
        KeyCode::Delete => app.delete_char(),
        KeyCode::Char(c) => app.insert_char(c),
        KeyCode::Enter => {
            let text = app.take_submitted_input();
            if text.is_empty() {
                return;
            }

            if text == "/quit" || text == "/wipe" {
                let wipe = text == "/wipe";
                send_shutdown(net, wipe).await;
                app.should_quit = true;
                return;
            }

            if text == "/clear" {
                app.clear_chat_screen();
                app.push_notice(
                    "SISTEMA",
                    Color::DarkGray,
                    "Tela local limpa e zeroizada.".to_owned(),
                );
                return;
            }

            if text == "/help" {
                for line in help_lines() {
                    app.push_notice("AJUDA", Color::Cyan, line);
                }
                return;
            }

            if text == "/peers" {
                if app.peers.is_empty() {
                    app.push_notice(
                        "PEERS",
                        Color::DarkGray,
                        "Nenhum peer listado (modo Preview).".to_owned(),
                    );
                } else {
                    app.push_notice(
                        "PEERS",
                        Color::Cyan,
                        format!("{} participante(s) ativo(s):", app.peers.len()),
                    );
                    let lines: Vec<String> = app
                        .peers
                        .iter()
                        .map(|p| {
                            let role = if p.is_host { "HOST" } else { "PEER" };
                            format!("  [{role}] {} — FP: {}", p.nick, p.fingerprint)
                        })
                        .collect();
                    for line in lines {
                        app.push_notice("PEERS", Color::Cyan, line);
                    }
                }
                return;
            }

            if text == "/fingerprint" {
                app.push_notice(
                    "IDENTIDADE",
                    Color::Cyan,
                    format!(
                        "Chave 128b: {}\nSHA-256 256b: {}",
                        app.fingerprint, app.full_fingerprint
                    ),
                );
                return;
            }

            if let Some(new_nick) = text.strip_prefix("/nick ") {
                if let Ok(clean) = sanitize_nick(new_nick) {
                    app.nick = clean.clone();
                    match net {
                        NetControl::Host(tx) => {
                            let _ = tx.send(HostCommand::UpdateNick(clean)).await;
                        }
                        NetControl::Peer(tx) => {
                            let _ = tx.send(PeerCommand::UpdateNick(clean)).await;
                        }
                        NetControl::Preview => {}
                    }
                } else {
                    app.push_notice("SISTEMA", Color::Red, "Apelido invalido.".to_owned());
                }
                return;
            }

            match net {
                NetControl::Host(tx) => {
                    let _ = tx.send(HostCommand::SendChat(text)).await;
                }
                NetControl::Peer(tx) => {
                    let _ = tx.send(PeerCommand::SendChat(text)).await;
                }
                NetControl::Preview => {
                    app.push_chat(ChatPayload {
                        msg_id: [0u8; 16],
                        sender_id: app.my_peer_id,
                        sender_nick: app.nick.clone(),
                        body: text,
                        sent_unix_secs: 0,
                    });
                }
            }
        }
        _ => {}
    }
}

async fn cast_next_vote(
    app: &mut AppState,
    net: &NetControl,
    allow_entry: bool,
    share_history: bool,
) {
    let Some(vote) = app.pending_votes.pop_front() else {
        return;
    };
    match net {
        NetControl::Host(tx) => {
            let _ = tx
                .send(HostCommand::CastVote {
                    candidate_id: vote.candidate_id,
                    allow_entry,
                    share_history,
                })
                .await;
        }
        NetControl::Peer(tx) => {
            let _ = tx
                .send(PeerCommand::CastVote {
                    candidate_id: vote.candidate_id,
                    allow_entry,
                    share_history,
                })
                .await;
        }
        NetControl::Preview => {}
    }
}

async fn send_shutdown(net: &NetControl, wipe: bool) {
    match net {
        NetControl::Host(tx) => {
            let cmd = if wipe {
                HostCommand::WipeAll
            } else {
                HostCommand::Shutdown
            };
            let _ = tx.send(cmd).await;
        }
        NetControl::Peer(tx) => {
            let _ = tx.send(PeerCommand::Disconnect).await;
        }
        NetControl::Preview => {}
    }
}
