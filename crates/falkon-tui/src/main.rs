#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use tokio::sync::mpsc;
use zeroize::Zeroize;

use falkon_core::crypto::{IdentityKeypair, RoomSecret, derive_room_psk, random_bytes};
use falkon_core::protocol::{HistoryRetention, PeerId, PeerSummary};
use falkon_core::sanitize::sanitize_nick;
use falkon_net::host::{HostCommand, HostConfig, HostEvent, run_host};
use falkon_net::peer::{PeerCommand, PeerConfig, PeerEvent, run_peer};
use falkon_net::transport::DirectTcpTransport;

const MAX_DISPLAY_LINES: usize = 200;

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
    about = "Falkon — Chat P2P E2EE 100% Terminal"
)]
struct Cli {
    #[arg(long, default_value = "Anonimo")]
    nick: String,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    connect: Option<String>,

    #[arg(long, value_enum, default_value_t = RetentionArg::Secs15)]
    retention: RetentionArg,
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

#[derive(Clone)]
struct PendingVotePrompt {
    candidate_id: PeerId,
    nick: String,
    fingerprint: String,
}

enum NetControl {
    Host(mpsc::Sender<HostCommand>),
    Peer(mpsc::Sender<PeerCommand>),
    Preview,
}

struct AppState {
    nick: String,
    fingerprint: String,
    mode_label: String,
    retention_label: String,
    status_line: String,
    messages: VecDeque<String>,
    peers: Vec<PeerSummary>,
    pending_votes: VecDeque<PendingVotePrompt>,
    input: String,
    should_quit: bool,
}

impl AppState {
    fn push_line(&mut self, line: String) {
        if self.messages.len() >= MAX_DISPLAY_LINES {
            let _ = self.messages.pop_front();
        }
        self.messages.push_back(line);
    }

    fn wipe_ram(&mut self) {
        for mut msg in self.messages.drain(..) {
            msg.zeroize();
        }
        self.input.zeroize();
        self.peers.clear();
        self.pending_votes.clear();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let nick = sanitize_nick(&cli.nick)?;
    let retention: HistoryRetention = cli.retention.into();
    let identity = IdentityKeypair::generate()?;
    let my_fp = identity.fingerprint();

    let (net_ctrl, mut host_ev_rx, mut peer_ev_rx, mode_label, retention_label) =
        match (cli.listen, cli.connect) {
            (Some(listen_addr), _) => {
                let raw_secret = rpassword::prompt_password("Segredo da sala (oculto): ")?;
                let secret = RoomSecret::new(raw_secret)?;
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
                    NetControl::Host(cmd_tx),
                    Some(ev_rx),
                    None,
                    format!("HOST ({listen_addr})"),
                    retention.label().to_owned(),
                )
            }
            (None, Some(connect_addr)) => {
                let raw_secret = rpassword::prompt_password("Segredo da sala (oculto): ")?;
                let secret = RoomSecret::new(raw_secret)?;

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
                    NetControl::Peer(cmd_tx),
                    None,
                    Some(ev_rx),
                    format!("PEER -> {connect_addr}"),
                    "Definida pelo Host".to_owned(),
                )
            }
            (None, None) => (
                NetControl::Preview,
                None,
                None,
                "PREVIEW (use --listen ou --connect)".to_owned(),
                retention.label().to_owned(),
            ),
        };

    let mut app = AppState {
        nick,
        fingerprint: my_fp,
        mode_label,
        retention_label,
        status_line: "Canal pronto.".to_owned(),
        messages: VecDeque::new(),
        peers: Vec::new(),
        pending_votes: VecDeque::new(),
        input: String::new(),
        should_quit: false,
    };

    app.push_line(
        "[SISTEMA] Comandos: /nick <nome> | /wipe (limpar e sair) | /quit | ESC para sair"
            .to_owned(),
    );

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard;
    let mut ui_tick = tokio::time::interval(Duration::from_millis(30));

    while !app.should_quit {
        terminal.draw(|frame| draw_ui(frame, &app))?;

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
                        app.push_line(format!("[HOST] Sala aberta em {addr}. Aguardando peers..."));
                    }
                    Some(HostEvent::SystemNotice(msg)) => app.push_line(format!("[SISTEMA] {msg}")),
                    Some(HostEvent::CandidateWaiting { candidate_id, nick, fingerprint }) => {
                        app.push_line(format!(
                            "[LOBBY] '{nick}' (FP: {fingerprint}) pediu entrada. Vote com F1/F2/F3!"
                        ));
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
                        app.push_line(format!("[VOTACAO] '{nick}' foi {status}."));
                    }
                    Some(HostEvent::ChatReceived(p)) => {
                        app.push_line(format!("<{}> {}", p.sender_nick, p.body));
                    }
                    Some(HostEvent::PeersUpdated(list)) => {
                        app.peers = list;
                    }
                    Some(HostEvent::HistoryPurged { removed, remaining }) => {
                        app.status_line = format!(
                            "Ciclo TTL: {removed} msg(s) zerada(s) da RAM | Ativas: {remaining}"
                        );
                    }
                    None => {
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
                        app.push_line(format!("[REDE] {s}"));
                    }
                    Some(PeerEvent::Admitted { host_fingerprint, retention, history_shared }) => {
                        app.retention_label = retention.label().to_owned();
                        app.status_line = format!("Conectado ao Host ({host_fingerprint})");
                        let h = if history_shared { "Historico enviado" } else { "Sem historico anterior" };
                        app.push_line(format!("[SALA] Entrada aprovada! ({h} | Retencao: {})", retention.label()));
                    }
                    Some(PeerEvent::VoteRequested { candidate_id, nick, fingerprint }) => {
                        app.push_line(format!(
                            "[LOBBY] '{nick}' (FP: {fingerprint}) quer entrar. Vote com F1/F2/F3!"
                        ));
                        app.pending_votes.push_back(PendingVotePrompt {
                            candidate_id,
                            nick,
                            fingerprint,
                        });
                    }
                    Some(PeerEvent::HistorySynced(msgs)) => {
                        app.push_line(format!("[HISTORICO] {} mensagem(ns) recente(s):", msgs.len()));
                        for m in msgs {
                            app.push_line(format!("  <{}> {}", m.sender_nick, m.body));
                        }
                    }
                    Some(PeerEvent::ChatReceived(p)) => {
                        app.push_line(format!("<{}> {}", p.sender_nick, p.body));
                    }
                    Some(PeerEvent::PeersUpdated(list)) => {
                        app.peers = list;
                    }
                    Some(PeerEvent::Disconnected(reason)) => {
                        app.status_line = format!("Desconectado: {reason}");
                        app.push_line(format!("[REDE] Desconectado: {reason}"));
                    }
                    None => {
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
        KeyCode::Backspace => {
            let _ = app.input.pop();
        }
        KeyCode::Char(c) => {
            if app.input.chars().count() < 1024 {
                app.input.push(c);
            }
        }
        KeyCode::Enter => {
            let text = app.input.trim().to_owned();
            app.input.zeroize();
            app.input.clear();
            if text.is_empty() {
                return;
            }

            if text == "/quit" || text == "/wipe" {
                let wipe = text == "/wipe";
                send_shutdown(net, wipe).await;
                app.should_quit = true;
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
                    app.push_line("[SISTEMA] Apelido invalido.".to_owned());
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
                    app.push_line(format!("<{} [LOCAL]> {}", app.nick, text));
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

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let vote_height = if app.pending_votes.is_empty() { 0 } else { 3 };

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(6),
            Constraint::Length(vote_height),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let header = Paragraph::new(format!(
        "FALKON v0.2 (Sofia) | Nick: {} | FP: {} | Retencao: {}\nModo: {} | {}",
        app.nick, app.fingerprint, app.retention_label, app.mode_label, app.status_line
    ))
    .wrap(Wrap { trim: false })
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .block(Block::default().borders(Borders::ALL).title("Status E2EE"));
    frame.render_widget(header, outer[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
        .split(outer[1]);

    let chat_lines: Vec<Line<'_>> = app
        .messages
        .iter()
        .map(|m| Line::from(Span::raw(m.as_str())))
        .collect();
    let chat = Paragraph::new(chat_lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Canal Efemero"),
    );
    frame.render_widget(chat, mid[0]);

    let peer_items: Vec<ListItem<'_>> = app
        .peers
        .iter()
        .map(|p| {
            let role = if p.is_host { "[HOST] " } else { "" };
            ListItem::new(format!("{role}{}\n  {}", p.nick, p.fingerprint))
        })
        .collect();
    let peers_list =
        List::new(peer_items).block(Block::default().borders(Borders::ALL).title("Peers Ativos"));
    frame.render_widget(peers_list, mid[1]);

    if let Some(vote) = app.pending_votes.front() {
        let banner = Paragraph::new(format!(
            "VOTACAO: '{}' ({}) | [F1] Aceitar + Historico | [F2] Aceitar SEM Historico | [F3] Recusar",
            vote.nick, vote.fingerprint
        ))
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title("Admissao P2P"));
        frame.render_widget(banner, outer[2]);
    }

    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Mensagem (Enter envia | /nick | /wipe | ESC sai)"),
    );
    frame.render_widget(input, outer[3]);
}
