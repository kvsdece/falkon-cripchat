#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use clap::{Parser, ValueEnum};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

use falkon_core::crypto::IdentityKeypair;
use falkon_core::protocol::HistoryRetention;
use falkon_core::sanitize::sanitize_nick;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let nick = sanitize_nick(&cli.nick)?;
    let retention: HistoryRetention = cli.retention.into();
    let identity = IdentityKeypair::generate()?;

    let mode = match (&cli.listen, &cli.connect) {
        (Some(addr), _) => format!("HOST ({addr})"),
        (None, Some(addr)) => format!("PEER -> {addr}"),
        (None, None) => "PREVIEW LOCAL (use --listen ou --connect)".to_owned(),
    };

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard;

    loop {
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(3),
                ])
                .split(frame.area());

            let header = Paragraph::new(format!(
                " FALKON v0.1 | Nick: {nick} | FP: {} | Retencao Host: {} | Modo: {mode} ",
                identity.fingerprint(),
                retention.label()
            ))
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL).title("Status E2EE"));
            frame.render_widget(header, chunks[0]);

            let body = Paragraph::new(
                "Base Ponto 1 + Ponto 2 carregada em AlternateScreen.\n\
                 - Transporte P2P-TCP abstraido e pronto para futuro .onion\n\
                 - Handshake Noise_XXpsk3 + Argon2id + ZeroizeOnDrop ativos\n\
                 - Proximo passo (Ponto 3): conectar loop multi-peer + votacao dupla interativa.",
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Canal Efemero (Zero Historico em Disco)"),
            );
            frame.render_widget(body, chunks[1]);

            let footer = Paragraph::new(" Pressione 'q' ou ESC para sair e limpar a tela. ")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            break;
        }
    }

    Ok(())
}
