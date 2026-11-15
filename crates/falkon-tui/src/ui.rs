use std::time::Instant;

use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::app::{
    AppState, DisplayEntry, MAX_INPUT_CHARS, format_utc_hms, remaining_retention_label,
};

const SIDEBAR_MIN_TERMINAL_WIDTH: u16 = 72;

pub fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &mut AppState) {
    let now = Instant::now();
    let vote_height = if app.pending_votes.is_empty() { 0 } else { 3 };
    let area = frame.area();
    let show_sidebar = area.width >= SIDEBAR_MIN_TERMINAL_WIDTH;

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(6),
            Constraint::Length(vote_height),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(frame, app, outer[0], show_sidebar);

    if show_sidebar {
        let mid = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
            .split(outer[1]);
        render_chat(frame, app, mid[0], now);
        render_peers_sidebar(frame, app, mid[1]);
    } else {
        render_chat(frame, app, outer[1], now);
    }

    if let Some(vote) = app.pending_votes.front() {
        let queued = app.pending_votes.len();
        let queue_tag = if queued > 1 {
            format!(" [1/{queued}]")
        } else {
            String::new()
        };
        let banner = Paragraph::new(format!(
            "VOTACAO{queue_tag}: '{}' ({}) | [F1] Aceitar + Historico | [F2] Aceitar SEM Historico | [F3] Recusar",
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

    render_input(frame, app, outer[3]);
}

fn render_header(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect, show_sidebar: bool) {
    let border_color = if app.disconnected {
        Color::Red
    } else if !app.pending_votes.is_empty() {
        Color::Yellow
    } else {
        Color::Cyan
    };

    let peers_hint = if show_sidebar {
        String::new()
    } else {
        format!(" | Peers: {}", app.peers.len())
    };

    let header = Paragraph::new(format!(
        "FALKON v0.4.0 (Helena) | Nick: {} | FP: {} | Retencao: {}{}\nModo: {} | {}",
        app.nick,
        app.fingerprint,
        remaining_retention_label(app),
        peers_hint,
        app.mode_label,
        app.status_line
    ))
    .wrap(Wrap { trim: false })
    .style(
        Style::default()
            .fg(border_color)
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title("Status E2EE"),
    );
    frame.render_widget(header, area);
}

fn render_chat(frame: &mut ratatui::Frame<'_>, app: &mut AppState, chat_area: Rect, now: Instant) {
    let inner_width = usize::from(chat_area.width.saturating_sub(2)).max(1);
    let inner_height = usize::from(chat_area.height.saturating_sub(2));

    let mut chat_lines: Vec<Line<'_>> = Vec::new();
    let mut total_visual_lines: usize = 0;

    for entry in &app.messages {
        match entry {
            DisplayEntry::Chat {
                payload,
                received_at,
            } => {
                let nick_color = app
                    .peer_colors
                    .get(&payload.sender_id)
                    .copied()
                    .unwrap_or(Color::LightCyan);

                let ts = format!("[{}] ", format_utc_hms(payload.sent_unix_secs));
                let ttl_badge = app.remaining_ttl_secs(*received_at, now).map(|secs| {
                    let color = if secs <= 3 {
                        Color::LightRed
                    } else if secs <= 7 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    };
                    (format!("[{secs:02}s] "), color)
                });

                let mut sublines = payload.body.split('\n');
                if let Some(first) = sublines.next() {
                    let nick_prefix = format!("<{}> ", payload.sender_nick);
                    let ttl_chars = ttl_badge.as_ref().map_or(0, |(s, _)| s.chars().count());
                    let line_chars = ts.chars().count()
                        + ttl_chars
                        + nick_prefix.chars().count()
                        + first.chars().count();
                    total_visual_lines += line_chars.max(1).div_ceil(inner_width);

                    let mut spans = vec![Span::styled(ts, Style::default().fg(Color::DarkGray))];
                    if let Some((badge, badge_color)) = ttl_badge {
                        spans.push(Span::styled(
                            badge,
                            Style::default()
                                .fg(badge_color)
                                .add_modifier(Modifier::BOLD),
                        ));
                    }
                    spans.push(Span::styled(
                        nick_prefix,
                        Style::default().fg(nick_color).add_modifier(Modifier::BOLD),
                    ));
                    spans.push(Span::raw(first));
                    chat_lines.push(Line::from(spans));
                }

                for rest in sublines {
                    let line_chars = 2 + rest.chars().count();
                    total_visual_lines += line_chars.max(1).div_ceil(inner_width);
                    chat_lines.push(Line::from(Span::raw(format!("  {rest}"))));
                }
            }
            DisplayEntry::Notice { tag, color, text } => {
                let prefix = format!("[{tag}] ");
                for (idx, part) in text.split('\n').enumerate() {
                    if idx == 0 {
                        let line_chars = prefix.chars().count() + part.chars().count();
                        total_visual_lines += line_chars.max(1).div_ceil(inner_width);
                        chat_lines.push(Line::from(vec![
                            Span::styled(
                                prefix.clone(),
                                Style::default().fg(*color).add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(part),
                        ]));
                    } else {
                        let line_chars = 2 + part.chars().count();
                        total_visual_lines += line_chars.max(1).div_ceil(inner_width);
                        chat_lines.push(Line::from(Span::raw(format!("  {part}"))));
                    }
                }
            }
        }
    }

    let max_scroll = total_visual_lines.saturating_sub(inner_height);
    app.scroll_from_bottom = app.scroll_from_bottom.min(max_scroll);
    let scroll_y =
        u16::try_from(max_scroll.saturating_sub(app.scroll_from_bottom)).unwrap_or(u16::MAX);

    let title = if app.scroll_from_bottom > 0 {
        format!(
            "Canal Efemero [PAUSADO +{}L — PageDown/↓ retoma]",
            app.scroll_from_bottom
        )
    } else {
        "Canal Efemero".to_owned()
    };

    let chat = Paragraph::new(chat_lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll_y, 0))
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(chat, chat_area);
}

fn render_peers_sidebar(frame: &mut ratatui::Frame<'_>, app: &AppState, area: Rect) {
    let peer_items: Vec<ListItem<'_>> = app
        .peers
        .iter()
        .map(|p| {
            let color = app
                .peer_colors
                .get(&p.id)
                .copied()
                .unwrap_or(Color::LightCyan);
            let role = if p.is_host { "[HOST] " } else { "" };
            let (fp_top, fp_bot) = if p.fingerprint.len() > 18 {
                let (a, b) = p.fingerprint.split_at(17);
                (a, b.trim_start_matches('-'))
            } else {
                (p.fingerprint.as_str(), "")
            };
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(
                        role,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        p.nick.as_str(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(Span::styled(
                    format!("  {fp_top}"),
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            if !fp_bot.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  {fp_bot}"),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            ListItem::new(lines)
        })
        .collect();

    let title = format!("Peers Ativos ({})", app.peers.len());
    let peers_list =
        List::new(peer_items).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(peers_list, area);
}

fn render_input(frame: &mut ratatui::Frame<'_>, app: &AppState, input_area: Rect) {
    let inner_width = usize::from(input_area.width.saturating_sub(2)).max(1);
    let scroll_x = app
        .cursor_char_idx
        .saturating_sub(inner_width.saturating_sub(1));
    let visible_input: String = app.input.chars().skip(scroll_x).take(inner_width).collect();

    let count = app.input.chars().count();
    let title = if count > 0 {
        format!("Mensagem [{count}/{MAX_INPUT_CHARS}] (/help | Enter envia | ESC sai)")
    } else {
        "Mensagem (/help | /nick | /peers | /wipe | ESC sai)".to_owned()
    };

    let input =
        Paragraph::new(visible_input).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(input, input_area);

    let cursor_col = app.cursor_char_idx.saturating_sub(scroll_x);
    let cursor_x = input_area
        .x
        .saturating_add(1)
        .saturating_add(u16::try_from(cursor_col).unwrap_or(0));
    let cursor_y = input_area.y.saturating_add(1);
    frame.set_cursor_position(Position::new(cursor_x, cursor_y));
}
