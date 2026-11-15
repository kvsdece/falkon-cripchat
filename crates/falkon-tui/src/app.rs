use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use ratatui::style::Color;
use zeroize::Zeroize;

use falkon_core::protocol::{ChatPayload, HistoryRetention, PeerId, PeerSummary};

pub const MAX_DISPLAY_LINES: usize = 200;
pub const MAX_INPUT_CHARS: usize = 1024;

const PEER_PALETTE: [Color; 10] = [
    Color::LightGreen,
    Color::LightCyan,
    Color::LightMagenta,
    Color::LightBlue,
    Color::LightYellow,
    Color::LightRed,
    Color::Green,
    Color::Cyan,
    Color::Magenta,
    Color::Blue,
];

#[derive(Clone)]
pub struct PendingVotePrompt {
    pub candidate_id: PeerId,
    pub nick: String,
    pub fingerprint: String,
}

pub enum DisplayEntry {
    Chat {
        payload: ChatPayload,
        received_at: Instant,
    },
    Notice {
        tag: &'static str,
        color: Color,
        text: String,
    },
}

pub struct AppState {
    pub my_peer_id: PeerId,
    pub nick: String,
    pub fingerprint: String,
    pub full_fingerprint: String,
    pub mode_label: String,
    pub retention: HistoryRetention,
    pub retention_known: bool,
    pub status_line: String,
    pub disconnected: bool,
    pub messages: VecDeque<DisplayEntry>,
    pub peers: Vec<PeerSummary>,
    pub peer_colors: HashMap<PeerId, Color>,
    pub pending_votes: VecDeque<PendingVotePrompt>,
    pub input: String,
    pub cursor_char_idx: usize,
    pub scroll_from_bottom: usize,
    pub should_quit: bool,
}

impl AppState {
    pub fn ensure_peer_color(&mut self, id: PeerId) -> Color {
        if let Some(&existing) = self.peer_colors.get(&id) {
            return existing;
        }
        let start = usize::from(id[0]) % PEER_PALETTE.len();
        let mut chosen = PEER_PALETTE[start];
        let mut best_count = usize::MAX;

        for offset in 0..PEER_PALETTE.len() {
            let candidate = PEER_PALETTE[(start + offset) % PEER_PALETTE.len()];
            let count = self
                .peer_colors
                .values()
                .filter(|&&c| c == candidate)
                .count();
            if count < best_count {
                best_count = count;
                chosen = candidate;
            }
        }
        self.peer_colors.insert(id, chosen);
        chosen
    }

    pub fn push_chat(&mut self, payload: ChatPayload) {
        self.push_chat_at(payload, Instant::now());
    }

    pub fn push_chat_at(&mut self, payload: ChatPayload, now: Instant) {
        let _ = self.ensure_peer_color(payload.sender_id);
        self.push_entry(DisplayEntry::Chat {
            payload,
            received_at: now,
        });
    }

    pub fn push_notice(&mut self, tag: &'static str, color: Color, text: String) {
        self.push_entry(DisplayEntry::Notice { tag, color, text });
    }

    fn push_entry(&mut self, entry: DisplayEntry) {
        if self.messages.len() >= MAX_DISPLAY_LINES {
            let _ = self.messages.pop_front();
        }
        self.messages.push_back(entry);
    }

    pub fn sync_peers(&mut self, list: Vec<PeerSummary>) {
        for p in &list {
            let _ = self.ensure_peer_color(p.id);
        }
        self.peers = list;
    }

    pub fn purge_expired_ui(&mut self, now: Instant) -> usize {
        if !self.retention_known {
            return 0;
        }
        let Some(ttl) = self.retention.as_duration() else {
            return 0;
        };

        let mut removed = 0usize;
        let mut kept = VecDeque::with_capacity(self.messages.len());
        while let Some(mut entry) = self.messages.pop_front() {
            match &mut entry {
                DisplayEntry::Chat {
                    payload,
                    received_at,
                } if now.saturating_duration_since(*received_at) >= ttl => {
                    payload.zeroize();
                    removed += 1;
                }
                _ => kept.push_back(entry),
            }
        }
        self.messages = kept;
        removed
    }

    pub fn clear_chat_screen(&mut self) {
        for mut entry in self.messages.drain(..) {
            match &mut entry {
                DisplayEntry::Chat { payload, .. } => payload.zeroize(),
                DisplayEntry::Notice { text, .. } => text.zeroize(),
            }
        }
        self.scroll_from_bottom = 0;
    }

    pub fn wipe_ram(&mut self) {
        self.clear_chat_screen();
        self.input.zeroize();
        self.input.clear();
        self.cursor_char_idx = 0;
        self.peers.clear();
        self.peer_colors.clear();
        self.pending_votes.clear();
    }

    fn cursor_byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(idx, _)| idx)
            .nth(self.cursor_char_idx)
            .unwrap_or(self.input.len())
    }

    pub fn insert_char(&mut self, c: char) {
        if self.input.chars().count() >= MAX_INPUT_CHARS {
            return;
        }
        let byte_idx = self.cursor_byte_index();
        self.input.insert(byte_idx, c);
        self.cursor_char_idx += 1;
    }

    pub fn backspace(&mut self) {
        if self.cursor_char_idx == 0 {
            return;
        }
        self.cursor_char_idx -= 1;
        let byte_idx = self.cursor_byte_index();
        if byte_idx < self.input.len() {
            let _ = self.input.remove(byte_idx);
        }
    }

    pub fn delete_char(&mut self) {
        let byte_idx = self.cursor_byte_index();
        if byte_idx < self.input.len() {
            let _ = self.input.remove(byte_idx);
        }
    }

    pub fn move_left(&mut self) {
        self.cursor_char_idx = self.cursor_char_idx.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        let len = self.input.chars().count();
        if self.cursor_char_idx < len {
            self.cursor_char_idx += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor_char_idx = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor_char_idx = self.input.chars().count();
    }

    pub fn take_submitted_input(&mut self) -> String {
        let text = self.input.trim().to_owned();
        self.input.zeroize();
        self.input.clear();
        self.cursor_char_idx = 0;
        self.scroll_from_bottom = 0;
        text
    }

    pub fn scroll_up(&mut self, lines: usize) {
        self.scroll_from_bottom = self.scroll_from_bottom.saturating_add(lines);
    }

    pub fn scroll_down(&mut self, lines: usize) {
        self.scroll_from_bottom = self.scroll_from_bottom.saturating_sub(lines);
    }

    pub fn remaining_ttl_secs(&self, received_at: Instant, now: Instant) -> Option<u64> {
        if !self.retention_known {
            return None;
        }
        let ttl = self.retention.as_duration()?;
        let elapsed = now.saturating_duration_since(received_at);
        if elapsed >= ttl {
            Some(0)
        } else {
            let rem = ttl.saturating_sub(elapsed);
            let secs = rem.as_secs();
            let rounded = if rem.subsec_nanos() > 0 {
                secs.saturating_add(1)
            } else {
                secs
            };
            Some(rounded.min(ttl.as_secs()))
        }
    }
}

pub fn format_utc_hms(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "LOCAL".to_owned();
    }
    let secs_of_day = unix_secs % 86_400;
    let h = secs_of_day / 3_600;
    let m = (secs_of_day % 3_600) / 60;
    let s = secs_of_day % 60;
    format!("{h:02}:{m:02}:{s:02}Z")
}

pub fn remaining_retention_label(app: &AppState) -> &str {
    if app.retention_known {
        app.retention.label()
    } else {
        "Sincronizando..."
    }
}

pub fn help_lines() -> Vec<String> {
    vec![
        "Comandos: /nick <nome> | /peers | /fingerprint | /clear | /wipe | /quit".to_owned(),
        "Votacao:  [F1] Aceitar + Historico | [F2] Aceitar SEM Historico | [F3] Recusar"
            .to_owned(),
        "Navegacao: Setas Esq/Dir/Home/End/Del editam texto | Up/Down/PgUp/PgDn rolam chat | ESC sai"
            .to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    fn test_app(retention: HistoryRetention) -> AppState {
        AppState {
            my_peer_id: [0u8; 16],
            nick: "Helena".to_owned(),
            fingerprint: "0000".to_owned(),
            full_fingerprint: "0000".to_owned(),
            mode_label: "TEST".to_owned(),
            retention,
            retention_known: true,
            status_line: String::new(),
            disconnected: false,
            messages: VecDeque::new(),
            peers: Vec::new(),
            peer_colors: HashMap::new(),
            pending_votes: VecDeque::new(),
            input: String::new(),
            cursor_char_idx: 0,
            scroll_from_bottom: 0,
            should_quit: false,
        }
    }

    #[test]
    fn ui_messages_purge_and_zeroize_on_ttl() {
        let start = Instant::now();
        let mut app = test_app(HistoryRetention::Secs5);
        app.push_chat_at(
            ChatPayload {
                msg_id: [1u8; 16],
                sender_id: [2u8; 16],
                sender_nick: "Diego".to_owned(),
                body: "segredo efemero".to_owned(),
                sent_unix_secs: 0,
            },
            start,
        );
        app.push_notice("SISTEMA", Color::DarkGray, "aviso fixo".to_owned());

        assert_eq!(app.messages.len(), 2);
        assert_eq!(app.purge_expired_ui(start + Duration::from_secs(3)), 0);
        assert_eq!(app.messages.len(), 2);

        assert_eq!(app.purge_expired_ui(start + Duration::from_secs(6)), 1);
        assert_eq!(app.messages.len(), 1);
    }

    #[test]
    fn utf8_cursor_edits_and_deletes_without_panic() {
        let mut app = test_app(HistoryRetention::Never);
        for c in "olá ç!".chars() {
            app.insert_char(c);
        }
        assert_eq!(app.input, "olá ç!");
        assert_eq!(app.cursor_char_idx, 6);

        app.move_left();
        app.move_left();
        app.backspace(); // remove espaco antes de 'ç'
        assert_eq!(app.input, "oláç!");

        app.move_home();
        app.delete_char(); // remove 'o'
        assert_eq!(app.input, "láç!");

        app.move_end();
        app.insert_char('?');
        assert_eq!(app.take_submitted_input(), "láç!?");
        assert!(app.input.is_empty());
        assert_eq!(app.cursor_char_idx, 0);
    }

    #[test]
    fn format_utc_hms_works() {
        assert_eq!(format_utc_hms(0), "LOCAL");
        assert_eq!(format_utc_hms(3_661), "01:01:01Z");
    }
}
