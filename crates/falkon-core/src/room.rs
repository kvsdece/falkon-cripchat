use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::error::FalkonError;
use crate::protocol::{ChatPayload, HistoryRetention, PeerId};

pub const MAX_ACTIVE_HISTORY_MESSAGES: usize = 200;
pub const MAX_PENDING_CANDIDATES: usize = 4;
pub const DEFAULT_VOTE_TIMEOUT: Duration = Duration::from_secs(30);

struct TimedMessage {
    payload: ChatPayload,
    inserted_at: Instant,
}

pub struct EphemeralHistory {
    retention: HistoryRetention,
    entries: VecDeque<TimedMessage>,
}

impl EphemeralHistory {
    pub fn new(retention: HistoryRetention) -> Self {
        Self {
            retention,
            entries: VecDeque::new(),
        }
    }

    pub fn retention(&self) -> HistoryRetention {
        self.retention
    }

    pub fn push(&mut self, payload: ChatPayload, now: Instant) {
        self.purge_expired(now);
        if self.entries.len() >= MAX_ACTIVE_HISTORY_MESSAGES {
            let _ = self.entries.pop_front();
        }
        self.entries.push_back(TimedMessage {
            payload,
            inserted_at: now,
        });
    }

    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let Some(ttl) = self.retention.as_duration() else {
            return 0;
        };

        let mut removed = 0;
        while let Some(front) = self.entries.front() {
            if now.saturating_duration_since(front.inserted_at) >= ttl {
                let _ = self.entries.pop_front();
                removed += 1;
            } else {
                break;
            }
        }
        removed
    }

    pub fn snapshot(&mut self, now: Instant) -> Vec<ChatPayload> {
        self.purge_expired(now);
        self.entries.iter().map(|e| e.payload.clone()).collect()
    }

    pub fn clear_all(&mut self) {
        while let Some(mut item) = self.entries.pop_front() {
            zeroize::Zeroize::zeroize(&mut item.payload);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteOutcome {
    pub allow_entry: bool,
    pub share_history: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteProgress {
    Pending,
    Decided(VoteOutcome),
    TimedOut,
}

pub struct AdmissionVote {
    pub candidate_id: PeerId,
    pub nick: String,
    pub fingerprint: String,
    created_at: Instant,
    expected_voters: HashSet<PeerId>,
    votes: HashMap<PeerId, (bool, bool)>,
}

impl AdmissionVote {
    pub fn new(
        candidate_id: PeerId,
        nick: String,
        fingerprint: String,
        expected_voters: HashSet<PeerId>,
        now: Instant,
    ) -> Result<Self, FalkonError> {
        if expected_voters.is_empty() {
            return Err(FalkonError::InvalidState(
                "votacao requer ao menos 1 votante (Host)",
            ));
        }
        Ok(Self {
            candidate_id,
            nick,
            fingerprint,
            created_at: now,
            expected_voters,
            votes: HashMap::new(),
        })
    }

    pub fn cast_vote(
        &mut self,
        voter_id: PeerId,
        allow_entry: bool,
        share_history: bool,
        now: Instant,
    ) -> Result<VoteProgress, FalkonError> {
        if now.saturating_duration_since(self.created_at) >= DEFAULT_VOTE_TIMEOUT {
            return Ok(VoteProgress::TimedOut);
        }

        if !self.expected_voters.contains(&voter_id) {
            return Err(FalkonError::InvalidInput(
                "votante nao autorizado nesta sala",
            ));
        }

        if self.votes.contains_key(&voter_id) {
            return Err(FalkonError::InvalidInput(
                "voto duplicado pelo mesmo membro",
            ));
        }

        self.votes
            .insert(voter_id, (allow_entry, allow_entry && share_history));

        if !allow_entry {
            return Ok(VoteProgress::Decided(VoteOutcome {
                allow_entry: false,
                share_history: false,
            }));
        }

        if self.votes.len() == self.expected_voters.len() {
            let all_allow = self.votes.values().all(|(entry, _)| *entry);
            let all_share = self.votes.values().all(|(_, hist)| *hist);
            return Ok(VoteProgress::Decided(VoteOutcome {
                allow_entry: all_allow,
                share_history: all_allow && all_share,
            }));
        }

        Ok(VoteProgress::Pending)
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= DEFAULT_VOTE_TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_msg(text: &str) -> ChatPayload {
        ChatPayload {
            msg_id: [1u8; 16],
            sender_id: [2u8; 16],
            sender_nick: "Clara".to_owned(),
            body: text.to_owned(),
            sent_unix_secs: 1_700_000_000,
        }
    }

    #[test]
    fn history_retention_expires_on_timer() {
        let start = Instant::now();
        let mut history = EphemeralHistory::new(HistoryRetention::Secs5);
        history.push(sample_msg("mensagem temporaria"), start);
        assert_eq!(history.len(), 1);

        let at_3s = start + Duration::from_secs(3);
        assert_eq!(history.snapshot(at_3s).len(), 1);

        let at_6s = start + Duration::from_secs(6);
        assert!(history.snapshot(at_6s).is_empty());
    }

    #[test]
    fn dual_vote_requires_unanimity_for_history_and_entry() -> Result<(), FalkonError> {
        let now = Instant::now();
        let host = [1u8; 16];
        let peer_a = [2u8; 16];
        let candidate = [3u8; 16];

        let mut voters = HashSet::new();
        voters.insert(host);
        voters.insert(peer_a);

        let mut vote = AdmissionVote::new(
            candidate,
            "Mateus".to_owned(),
            "AABB-CCDD-1122-3344".to_owned(),
            voters,
            now,
        )?;

        let p1 = vote.cast_vote(host, true, true, now)?;
        assert_eq!(p1, VoteProgress::Pending);

        // Voto duplicado do mesmo membro deve ser rejeitado
        assert!(vote.cast_vote(host, true, false, now).is_err());

        let p2 = vote.cast_vote(peer_a, true, false, now)?;
        assert_eq!(
            p2,
            VoteProgress::Decided(VoteOutcome {
                allow_entry: true,
                share_history: false,
            })
        );

        Ok(())
    }
}
