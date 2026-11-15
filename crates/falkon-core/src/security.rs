use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::protocol::MessageId;

pub const DEFAULT_REPLAY_WINDOW: usize = 1024;

/// Protege contra replay de MessageId mantendo janela limitada de O(1).
pub struct ReplayGuard {
    capacity: usize,
    order: VecDeque<MessageId>,
    seen: HashSet<MessageId>,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            order: VecDeque::with_capacity(cap),
            seen: HashSet::with_capacity(cap),
        }
    }

    /// Retorna `true` se o MessageId for inedito (aceito); `false` se for repetido (replay).
    pub fn check_and_insert(&mut self, id: MessageId) -> bool {
        if self.seen.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.order.push_back(id);
        self.seen.insert(id);
        true
    }
}

/// Limitador de taxa por peer (Token Bucket) contra flood dentro da sala.
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            capacity: capacity.max(1.0),
            tokens: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(0.1),
            last_refill: now,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn cooldown_ready(last_action: Option<Instant>, cooldown: Duration, now: Instant) -> bool {
    match last_action {
        None => true,
        Some(prev) => now.saturating_duration_since(prev) >= cooldown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_guard_rejects_duplicate_and_evicts_oldest() {
        let mut guard = ReplayGuard::new(2);
        let id1 = [1u8; 16];
        let id2 = [2u8; 16];
        let id3 = [3u8; 16];

        assert!(guard.check_and_insert(id1));
        assert!(!guard.check_and_insert(id1));
        assert!(guard.check_and_insert(id2));
        assert!(guard.check_and_insert(id3));
        // id1 saiu da janela de 2 itens
        assert!(guard.check_and_insert(id1));
    }

    #[test]
    fn token_bucket_throttles_burst_and_refills() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(3.0, 2.0, start);

        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(!bucket.allow(start));

        // Apos 1 segundo recarrega 2 tokens
        let later = start + Duration::from_secs(1);
        assert!(bucket.allow(later));
        assert!(bucket.allow(later));
        assert!(!bucket.allow(later));
    }
}
