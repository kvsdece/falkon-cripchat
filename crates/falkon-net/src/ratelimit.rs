use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use crate::transport::PeerEndpoint;

const MAX_TRACKED_KEYS: usize = 1024;
const DEFAULT_WINDOW: Duration = Duration::from_secs(10);
const DEFAULT_MAX_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateKey {
    Ip(IpAddr),
    OnionShared,
}

/// Limitador de taxa de conexoes em RAM com teto fixo de chaves rastreadas
/// (impede crescimento infinito da tabela sob ataque distribuido).
pub struct ConnectionRateLimiter {
    window: Duration,
    max_attempts: usize,
    entries: HashMap<RateKey, VecDeque<Instant>>,
    lru: VecDeque<RateKey>,
}

impl Default for ConnectionRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_MAX_ATTEMPTS)
    }
}

impl ConnectionRateLimiter {
    pub fn new(window: Duration, max_attempts: usize) -> Self {
        Self {
            window,
            max_attempts: max_attempts.max(1),
            entries: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn allow(&mut self, endpoint: &PeerEndpoint, now: Instant) -> bool {
        let key = match endpoint {
            PeerEndpoint::DirectTcp(addr) => RateKey::Ip(addr.ip()),
            PeerEndpoint::OnionV3(_) => RateKey::OnionShared,
        };

        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_TRACKED_KEYS {
            while let Some(old_key) = self.lru.pop_front() {
                if self.entries.remove(&old_key).is_some() {
                    break;
                }
            }
        }

        let is_new = !self.entries.contains_key(&key);
        let queue = self.entries.entry(key).or_default();
        if is_new {
            self.lru.push_back(key);
        }

        while let Some(&oldest) = queue.front() {
            if now.saturating_duration_since(oldest) >= self.window {
                let _ = queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.max_attempts {
            return false;
        }

        queue.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn rate_limiter_blocks_burst_and_recovers_after_window() {
        let mut limiter = ConnectionRateLimiter::new(Duration::from_secs(10), 3);
        let ep = PeerEndpoint::DirectTcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            50000,
        ));
        let start = Instant::now();

        assert!(limiter.allow(&ep, start));
        assert!(limiter.allow(&ep, start));
        assert!(limiter.allow(&ep, start));
        assert!(!limiter.allow(&ep, start));

        let after_window = start + Duration::from_secs(11);
        assert!(limiter.allow(&ep, after_window));
    }
}
