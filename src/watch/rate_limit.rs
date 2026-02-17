use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Per-source-IP sliding-window event rate limiter.
///
/// Returns `true` from `check_and_increment` when the given IP has exceeded
/// the configured threshold within the sliding window, meaning the event
/// should be suppressed.
pub struct EventRateLimiter {
    max_events: u64,
    window: std::time::Duration,
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl EventRateLimiter {
    pub fn new(max_events_per_ip: u64, window_secs: u64) -> Self {
        Self {
            max_events: max_events_per_ip,
            window: std::time::Duration::from_secs(window_secs),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record an event for the given IP and return `true` if the rate limit
    /// has been **exceeded** (i.e., the event should be dropped).
    pub fn check_and_increment(&self, ip: &IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap();
        let timestamps = map.entry(*ip).or_default();

        // Prune timestamps older than the sliding window.
        timestamps.retain(|t| now.duration_since(*t) <= self.window);

        if timestamps.len() as u64 >= self.max_events {
            return true; // exceeded
        }

        timestamps.push(now);
        false
    }
}
