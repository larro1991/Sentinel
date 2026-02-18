use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::WatchEvent;

/// Key for deduplication: (source_ip, event_type, dest_port).
type DedupKey = (String, String, u16);

struct PendingEntry {
    first_event: WatchEvent,
    count: u32,
    first_seen: DateTime<Utc>,
}

/// Collapses repeated events within a configurable time window.
///
/// On the first occurrence of (source_ip, event_type, dest_port), the event
/// passes through immediately. Subsequent identical events within `window_secs`
/// are suppressed. When the window expires, the next occurrence passes with
/// `dedup_count` set to the total collapsed count.
pub struct EventDeduplicator {
    window_secs: u64,
    pending: HashMap<DedupKey, PendingEntry>,
}

impl EventDeduplicator {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            pending: HashMap::new(),
        }
    }

    /// Process an event. Returns `Some(event)` if it should be emitted,
    /// `None` if it was collapsed/suppressed.
    pub fn process(&mut self, mut event: WatchEvent) -> Option<WatchEvent> {
        let key: DedupKey = (
            event.source_ip.to_string(),
            event.event_type.to_string(),
            event.dest_port,
        );

        let now = event.timestamp;

        if let Some(entry) = self.pending.get_mut(&key) {
            let elapsed = (now - entry.first_seen).num_seconds();

            if elapsed < self.window_secs as i64 {
                // Still within window — suppress.
                entry.count += 1;
                return None;
            }

            // Window expired — emit with accumulated count.
            let count = entry.count + 1;
            entry.first_seen = now;
            entry.count = 0;
            entry.first_event = event.clone();
            event.dedup_count = Some(count);
            Some(event)
        } else {
            // First occurrence — pass through.
            self.pending.insert(
                key,
                PendingEntry {
                    first_event: event.clone(),
                    count: 0,
                    first_seen: now,
                },
            );
            Some(event)
        }
    }

    /// Flush all pending entries — emit events with their accumulated counts.
    /// Used during shutdown to avoid losing suppressed event counts.
    pub fn flush(&mut self) -> Vec<WatchEvent> {
        let mut events = Vec::new();
        for (_key, entry) in self.pending.drain() {
            if entry.count > 0 {
                let mut event = entry.first_event;
                event.dedup_count = Some(entry.count + 1);
                events.push(event);
            }
        }
        events
    }
}
