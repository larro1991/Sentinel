use anyhow::Result;
use async_trait::async_trait;

use super::alert::AlertSink;
use super::WatchEvent;
use crate::store::EventStore;

/// AlertSink that writes events to the SQLite event store.
pub struct SqliteSink {
    store: EventStore,
}

impl SqliteSink {
    pub fn new(store: EventStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AlertSink for SqliteSink {
    fn name(&self) -> &str {
        "sqlite"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        self.store.insert_event(event).await
    }
}
