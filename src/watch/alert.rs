use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use colored::Colorize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::finding::Severity;
use super::WatchEvent;

/// Trait for consuming watch events.
#[async_trait]
pub trait AlertSink: Send + Sync {
    fn name(&self) -> &str;
    async fn emit(&self, event: &WatchEvent) -> Result<()>;
}

// ── JsonFileSink ──────────────────────────────────────────────────────────────

/// Appends one JSON object per line (NDJSON) to a file.
pub struct JsonFileSink {
    path: PathBuf,
    file: Mutex<tokio::fs::File>,
}

impl JsonFileSink {
    pub async fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create directory for {}", path.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("Failed to open alert file {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl AlertSink for JsonFileSink {
    fn name(&self) -> &str {
        "json-file"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        let mut line = serde_json::to_string(event)
            .context("Failed to serialize WatchEvent")?;
        line.push('\n');
        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes()).await
            .context("Failed to write to alert file")?;
        file.flush().await
            .context("Failed to flush alert file")?;
        Ok(())
    }
}

// ── ConsoleSink ───────────────────────────────────────────────────────────────

/// Prints events to the terminal with severity-based coloring.
pub struct ConsoleSink;

#[async_trait]
impl AlertSink for ConsoleSink {
    fn name(&self) -> &str {
        "console"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        let severity_tag = match event.severity {
            Severity::Critical => format!("[{}]", "CRIT".red().bold()),
            Severity::High     => format!("[{}]", "HIGH".red()),
            Severity::Medium   => format!("[{}]", "MED ".yellow()),
            Severity::Low      => format!("[{}]", "LOW ".blue()),
            Severity::Info     => format!("[{}]", "INFO".white()),
        };

        let captured = event
            .captured_data
            .as_deref()
            .unwrap_or("");

        println!(
            "{} {} {} {}:{} -> :{} {}  {}",
            event.timestamp.format("%H:%M:%S").to_string().dimmed(),
            severity_tag,
            event.listener.cyan(),
            event.source_ip,
            event.source_port,
            event.dest_port,
            event.event_type.to_string().bold(),
            captured,
        );

        Ok(())
    }
}
