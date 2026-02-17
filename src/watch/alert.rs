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

// ── RotatingJsonFileSink ─────────────────────────────────────────────────────

/// NDJSON file sink with size-based rotation.
///
/// When the current file size plus the new line would exceed `max_size_bytes`,
/// the file is rotated: `.jsonl` -> `.jsonl.1`, `.jsonl.1` -> `.jsonl.2`, etc.
/// Files beyond `max_files` are deleted.
pub struct RotatingJsonFileSink {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
    state: Mutex<RotatingState>,
}

struct RotatingState {
    file: tokio::fs::File,
    current_size: u64,
}

impl RotatingJsonFileSink {
    pub async fn new(path: &Path, max_size_bytes: u64, max_files: u32) -> Result<Self> {
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

        let current_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            path: path.to_path_buf(),
            max_size_bytes,
            max_files,
            state: Mutex::new(RotatingState {
                file,
                current_size,
            }),
        })
    }

    /// Rotate log files: .jsonl -> .jsonl.1, .jsonl.1 -> .jsonl.2, etc.
    async fn rotate(&self, state: &mut RotatingState) -> Result<()> {
        // Close current file (drop will happen when we overwrite).
        // Rotate existing numbered files.
        for i in (1..self.max_files).rev() {
            let from = rotated_path(&self.path, i);
            let to = rotated_path(&self.path, i + 1);
            if tokio::fs::metadata(&from).await.is_ok() {
                let _ = tokio::fs::rename(&from, &to).await;
            }
        }

        // Delete the oldest if it exceeds max_files.
        let oldest = rotated_path(&self.path, self.max_files);
        if tokio::fs::metadata(&oldest).await.is_ok() {
            let _ = tokio::fs::remove_file(&oldest).await;
        }

        // Rename current -> .jsonl.1
        let first_rotated = rotated_path(&self.path, 1);
        let _ = tokio::fs::rename(&self.path, &first_rotated).await;

        // Open a fresh file.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .context("Failed to open fresh rotated file")?;

        state.file = file;
        state.current_size = 0;

        tracing::info!("Log file rotated: {}", self.path.display());
        Ok(())
    }
}

fn rotated_path(base: &Path, n: u32) -> PathBuf {
    let mut p = base.as_os_str().to_owned();
    p.push(format!(".{}", n));
    PathBuf::from(p)
}

#[async_trait]
impl AlertSink for RotatingJsonFileSink {
    fn name(&self) -> &str {
        "rotating-json-file"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        let mut line = serde_json::to_string(event)
            .context("Failed to serialize WatchEvent")?;
        line.push('\n');

        let line_len = line.len() as u64;
        let mut state = self.state.lock().await;

        // Check if rotation is needed.
        if state.current_size + line_len > self.max_size_bytes {
            self.rotate(&mut state).await?;
        }

        state
            .file
            .write_all(line.as_bytes())
            .await
            .context("Failed to write to alert file")?;
        state
            .file
            .flush()
            .await
            .context("Failed to flush alert file")?;
        state.current_size += line_len;

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

        let geo_str = event
            .geo_country_code
            .as_deref()
            .map(|cc| format!(" [{}]", cc))
            .unwrap_or_default();

        println!(
            "{} {} {} {}:{} -> :{} {}  {}{}",
            event.timestamp.format("%H:%M:%S").to_string().dimmed(),
            severity_tag,
            event.listener.cyan(),
            event.source_ip,
            event.source_port,
            event.dest_port,
            event.event_type.to_string().bold(),
            captured,
            geo_str.dimmed(),
        );

        Ok(())
    }
}
