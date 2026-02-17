use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::sync::{mpsc, watch};

use crate::config::{WatchConfig, WatchServiceConfig};
use super::alert::{AlertSink, ConsoleSink, JsonFileSink};
use super::{WatchEvent, WatchListener};
use super::ssh::SshHoneypot;
use super::http::HttpHoneypot;
use super::smb::SmbHoneypot;
use super::ftp::FtpHoneypot;
use super::telnet::TelnetHoneypot;
use super::rdp::RdpHoneypot;

/// Orchestrates honeypot listeners, event collection, and alert dispatch.
pub struct WatchEngine {
    config: WatchConfig,
    listeners: Vec<(Box<dyn WatchListener>, SocketAddr)>,
    sinks: Vec<Arc<dyn AlertSink>>,
}

impl WatchEngine {
    /// Build the engine from a WatchConfig, registering the appropriate listeners and sinks.
    pub async fn from_config(config: &WatchConfig) -> Result<Self> {
        let bind: std::net::IpAddr = config
            .bind_address
            .parse()
            .with_context(|| format!("Invalid bind address: {}", config.bind_address))?;

        let mut listeners: Vec<(Box<dyn WatchListener>, SocketAddr)> = Vec::new();

        for svc in &config.services {
            if !svc.enabled {
                continue;
            }
            let addr = SocketAddr::new(bind, svc.port);
            let listener: Box<dyn WatchListener> = build_listener(svc)?;
            listeners.push((listener, addr));
        }

        // Set up sinks.
        let mut sinks: Vec<Arc<dyn AlertSink>> = vec![Arc::new(ConsoleSink)];

        let alert_path = config
            .alert_file
            .as_deref()
            .unwrap_or("./results/watch-events.jsonl");
        let json_sink = JsonFileSink::new(Path::new(alert_path)).await
            .context("Failed to initialize JSON alert file sink")?;
        sinks.push(Arc::new(json_sink));

        Ok(Self {
            config: config.clone(),
            listeners,
            sinks,
        })
    }

    /// Run all listeners until Ctrl+C.
    pub async fn run(self) -> Result<()> {
        if self.listeners.is_empty() {
            println!("{}", "No watch listeners enabled. Nothing to do.".yellow());
            return Ok(());
        }

        self.print_startup_banner();

        let (events_tx, mut events_rx) = mpsc::unbounded_channel::<WatchEvent>();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn each listener as a tokio task.
        let mut handles = Vec::new();
        for (listener, addr) in self.listeners {
            let tx = events_tx.clone();
            let rx = shutdown_rx.clone();
            let name = listener.name().to_string();
            handles.push(tokio::spawn(async move {
                if let Err(e) = listener.listen(addr, tx, rx).await {
                    tracing::error!("[{}] Listener error: {}", name, e);
                }
            }));
        }
        // Drop the original sender so the channel can close after all listeners stop.
        drop(events_tx);

        let sinks = Arc::new(self.sinks);

        // Event dispatch loop — also spawned so we can select on Ctrl+C.
        let sinks_clone = sinks.clone();
        let dispatch_handle = tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                for sink in sinks_clone.iter() {
                    if let Err(e) = sink.emit(&event).await {
                        tracing::error!("[{}] Sink error: {}", sink.name(), e);
                    }
                }
            }
        });

        // Wait for Ctrl+C.
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for Ctrl+C")?;

        println!();
        println!("{}", "Shutting down watch listeners...".yellow().bold());

        // Signal all listeners to stop.
        let _ = shutdown_tx.send(true);

        // Give listeners a moment to wind down, then wait for dispatch to finish.
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Abort any remaining listener tasks.
        for h in &handles {
            h.abort();
        }
        // Wait for dispatch to drain remaining events.
        let _ = dispatch_handle.await;

        let alert_path = self
            .config
            .alert_file
            .as_deref()
            .unwrap_or("./results/watch-events.jsonl");
        println!(
            "{} Events written to {}",
            "Done.".green().bold(),
            alert_path,
        );

        Ok(())
    }

    fn print_startup_banner(&self) {
        println!();
        println!("{}", "╔═══════════════════════════════════════╗".cyan());
        println!("{}", "║        S E N T I N E L  W A T C H     ║".cyan());
        println!("{}", "║       Honeypot / Passive Defense      ║".cyan());
        println!("{}", "╚═══════════════════════════════════════╝".cyan());
        println!();
        println!(
            "{} {}",
            "Bind address:".bold(),
            self.config.bind_address
        );
        println!("{}", "Active listeners:".bold());
        for (listener, addr) in &self.listeners {
            println!(
                "  {} {} on {}",
                "●".green(),
                listener.name().cyan(),
                addr,
            );
        }
        println!();
        println!("{}", "Press Ctrl+C to stop.".dimmed());
        println!();
    }
}

/// Build a concrete WatchListener from a service config entry.
fn build_listener(svc: &WatchServiceConfig) -> Result<Box<dyn WatchListener>> {
    match svc.protocol.as_str() {
        "ssh" => Ok(Box::new(SshHoneypot::new(
            svc.banner.as_deref(),
        ))),
        "http" => Ok(Box::new(HttpHoneypot::new())),
        "smb" => Ok(Box::new(SmbHoneypot::new())),
        "ftp" => Ok(Box::new(FtpHoneypot::new(
            svc.banner.as_deref(),
        ))),
        "telnet" => Ok(Box::new(TelnetHoneypot::new())),
        "rdp" => Ok(Box::new(RdpHoneypot::new())),
        other => anyhow::bail!("Unknown watch service protocol: {}", other),
    }
}
