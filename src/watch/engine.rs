use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::sync::{mpsc, watch};

use crate::config::{
    AuthorizationConfig, ScopeConfig, WatchConfig, WatchServiceConfig,
};
use crate::scope::ScopeValidator;

use super::alert::{AlertSink, ConsoleSink, JsonFileSink, RotatingJsonFileSink};
use super::dashboard::DashboardSink;
use super::dns::DnsHoneypot;
use super::ftp::FtpHoneypot;
use super::geo::{GeoProvider, IpApiProvider};
use super::http::HttpHoneypot;
use super::mysql::MysqlHoneypot;
use super::postgres::PostgresHoneypot;
use super::rate_limit::EventRateLimiter;
use super::rdp::RdpHoneypot;
use super::smb::SmbHoneypot;
use super::smtp::SmtpHoneypot;
use super::ssh::SshHoneypot;
use super::telnet::TelnetHoneypot;
use super::webhook::WebhookSink;
use super::{WatchEvent, WatchListener};

/// Orchestrates honeypot listeners, event collection, and alert dispatch.
pub struct WatchEngine {
    config: WatchConfig,
    listeners: Vec<(Box<dyn WatchListener>, SocketAddr)>,
    sinks: Vec<Arc<dyn AlertSink>>,
    scope_validator: Option<Arc<ScopeValidator>>,
    rate_limiter: Option<Arc<EventRateLimiter>>,
    geo_provider: Option<Arc<dyn GeoProvider>>,
    scope_action: String,
}

impl WatchEngine {
    /// Build the engine from a WatchConfig, registering the appropriate listeners and sinks.
    /// Optionally accepts scope/authorization configs for the enrichment pipeline.
    pub async fn from_config(
        config: &WatchConfig,
        scope: Option<(&ScopeConfig, &AuthorizationConfig)>,
    ) -> Result<Self> {
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

        // Use rotating file sink if log rotation is configured, otherwise plain.
        if let Some(ref rotation) = config.log_rotation {
            let rotating_sink = RotatingJsonFileSink::new(
                Path::new(alert_path),
                rotation.max_size_bytes,
                rotation.max_files,
            )
            .await
            .context("Failed to initialize rotating JSON file sink")?;
            sinks.push(Arc::new(rotating_sink));
        } else {
            let json_sink = JsonFileSink::new(Path::new(alert_path))
                .await
                .context("Failed to initialize JSON alert file sink")?;
            sinks.push(Arc::new(json_sink));
        }

        // Webhook sinks.
        for wh in &config.webhooks {
            let webhook_sink = WebhookSink::new(&wh.url, &wh.name, &wh.min_severity);
            sinks.push(Arc::new(webhook_sink));
        }

        // Dashboard sink.
        if let Some(ref dash_config) = config.dashboard {
            let dashboard_sink = DashboardSink::new(
                &dash_config.bind_address,
                dash_config.port,
            );
            sinks.push(Arc::new(dashboard_sink));
        }

        // Scope validator.
        let scope_validator = if let Some((scope_cfg, auth_cfg)) = scope {
            if config.scope_filter.is_some() {
                match ScopeValidator::new(scope_cfg, auth_cfg) {
                    Ok(v) => Some(Arc::new(v)),
                    Err(e) => {
                        tracing::warn!("Failed to build scope validator for watch: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let scope_action = config
            .scope_filter
            .as_ref()
            .map(|sf| sf.action.clone())
            .unwrap_or_else(|| "tag".to_string());

        // Rate limiter.
        let rate_limiter = config.rate_limit.as_ref().map(|rl| {
            Arc::new(EventRateLimiter::new(
                rl.max_events_per_ip,
                rl.window_secs,
            ))
        });

        // GeoIP provider.
        let geo_provider: Option<Arc<dyn GeoProvider>> = config.geoip.as_ref().map(|geo| {
            Arc::new(IpApiProvider::new(geo.cache_size)) as Arc<dyn GeoProvider>
        });

        Ok(Self {
            config: config.clone(),
            listeners,
            sinks,
            scope_validator,
            rate_limiter,
            geo_provider,
            scope_action,
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
        let scope_validator = self.scope_validator.clone();
        let rate_limiter = self.rate_limiter.clone();
        let geo_provider = self.geo_provider.clone();
        let scope_action = self.scope_action.clone();

        // Event dispatch loop with enrichment pipeline.
        let sinks_clone = sinks.clone();
        let dispatch_handle = tokio::spawn(async move {
            while let Some(mut event) = events_rx.recv().await {
                // 1. Scope filter
                if let Some(ref validator) = scope_validator {
                    if validator.validate_ip(&event.source_ip).is_err() {
                        if scope_action == "drop" {
                            tracing::debug!(
                                "Dropping event from out-of-scope IP: {}",
                                event.source_ip
                            );
                            continue;
                        }
                        // "tag" mode — annotate but continue
                        event
                            .details
                            .insert("out_of_scope".to_string(), "true".to_string());
                    }
                }

                // 2. Rate limit
                if let Some(ref limiter) = rate_limiter {
                    if limiter.check_and_increment(&event.source_ip) {
                        tracing::debug!(
                            "Rate-limited event from {}: suppressed",
                            event.source_ip
                        );
                        continue;
                    }
                }

                // 3. GeoIP enrichment
                if let Some(ref geo) = geo_provider {
                    if let Ok(info) = geo.lookup(&event.source_ip).await {
                        event.geo_country = info.country;
                        event.geo_country_code = info.country_code;
                        event.geo_city = info.city;
                        event.geo_asn = info.asn;
                        event.geo_org = info.org;
                    }
                }

                // 4. Dispatch to all sinks
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
        if self.scope_validator.is_some() {
            println!("  {} Scope filter active ({})", "●".green(), self.scope_action);
        }
        if self.rate_limiter.is_some() {
            println!("  {} Rate limiter active", "●".green());
        }
        if self.geo_provider.is_some() {
            println!("  {} GeoIP enrichment active", "●".green());
        }
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
        "ssh" => {
            let shell_enabled = svc
                .options
                .get("shell_enabled")
                .map(|v| v == "true")
                .unwrap_or(false);
            Ok(Box::new(SshHoneypot::new(
                svc.banner.as_deref(),
                shell_enabled,
            )))
        }
        "http" => Ok(Box::new(HttpHoneypot::new())),
        "smb" => Ok(Box::new(SmbHoneypot::new())),
        "ftp" => Ok(Box::new(FtpHoneypot::new(svc.banner.as_deref()))),
        "telnet" => Ok(Box::new(TelnetHoneypot::new())),
        "rdp" => Ok(Box::new(RdpHoneypot::new())),
        "smtp" => Ok(Box::new(SmtpHoneypot::new(svc.banner.as_deref()))),
        "dns" => Ok(Box::new(DnsHoneypot::new())),
        "mysql" => Ok(Box::new(MysqlHoneypot::new())),
        "postgres" => Ok(Box::new(PostgresHoneypot::new())),
        other => anyhow::bail!("Unknown watch service protocol: {}", other),
    }
}
