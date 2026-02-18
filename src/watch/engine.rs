use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::sync::{mpsc, watch, Mutex};

use crate::api::{self, ApiState};
use crate::config::{
    AuthorizationConfig, ScopeConfig, WatchConfig, WatchServiceConfig,
};
use crate::scope::ScopeValidator;
use crate::store::EventStore;

use super::alert::{AlertSink, ConsoleSink, JsonFileSink, RotatingJsonFileSink};
use super::correlation::{self, CorrelatedAlert, CorrelationEngine};
use super::dashboard::DashboardSink;
use super::dedup::EventDeduplicator;
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
use super::sqlite_sink::SqliteSink;
use super::ssh::SshHoneypot;
use super::syslog::SyslogSink;
use super::telnet::TelnetHoneypot;
use super::threat_intel::{AbuseIpDbProvider, ThreatIntelProvider};
use super::tls::TlsHoneypot;
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
    threat_intel_provider: Option<Arc<dyn ThreatIntelProvider>>,
    scope_action: String,
    store: Option<EventStore>,
    dedup_window_secs: Option<u64>,
    correlation_rules_path: Option<String>,
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

        // Syslog sink.
        if let Some(ref syslog_config) = config.syslog {
            match syslog_config.output.as_str() {
                "udp" => {
                    let host = syslog_config.host.as_deref().unwrap_or("127.0.0.1");
                    let port = syslog_config.port.unwrap_or(514);
                    match SyslogSink::new_udp(host, port).await {
                        Ok(sink) => sinks.push(Arc::new(sink)),
                        Err(e) => tracing::warn!("Failed to initialize syslog UDP sink: {}", e),
                    }
                }
                _ => {
                    let path = syslog_config
                        .path
                        .as_deref()
                        .unwrap_or("./results/watch-events.cef");
                    match SyslogSink::new_file(std::path::Path::new(path)).await {
                        Ok(sink) => sinks.push(Arc::new(sink)),
                        Err(e) => tracing::warn!("Failed to initialize syslog file sink: {}", e),
                    }
                }
            }
        }

        // Dashboard sink.
        let listener_count = listeners.len() as u32;
        if let Some(ref dash_config) = config.dashboard {
            let dashboard_sink = DashboardSink::new(
                &dash_config.bind_address,
                dash_config.port,
                listener_count,
            );
            sinks.push(Arc::new(dashboard_sink));
        }

        // SQLite event store + sink.
        let store = if let Some(ref db_path) = config.database {
            match EventStore::open(db_path).await {
                Ok(store) => {
                    sinks.push(Arc::new(SqliteSink::new(store.clone())));
                    tracing::info!("SQLite event store opened: {}", db_path);
                    Some(store)
                }
                Err(e) => {
                    tracing::warn!("Failed to open SQLite store at {}: {}", db_path, e);
                    None
                }
            }
        } else {
            None
        };

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

        // Threat intelligence provider.
        let threat_intel_provider: Option<Arc<dyn ThreatIntelProvider>> =
            config.threat_intel.as_ref().and_then(|ti| {
                if !ti.enabled || ti.api_key.is_empty() {
                    None
                } else {
                    Some(Arc::new(AbuseIpDbProvider::new(&ti.api_key, ti.cache_size))
                        as Arc<dyn ThreatIntelProvider>)
                }
            });

        Ok(Self {
            config: config.clone(),
            listeners,
            sinks,
            scope_validator,
            rate_limiter,
            geo_provider,
            threat_intel_provider,
            scope_action,
            store,
            dedup_window_secs: config.dedup_window_secs,
            correlation_rules_path: config.correlation_rules.clone(),
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

        // Set up correlation engine.
        let (corr_tx, mut corr_rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
        let rules = if let Some(ref path) = self.correlation_rules_path {
            match correlation::load_rules(path) {
                Ok(r) => {
                    tracing::info!("Loaded {} correlation rules from {}", r.len(), path);
                    r
                }
                Err(e) => {
                    tracing::warn!("Failed to load correlation rules from {}: {} — using defaults", path, e);
                    correlation::default_rules()
                }
            }
        } else {
            correlation::default_rules()
        };
        let correlation_engine = Arc::new(Mutex::new(CorrelationEngine::new(rules, corr_tx)));

        // Set up deduplicator.
        let deduplicator = self
            .dedup_window_secs
            .map(|secs| Arc::new(Mutex::new(EventDeduplicator::new(secs))));

        // Spawn API server if configured.
        if let Some(ref api_config) = self.config.api {
            if let Some(ref store) = self.store {
                let state = ApiState {
                    store: store.clone(),
                };
                let bind = api_config.bind_address.clone();
                let port = api_config.port;
                tokio::spawn(async move {
                    if let Err(e) = api::serve(&bind, port, state).await {
                        tracing::error!("REST API server error: {}", e);
                    }
                });
            }
        }

        // Spawn correlation alert consumer.
        let store_for_corr = self.store.clone();
        let corr_consumer = tokio::spawn(async move {
            while let Some(alert) = corr_rx.recv().await {
                tracing::warn!(
                    "CORRELATION [{}] {} from {} — {} events",
                    alert.severity.to_uppercase(),
                    alert.rule_name,
                    alert.source_ip,
                    alert.count,
                );
                // Persist to SQLite if available.
                if let Some(ref store) = store_for_corr {
                    let row = crate::store::CorrelationRow {
                        rule_name: alert.rule_name,
                        severity: alert.severity,
                        source_ip: alert.source_ip,
                        trigger_event_ids: alert.trigger_event_ids,
                        event_count: alert.count,
                        window_start: alert.window_start.to_rfc3339(),
                        window_end: alert.window_end.to_rfc3339(),
                        created_at: alert.created_at.to_rfc3339(),
                    };
                    if let Err(e) = store.insert_correlation(&row).await {
                        tracing::error!("Failed to persist correlation: {}", e);
                    }
                }
            }
        });

        // Spawn periodic prune task for correlation engine.
        let corr_engine_prune = correlation_engine.clone();
        let mut shutdown_prune = shutdown_rx.clone();
        let prune_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                        corr_engine_prune.lock().await.prune();
                    }
                    _ = shutdown_prune.changed() => {
                        break;
                    }
                }
            }
        });

        let sinks = Arc::new(self.sinks);
        let scope_validator = self.scope_validator.clone();
        let rate_limiter = self.rate_limiter.clone();
        let geo_provider = self.geo_provider.clone();
        let threat_intel_provider = self.threat_intel_provider.clone();
        let scope_action = self.scope_action.clone();

        // Event dispatch loop with enrichment pipeline.
        let sinks_clone = sinks.clone();
        let corr_engine = correlation_engine.clone();
        let dedup = deduplicator.clone();
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

                // 2.5. Deduplication
                if let Some(ref dedup) = dedup {
                    let result = dedup.lock().await.process(event.clone());
                    match result {
                        Some(deduped) => event = deduped,
                        None => continue,
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

                // 4. Threat intelligence enrichment
                if let Some(ref ti) = threat_intel_provider {
                    if let Ok(info) = ti.lookup(&event.source_ip).await {
                        if let Some(score) = info.abuse_score {
                            event
                                .details
                                .insert("threat_score".to_string(), score.to_string());
                        }
                        if info.is_malicious {
                            event
                                .details
                                .insert("threat_malicious".to_string(), "true".to_string());
                        }
                        if !info.threat_categories.is_empty() {
                            event.details.insert(
                                "threat_categories".to_string(),
                                info.threat_categories.join(", "),
                            );
                        }
                    }
                }

                // 5. Dispatch to all sinks
                for sink in sinks_clone.iter() {
                    if let Err(e) = sink.emit(&event).await {
                        tracing::error!("[{}] Sink error: {}", sink.name(), e);
                    }
                }

                // 6. Correlation engine
                corr_engine.lock().await.process(&event);
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

        // Flush deduplicator.
        if let Some(ref dedup) = deduplicator {
            let flushed = dedup.lock().await.flush();
            if !flushed.is_empty() {
                tracing::info!("Flushing {} accumulated dedup events", flushed.len());
                for event in &flushed {
                    for sink in sinks.iter() {
                        let _ = sink.emit(event).await;
                    }
                }
            }
        }

        // Wait for dispatch to drain remaining events.
        let _ = dispatch_handle.await;

        // Clean up background tasks.
        prune_handle.abort();
        corr_consumer.abort();

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

        if self.store.is_some() {
            let db_path = self.config.database.as_deref().unwrap_or("sentinel.db");
            println!(
                "{} Events persisted to {}",
                "Done.".green().bold(),
                db_path,
            );
        }

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
        if self.threat_intel_provider.is_some() {
            println!("  {} Threat intelligence active", "●".green());
        }
        if self.store.is_some() {
            println!("  {} SQLite persistence active", "●".green());
        }
        if self.dedup_window_secs.is_some() {
            println!("  {} Event deduplication active", "●".green());
        }
        if self.correlation_rules_path.is_some() || self.store.is_some() {
            println!("  {} Correlation engine active", "●".green());
        }
        if self.config.api.is_some() && self.store.is_some() {
            let api = self.config.api.as_ref().unwrap();
            println!(
                "  {} REST API on http://{}:{}",
                "●".green(),
                api.bind_address,
                api.port
            );
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
        "tls" => Ok(Box::new(TlsHoneypot::new())),
        other => anyhow::bail!("Unknown watch service protocol: {}", other),
    }
}
