use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level engagement configuration, typically loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementConfig {
    pub id: String,
    pub name: String,
    pub scope: ScopeConfig,
    pub authorization: AuthorizationConfig,
    pub rate_limit_per_second: Option<u32>,
    pub emergency_contact: String,
    /// Path to the Rules of Engagement document.
    pub roe_document: Option<String>,
    pub output_dir: String,
    /// Module selection — which recon and vuln modules to run.
    /// If omitted, all modules are enabled.
    #[serde(default)]
    pub modules: Option<ModuleConfig>,
    /// Port scan configuration.
    #[serde(default)]
    pub port_scan: Option<PortScanConfig>,
    /// Report output formats. If omitted, all formats are generated.
    #[serde(default)]
    pub report_formats: Option<Vec<String>>,
    /// Watch mode (honeypot / passive defense) configuration.
    #[serde(default)]
    pub watch: Option<WatchConfig>,
}

/// Controls which modules are enabled for the engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Recon module names to enable. If omitted, all recon modules run.
    pub recon: Option<Vec<String>>,
    /// Vuln check names to enable. If omitted, all vuln checks run.
    pub vuln: Option<Vec<String>>,
}

/// Port scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    /// Port profile: "quick" (32 ports), "standard" (100 ports), "thorough" (1000 ports), or "custom".
    #[serde(default = "default_port_profile")]
    pub profile: String,
    /// Custom port list (used when profile is "custom").
    pub ports: Option<Vec<u16>>,
    /// Connection timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Max concurrent connections.
    pub concurrency: Option<usize>,
}

fn default_port_profile() -> String {
    "quick".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// CIDR ranges or hostnames that are in scope.
    pub targets: Vec<String>,
    /// CIDR ranges or hostnames that must never be touched.
    pub exclusions: Vec<String>,
    pub time_windows: Vec<TimeWindowConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindowConfig {
    /// Start time in "HH:MM" format.
    pub start: String,
    /// End time in "HH:MM" format.
    pub end: String,
    /// Days of the week this window applies to, e.g. ["Mon","Tue"]. None means all days.
    pub days: Option<Vec<String>>,
    /// Timezone name. Defaults to UTC if not specified.
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationConfig {
    /// Maximum authorization level: "passive", "scanning", "verification", "exploitation", "post_exploit".
    pub max_level: String,
    /// Operations up to this level are automatically approved without prompting.
    pub auto_approve_up_to: Option<String>,
}

impl EngagementConfig {
    /// Load an engagement configuration from a YAML file at the given path.
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        let config: Self = serde_yaml::from_str(&contents)
            .with_context(|| format!("Failed to parse YAML config: {}", path))?;
        Ok(config)
    }

    /// Validate that required fields are present and sensible.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            bail!("Engagement config: 'id' must not be empty");
        }
        if self.name.is_empty() {
            bail!("Engagement config: 'name' must not be empty");
        }
        if self.scope.targets.is_empty() {
            bail!("Engagement config: 'scope.targets' must contain at least one target");
        }
        if self.emergency_contact.is_empty() {
            bail!("Engagement config: 'emergency_contact' must not be empty");
        }
        if self.output_dir.is_empty() {
            bail!("Engagement config: 'output_dir' must not be empty");
        }

        // Validate authorization level string parses correctly.
        crate::auth::AuthorizationLevel::from_str_loose(&self.authorization.max_level)
            .context("Invalid authorization.max_level")?;

        if let Some(ref auto) = self.authorization.auto_approve_up_to {
            crate::auth::AuthorizationLevel::from_str_loose(auto)
                .context("Invalid authorization.auto_approve_up_to")?;
        }

        // Validate time window formats.
        for (i, tw) in self.scope.time_windows.iter().enumerate() {
            chrono::NaiveTime::parse_from_str(&tw.start, "%H:%M")
                .with_context(|| format!("Invalid start time in time_window[{}]: '{}'", i, tw.start))?;
            chrono::NaiveTime::parse_from_str(&tw.end, "%H:%M")
                .with_context(|| format!("Invalid end time in time_window[{}]: '{}'", i, tw.end))?;
        }

        Ok(())
    }
}

// ── Watch Mode Configuration ──────────────────────────────────────────────────

/// Top-level watch mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    /// Address to bind all listeners on, e.g. "0.0.0.0".
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Path to the NDJSON alert file. Defaults to "./results/watch-events.jsonl".
    pub alert_file: Option<String>,
    /// List of honeypot services to run.
    #[serde(default)]
    pub services: Vec<WatchServiceConfig>,
    /// Scope filter for dropping or tagging events from excluded IPs.
    #[serde(default)]
    pub scope_filter: Option<WatchScopeFilterConfig>,
    /// Per-source-IP event rate limiting.
    #[serde(default)]
    pub rate_limit: Option<WatchRateLimitConfig>,
    /// Webhook alert sinks (Slack, generic URL).
    #[serde(default)]
    pub webhooks: Vec<WebhookSinkConfig>,
    /// GeoIP enrichment provider.
    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,
    /// Live dashboard configuration.
    #[serde(default)]
    pub dashboard: Option<DashboardConfig>,
    /// Log file rotation settings.
    #[serde(default)]
    pub log_rotation: Option<LogRotationConfig>,
    /// Threat intelligence enrichment.
    #[serde(default)]
    pub threat_intel: Option<ThreatIntelConfig>,
    /// Syslog/CEF export.
    #[serde(default)]
    pub syslog: Option<SyslogConfig>,
    /// Path to the SQLite database for event persistence.
    #[serde(default)]
    pub database: Option<String>,
    /// Path to correlation rules YAML file.
    #[serde(default)]
    pub correlation_rules: Option<String>,
    /// REST API configuration.
    #[serde(default)]
    pub api: Option<ApiConfig>,
    /// Deduplication time window in seconds.
    #[serde(default)]
    pub dedup_window_secs: Option<u64>,
}

/// REST API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Port for the API server (default: 9091).
    #[serde(default = "default_api_port")]
    pub port: u16,
    /// Bind address for the API server (default: "0.0.0.0").
    #[serde(default = "default_api_bind")]
    pub bind_address: String,
}

fn default_api_port() -> u16 {
    9091
}

fn default_api_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

/// Configuration for a single honeypot service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchServiceConfig {
    /// Protocol identifier: "ssh", "http", "smb", "ftp", "telnet", "rdp", "smtp", "dns", "mysql", "postgres".
    pub protocol: String,
    /// TCP (or UDP for DNS) port to listen on.
    pub port: u16,
    /// Whether this listener is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional custom banner string (used by ssh, ftp).
    pub banner: Option<String>,
    /// Per-protocol key-value options (e.g., shell_enabled: "true" for SSH).
    #[serde(default)]
    pub options: HashMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

/// Controls whether events from IPs outside the engagement scope are dropped or tagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchScopeFilterConfig {
    /// "drop" — silently discard events; "tag" — add an out_of_scope detail.
    #[serde(default = "default_scope_action")]
    pub action: String,
}

fn default_scope_action() -> String {
    "tag".to_string()
}

/// Per-source-IP sliding-window rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRateLimitConfig {
    /// Maximum number of events per IP within the window.
    #[serde(default = "default_max_events")]
    pub max_events_per_ip: u64,
    /// Window duration in seconds.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_max_events() -> u64 {
    100
}

fn default_window_secs() -> u64 {
    60
}

/// Webhook sink — POST JSON alerts to a URL (Slack, generic endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSinkConfig {
    /// Target URL to POST events to.
    pub url: String,
    /// Friendly name for logging.
    #[serde(default = "default_webhook_name")]
    pub name: String,
    /// Minimum severity to forward (Critical, High, Medium, Low, Info).
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
}

fn default_webhook_name() -> String {
    "webhook".to_string()
}

fn default_min_severity() -> String {
    "Info".to_string()
}

/// GeoIP enrichment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Provider: "ip-api" (default, free).
    #[serde(default = "default_geo_provider")]
    pub provider: String,
    /// Maximum number of cached lookups.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_geo_provider() -> String {
    "ip-api".to_string()
}

fn default_cache_size() -> usize {
    10_000
}

/// Live dashboard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// HTTP port for the dashboard server.
    #[serde(default = "default_dashboard_port")]
    pub port: u16,
    /// Bind address for the dashboard.
    #[serde(default = "default_dashboard_bind")]
    pub bind_address: String,
}

fn default_dashboard_port() -> u16 {
    9090
}

fn default_dashboard_bind() -> String {
    "0.0.0.0".to_string()
}

/// NDJSON log file rotation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum size of a single log file in bytes before rotation.
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
    /// Maximum number of rotated files to keep.
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

fn default_max_size_bytes() -> u64 {
    50 * 1024 * 1024 // 50 MiB
}

fn default_max_files() -> u32 {
    10
}

/// Threat intelligence enrichment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Whether threat intel enrichment is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Provider: "abuseipdb" (default).
    #[serde(default = "default_threat_intel_provider")]
    pub provider: String,
    /// API key for the provider.
    #[serde(default)]
    pub api_key: String,
    /// Maximum number of cached lookups.
    #[serde(default = "default_threat_intel_cache_size")]
    pub cache_size: usize,
}

fn default_threat_intel_provider() -> String {
    "abuseipdb".to_string()
}

fn default_threat_intel_cache_size() -> usize {
    5_000
}

/// Syslog / CEF export configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Output format: "cef" (default).
    #[serde(default = "default_syslog_format")]
    pub format: String,
    /// Output mode: "file" or "udp".
    #[serde(default = "default_syslog_output")]
    pub output: String,
    /// File path (used when output is "file").
    pub path: Option<String>,
    /// Remote syslog host (used when output is "udp").
    pub host: Option<String>,
    /// Remote syslog port (used when output is "udp").
    pub port: Option<u16>,
}

fn default_syslog_format() -> String {
    "cef".to_string()
}

fn default_syslog_output() -> String {
    "file".to_string()
}
