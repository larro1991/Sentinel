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
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

/// Configuration for a single honeypot service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchServiceConfig {
    /// Protocol identifier: "ssh", "http", "smb", "ftp", "telnet", "rdp".
    pub protocol: String,
    /// TCP port to listen on.
    pub port: u16,
    /// Whether this listener is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional custom banner string (used by ssh, ftp).
    pub banner: Option<String>,
}

fn default_enabled() -> bool {
    true
}
