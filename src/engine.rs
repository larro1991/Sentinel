use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

use crate::config::EngagementConfig;
use crate::finding::FindingsManager;
use crate::recon::{ReconData, ReconModule, ReconResult};
use crate::scope::ScopeValidator;
use crate::vuln::{Service, VulnCheck};

/// The current phase of the engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnginePhase {
    Setup,
    Recon,
    VulnScan,
    Reporting,
    Complete,
}

/// Summary of a completed engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementResult {
    pub findings_count: usize,
    pub duration_secs: f64,
    pub targets_scanned: usize,
    pub phase_reached: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

/// Simple token-bucket rate limiter.
struct RateLimiter {
    semaphore: Arc<Semaphore>,
    rate_per_sec: u32,
}

impl RateLimiter {
    fn new(rate_per_sec: u32) -> Self {
        let permits = rate_per_sec.max(1) as usize;
        Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            rate_per_sec,
        }
    }

    /// Acquire a rate-limit token. Blocks until one is available.
    async fn acquire(&self) {
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();
        let delay = Duration::from_secs_f64(1.0 / self.rate_per_sec as f64);
        // Release the permit after the rate window.
        tokio::spawn(async move {
            sleep(delay).await;
            drop(permit);
        });
    }
}

/// The engagement execution engine coordinates recon, vulnerability scanning,
/// and reporting across all in-scope targets.
pub struct Engine {
    config: EngagementConfig,
    scope: ScopeValidator,
    findings: FindingsManager,
    phase: EnginePhase,
    recon_modules: Vec<Box<dyn ReconModule>>,
    vuln_modules: Vec<Box<dyn VulnCheck>>,
    emergency_stopped: bool,
    recon_results: Vec<ReconResult>,
    rate_limiter: Option<RateLimiter>,
}

impl Engine {
    /// Create a new engine from an engagement configuration.
    pub fn new(config: EngagementConfig) -> Result<Self> {
        config.validate().context("Configuration validation failed")?;

        let scope = ScopeValidator::new(&config.scope, &config.authorization)
            .map_err(|e| anyhow::anyhow!("Scope validation setup failed: {}", e))?;

        let rate_limiter = config.rate_limit_per_second.map(RateLimiter::new);

        Ok(Self {
            config,
            scope,
            findings: FindingsManager::new(),
            phase: EnginePhase::Setup,
            recon_modules: Vec::new(),
            vuln_modules: Vec::new(),
            emergency_stopped: false,
            recon_results: Vec::new(),
            rate_limiter,
        })
    }

    /// Register a recon module to be executed during the recon phase.
    pub fn register_recon(&mut self, module: Box<dyn ReconModule>) {
        tracing::info!("Registered recon module: {}", module.name());
        self.recon_modules.push(module);
    }

    /// Register a vulnerability check module.
    pub fn register_vuln(&mut self, module: Box<dyn VulnCheck>) {
        tracing::info!("Registered vuln check: {}", module.name());
        self.vuln_modules.push(module);
    }

    /// Expand CIDR ranges in the target list into individual IP addresses.
    /// Hostnames pass through unchanged. CIDR ranges larger than /16 are skipped.
    fn expand_targets(targets: &[String]) -> Vec<String> {
        let mut expanded = Vec::new();
        for target in targets {
            if let Ok(net) = target.parse::<IpNet>() {
                // Only expand if the range is reasonable (max /16 = 65536 hosts).
                let host_count = net.hosts().count();
                if host_count > 65536 {
                    tracing::warn!(
                        "CIDR range {} has {} hosts (> 65536), scanning network as-is",
                        target, host_count
                    );
                    expanded.push(target.clone());
                } else if host_count > 1 {
                    tracing::info!("Expanding CIDR {} -> {} hosts", target, host_count);
                    for addr in net.hosts() {
                        expanded.push(addr.to_string());
                    }
                } else {
                    // Single IP in CIDR notation.
                    expanded.push(net.addr().to_string());
                }
            } else if let Ok(addr) = target.parse::<IpAddr>() {
                expanded.push(addr.to_string());
            } else {
                // Hostname — pass through.
                expanded.push(target.clone());
            }
        }
        expanded
    }

    /// Run the full engagement: recon -> vuln scan -> results.
    pub async fn run(&mut self) -> Result<EngagementResult> {
        let start_time = Instant::now();
        let started_at = Utc::now();

        tracing::info!(
            "=== Engagement '{}' ({}) starting ===",
            self.config.name,
            self.config.id
        );

        // Expand CIDR targets.
        let expanded_targets = Self::expand_targets(&self.config.scope.targets);
        tracing::info!("Targets: {} ({} expanded)", self.config.scope.targets.len(), expanded_targets.len());
        tracing::info!(
            "Authorization level: {}",
            self.config.authorization.max_level
        );
        if let Some(ref rl) = self.rate_limiter {
            tracing::info!("Rate limit: {} ops/sec", rl.rate_per_sec);
        }

        // Validate time window before starting.
        if let Err(e) = self.scope.validate_time() {
            bail!("Cannot start engagement: {}", e);
        }

        // Phase 1: Recon (runs against expanded targets)
        self.phase = EnginePhase::Recon;
        tracing::info!("--- Phase: Reconnaissance ---");

        if let Err(e) = self.run_recon_targets(&expanded_targets).await {
            tracing::error!("Recon phase encountered errors: {}", e);
        }

        if self.emergency_stopped {
            return Ok(self.build_result(start_time, started_at));
        }

        // Convert recon results into Service structs for vuln scanning.
        let services = self.extract_services();
        tracing::info!("Discovered {} services across all targets", services.len());

        // Phase 2: Vulnerability scanning
        self.phase = EnginePhase::VulnScan;
        tracing::info!("--- Phase: Vulnerability Scanning ---");

        if let Err(e) = self.run_vulns(&services).await {
            tracing::error!("Vuln scan phase encountered errors: {}", e);
        }

        // Phase 3: Reporting
        self.phase = EnginePhase::Reporting;
        tracing::info!("--- Phase: Reporting ---");

        self.phase = EnginePhase::Complete;
        tracing::info!(
            "=== Engagement complete: {} findings in {:.1}s ===",
            self.findings.findings().len(),
            start_time.elapsed().as_secs_f64()
        );

        Ok(self.build_result(start_time, started_at))
    }

    /// Execute each recon module against each target (uses config targets).
    pub async fn run_recon(&mut self) -> Result<()> {
        let targets = self.config.scope.targets.clone();
        self.run_recon_targets(&targets).await
    }

    /// Execute each recon module against the given target list.
    async fn run_recon_targets(&mut self, targets: &[String]) -> Result<()> {
        // Get enabled recon modules from config.
        let enabled_recon = self.config.modules.as_ref().and_then(|m| m.recon.as_ref());

        for target in targets {
            if self.emergency_stopped {
                tracing::warn!("Emergency stop -- skipping remaining targets");
                break;
            }

            // Validate target scope before scanning.
            let auth_level_passive = crate::auth::AuthorizationLevel::Passive;
            if let Err(e) = self.scope.validate_all(target, auth_level_passive) {
                tracing::warn!("Target '{}' failed scope validation: {}", target, e);
                continue;
            }

            tracing::info!("Scanning target: {}", target);

            for i in 0..self.recon_modules.len() {
                if self.emergency_stopped {
                    break;
                }

                let auth_level = self.recon_modules[i].authorization_level();
                let module_name = self.recon_modules[i].name().to_string();

                // Check if this module is enabled in config.
                if let Some(enabled) = enabled_recon {
                    if !enabled.iter().any(|e| e == &module_name) {
                        continue;
                    }
                }

                // Validate authorization for this module.
                if let Err(e) = self.scope.validate_authorization(auth_level) {
                    tracing::warn!(
                        "Skipping module '{}' for '{}': {}",
                        module_name,
                        target,
                        e
                    );
                    continue;
                }

                // Rate limit if configured.
                if let Some(ref limiter) = self.rate_limiter {
                    limiter.acquire().await;
                }

                tracing::info!(
                    "Running module '{}' against '{}'",
                    module_name,
                    target
                );

                match self.recon_modules[i].execute(target).await {
                    Ok(result) => {
                        tracing::info!(
                            "Module '{}' completed for '{}'",
                            module_name,
                            target
                        );
                        self.recon_results.push(result);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Module '{}' failed for '{}': {}",
                            module_name,
                            target,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute each vulnerability check against discovered services.
    pub async fn run_vulns(&mut self, services: &[Service]) -> Result<()> {
        // Get enabled vuln modules from config.
        let enabled_vuln = self.config.modules.as_ref().and_then(|m| m.vuln.as_ref());

        for service in services {
            if self.emergency_stopped {
                tracing::warn!("Emergency stop -- skipping remaining services");
                break;
            }

            let target_str = format!("{}:{}", service.host, service.port);

            // Validate scope for this service.
            if let Err(e) = self.scope.validate_all(
                &service.host,
                crate::auth::AuthorizationLevel::Scanning,
            ) {
                tracing::warn!(
                    "Service '{}' failed scope validation: {}",
                    target_str,
                    e
                );
                continue;
            }

            for i in 0..self.vuln_modules.len() {
                if self.emergency_stopped {
                    break;
                }

                // Check if this module applies to this service.
                if !self.vuln_modules[i].applies_to(service) {
                    continue;
                }

                let auth_level = self.vuln_modules[i].authorization_level();
                let check_name = self.vuln_modules[i].name().to_string();

                // Check if this module is enabled in config.
                if let Some(enabled) = enabled_vuln {
                    if !enabled.iter().any(|e| e == &check_name) {
                        continue;
                    }
                }

                // Validate authorization.
                if let Err(e) = self.scope.validate_authorization(auth_level) {
                    tracing::warn!(
                        "Skipping check '{}' for '{}': {}",
                        check_name,
                        target_str,
                        e
                    );
                    continue;
                }

                // Rate limit if configured.
                if let Some(ref limiter) = self.rate_limiter {
                    limiter.acquire().await;
                }

                tracing::info!(
                    "Running check '{}' against '{}'",
                    check_name,
                    target_str
                );

                match self.vuln_modules[i].check(service).await {
                    Ok(new_findings) => {
                        for finding in new_findings {
                            self.findings.add(finding);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Check '{}' failed for '{}': {}",
                            check_name,
                            target_str,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Signal an emergency stop for the engagement.
    pub fn emergency_stop(&mut self, reason: &str) {
        tracing::error!("!!! EMERGENCY STOP: {} !!!", reason);
        tracing::error!(
            "Emergency contact: {}",
            self.config.emergency_contact
        );
        self.emergency_stopped = true;
    }

    /// Get a reference to the findings manager.
    pub fn results(&self) -> &FindingsManager {
        &self.findings
    }

    /// Get the engagement configuration.
    pub fn config(&self) -> &EngagementConfig {
        &self.config
    }

    /// Get collected recon results.
    pub fn recon_results(&self) -> &[ReconResult] {
        &self.recon_results
    }

    /// Extract Service structs from collected recon results.
    fn extract_services(&self) -> Vec<Service> {
        let mut services = Vec::new();

        for result in &self.recon_results {
            match &result.data {
                ReconData::OpenPorts(ports) => {
                    for port in ports {
                        if port.state == "open" {
                            let tls = matches!(
                                port.port,
                                443 | 8443 | 993 | 995 | 465 | 636 | 5986
                            );
                            services.push(Service {
                                host: result.target.clone(),
                                port: port.port,
                                service_name: port
                                    .service
                                    .clone()
                                    .unwrap_or_else(|| "unknown".to_string()),
                                version: None,
                                banner: port.banner.clone(),
                                tls,
                            });
                        }
                    }
                }
                ReconData::ServiceInfo(infos) => {
                    for info in infos {
                        services.push(Service {
                            host: result.target.clone(),
                            port: info.port,
                            service_name: info.service_name.clone(),
                            version: info.version.clone(),
                            banner: info.banner.clone(),
                            tls: info.tls,
                        });
                    }
                }
                ReconData::DnsRecords(_) => {
                    // DNS records don't directly produce services.
                }
            }
        }

        // Deduplicate services by (host, port) — prefer entries with more info.
        services.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then(a.port.cmp(&b.port))
        });
        services.dedup_by(|a, b| a.host == b.host && a.port == b.port);

        services
    }

    fn build_result(&self, start_time: Instant, started_at: DateTime<Utc>) -> EngagementResult {
        EngagementResult {
            findings_count: self.findings.findings().len(),
            duration_secs: start_time.elapsed().as_secs_f64(),
            targets_scanned: self.config.scope.targets.len(),
            phase_reached: format!("{:?}", self.phase),
            started_at,
            completed_at: Utc::now(),
        }
    }
}
