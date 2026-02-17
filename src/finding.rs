use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Severity levels for findings, ordered from most to least critical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Severity::Critical => "CRITICAL".red().bold().to_string(),
            Severity::High => "HIGH".red().to_string(),
            Severity::Medium => "MEDIUM".yellow().to_string(),
            Severity::Low => "LOW".blue().to_string(),
            Severity::Info => "INFO".white().to_string(),
        };
        write!(f, "{}", text)
    }
}

impl Severity {
    /// Return the plain (uncolored) label.
    pub fn label(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// A single security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub cwe_id: Option<String>,
    pub cve_ids: Vec<String>,
    pub affected_asset: String,
    pub affected_component: Option<String>,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub references: Vec<String>,
    pub module_name: String,
    pub timestamp: DateTime<Utc>,
}

/// Evidence attached to a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub content: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    HttpRequest,
    HttpResponse,
    Banner,
    Certificate,
    DnsRecord,
    PortScan,
    CommandOutput,
    Raw,
}

/// Summary statistics for a set of findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub deduplicated: usize,
}

/// Manages findings with deduplication.
#[derive(Debug, Clone)]
pub struct FindingsManager {
    findings: Vec<Finding>,
    seen_hashes: HashSet<String>,
    dedup_count: usize,
}

impl FindingsManager {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen_hashes: HashSet::new(),
            dedup_count: 0,
        }
    }

    /// Add a finding, deduplicating based on (title, affected_asset, cwe_id).
    pub fn add(&mut self, finding: Finding) {
        let dedup_key = format!(
            "{}|{}|{}",
            finding.title,
            finding.affected_asset,
            finding.cwe_id.as_deref().unwrap_or("none")
        );
        let mut hasher = Sha256::new();
        hasher.update(dedup_key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        if self.seen_hashes.contains(&hash) {
            self.dedup_count += 1;
            tracing::debug!("Duplicate finding skipped: {}", finding.title);
            return;
        }

        self.seen_hashes.insert(hash);
        tracing::info!(
            "Finding added: [{}] {} on {}",
            finding.severity.label(),
            finding.title,
            finding.affected_asset
        );
        self.findings.push(finding);
    }

    /// Get all findings.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Filter findings by severity.
    pub fn by_severity(&self, severity: &Severity) -> Vec<&Finding> {
        self.findings.iter().filter(|f| &f.severity == severity).collect()
    }

    /// Filter findings by affected asset.
    pub fn by_asset(&self, asset: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.affected_asset == asset).collect()
    }

    /// Compute summary statistics.
    pub fn stats(&self) -> FindingStats {
        FindingStats {
            total: self.findings.len(),
            critical: self.by_severity(&Severity::Critical).len(),
            high: self.by_severity(&Severity::High).len(),
            medium: self.by_severity(&Severity::Medium).len(),
            low: self.by_severity(&Severity::Low).len(),
            info: self.by_severity(&Severity::Info).len(),
            deduplicated: self.dedup_count,
        }
    }

    /// Save findings to a JSON file.
    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.findings)
            .context("Failed to serialize findings to JSON")?;
        std::fs::write(path, json)
            .with_context(|| format!("Failed to write findings to {}", path.display()))?;
        tracing::info!("Findings saved to {}", path.display());
        Ok(())
    }

    /// Load findings from a JSON file.
    pub fn load_json(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read findings from {}", path.display()))?;
        let findings: Vec<Finding> = serde_json::from_str(&data)
            .context("Failed to parse findings JSON")?;
        let mut manager = Self::new();
        for f in findings {
            manager.add(f);
        }
        Ok(manager)
    }
}

impl Default for FindingsManager {
    fn default() -> Self {
        Self::new()
    }
}
