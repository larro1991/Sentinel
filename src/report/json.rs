use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::EngagementConfig;
use crate::finding::{Finding, FindingStats, FindingsManager};
use super::ReportGenerator;

/// Structured JSON representation of the full engagement report.
#[derive(Debug, Serialize)]
struct JsonReportData {
    engagement: EngagementSummary,
    findings: Vec<Finding>,
    statistics: FindingStats,
    generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct EngagementSummary {
    id: String,
    name: String,
    targets: Vec<String>,
    exclusions: Vec<String>,
    authorization_level: String,
    emergency_contact: String,
}

/// Generates a structured JSON report of the engagement.
pub struct JsonReport;

impl ReportGenerator for JsonReport {
    fn format_name(&self) -> &str {
        "json"
    }

    fn generate(
        &self,
        config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let report = JsonReportData {
            engagement: EngagementSummary {
                id: config.id.clone(),
                name: config.name.clone(),
                targets: config.scope.targets.clone(),
                exclusions: config.scope.exclusions.clone(),
                authorization_level: config.authorization.max_level.clone(),
                emergency_contact: config.emergency_contact.clone(),
            },
            findings: findings.findings().to_vec(),
            statistics: findings.stats(),
            generated_at: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&report)
            .context("Failed to serialize report to JSON")?;

        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

        let path = output_dir.join("report.json");
        std::fs::write(&path, &json)
            .with_context(|| format!("Failed to write report to {}", path.display()))?;

        tracing::info!("JSON report written to {}", path.display());
        Ok(path)
    }
}
