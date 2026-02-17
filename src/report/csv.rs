use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::EngagementConfig;
use crate::finding::{FindingsManager, Severity};
use super::ReportGenerator;

/// Generates a CSV report of all findings.
pub struct CsvReport;

impl ReportGenerator for CsvReport {
    fn format_name(&self) -> &str {
        "csv"
    }

    fn generate(
        &self,
        _config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let mut csv = String::with_capacity(8192);

        // Header row
        csv.push_str("ID,Severity,Title,CVSS Score,CWE,CVEs,Affected Asset,Component,Description,Remediation,Module,Timestamp\n");

        // Findings sorted by severity (Critical first)
        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        for severity in &severity_order {
            let matching = findings.by_severity(severity);
            for finding in matching {
                let cvss_str = finding
                    .cvss_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_default();

                let cwe_str = finding.cwe_id.as_deref().unwrap_or("");

                let cves_str = finding.cve_ids.join("; ");

                let component_str = finding.affected_component.as_deref().unwrap_or("");

                let timestamp_str = finding
                    .timestamp
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string();

                csv.push_str(&csv_field(&finding.id));
                csv.push(',');
                csv.push_str(&csv_field(severity.label()));
                csv.push(',');
                csv.push_str(&csv_field(&finding.title));
                csv.push(',');
                csv.push_str(&csv_field(&cvss_str));
                csv.push(',');
                csv.push_str(&csv_field(cwe_str));
                csv.push(',');
                csv.push_str(&csv_field(&cves_str));
                csv.push(',');
                csv.push_str(&csv_field(&finding.affected_asset));
                csv.push(',');
                csv.push_str(&csv_field(component_str));
                csv.push(',');
                csv.push_str(&csv_field(&finding.description));
                csv.push(',');
                csv.push_str(&csv_field(&finding.remediation));
                csv.push(',');
                csv.push_str(&csv_field(&finding.module_name));
                csv.push(',');
                csv.push_str(&csv_field(&timestamp_str));
                csv.push('\n');
            }
        }

        // Write file
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

        let path = output_dir.join("report.csv");
        std::fs::write(&path, &csv)
            .with_context(|| format!("Failed to write CSV report to {}", path.display()))?;

        tracing::info!("CSV report written to {}", path.display());
        Ok(path)
    }
}

/// Encode a single CSV field according to RFC 4180:
///
/// - If the field contains a comma, double-quote, or newline, wrap it in double
///   quotes and escape any inner double-quotes by doubling them.
/// - Otherwise return the field as-is.
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        value.to_string()
    }
}
