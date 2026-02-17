use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::config::EngagementConfig;
use crate::finding::{FindingsManager, Severity};
use super::ReportGenerator;

/// Generates a professional Markdown security assessment report.
pub struct MarkdownReport;

impl ReportGenerator for MarkdownReport {
    fn format_name(&self) -> &str {
        "markdown"
    }

    fn generate(
        &self,
        config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let stats = findings.stats();
        let date = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

        // Determine overall risk rating based on highest severity found.
        let risk_rating = if stats.critical > 0 {
            "CRITICAL"
        } else if stats.high > 0 {
            "HIGH"
        } else if stats.medium > 0 {
            "MEDIUM"
        } else if stats.low > 0 {
            "LOW"
        } else {
            "MINIMAL"
        };

        let targets_str = config.scope.targets.join(", ");
        let exclusions_str = if config.scope.exclusions.is_empty() {
            "None".to_string()
        } else {
            config.scope.exclusions.join(", ")
        };

        let mut report = String::new();

        // Title
        report.push_str("# Security Assessment Report\n\n");
        report.push_str(&format!("**Engagement:** {}\n\n", config.name));
        report.push_str(&format!("**Engagement ID:** {}\n\n", config.id));
        report.push_str(&format!("**Date:** {}\n\n", date));
        report.push_str(&format!("**Scope:** {}\n\n", targets_str));
        report.push_str(&format!(
            "**Authorization Level:** {}\n\n",
            config.authorization.max_level
        ));
        report.push_str(&format!(
            "**Emergency Contact:** {}\n\n",
            config.emergency_contact
        ));
        report.push_str("---\n\n");

        // Executive Summary
        report.push_str("## Executive Summary\n\n");
        report.push_str(&format!("- **Total findings:** {}\n", stats.total));
        report.push_str(&format!(
            "- **Critical:** {} | **High:** {} | **Medium:** {} | **Low:** {} | **Info:** {}\n",
            stats.critical, stats.high, stats.medium, stats.low, stats.info
        ));
        if stats.deduplicated > 0 {
            report.push_str(&format!(
                "- **Deduplicated:** {} duplicate findings removed\n",
                stats.deduplicated
            ));
        }
        report.push_str(&format!("- **Risk Rating:** {}\n", risk_rating));
        report.push_str("\n---\n\n");

        // Findings — sorted by severity (Critical first)
        report.push_str("## Findings\n\n");

        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        let mut finding_number = 0;
        for severity in &severity_order {
            let matching = findings.by_severity(severity);
            for finding in matching {
                finding_number += 1;
                report.push_str(&format!(
                    "### {}.  [{}] {}\n\n",
                    finding_number,
                    severity.label(),
                    finding.title
                ));

                report.push_str(&format!("**Asset:** {}\n\n", finding.affected_asset));

                if let Some(ref component) = finding.affected_component {
                    report.push_str(&format!("**Component:** {}\n\n", component));
                }

                if let Some(score) = finding.cvss_score {
                    let vector_str = finding
                        .cvss_vector
                        .as_deref()
                        .map(|v| format!(" ({})", v))
                        .unwrap_or_default();
                    report.push_str(&format!("**CVSS:** {}{}\n\n", score, vector_str));
                }

                if let Some(ref cwe) = finding.cwe_id {
                    report.push_str(&format!("**CWE:** {}\n\n", cwe));
                }

                if !finding.cve_ids.is_empty() {
                    report.push_str(&format!("**CVE:** {}\n\n", finding.cve_ids.join(", ")));
                }

                report.push_str("**Description:**\n\n");
                report.push_str(&finding.description);
                report.push_str("\n\n");

                if !finding.evidence.is_empty() {
                    report.push_str("**Evidence:**\n\n");
                    for ev in &finding.evidence {
                        if let Some(ref label) = ev.label {
                            report.push_str(&format!("*{}:*\n\n", label));
                        }
                        report.push_str("```\n");
                        report.push_str(&ev.content);
                        report.push_str("\n```\n\n");
                    }
                }

                report.push_str("**Remediation:**\n\n");
                report.push_str(&finding.remediation);
                report.push_str("\n\n");

                if !finding.references.is_empty() {
                    report.push_str("**References:**\n\n");
                    for r in &finding.references {
                        report.push_str(&format!("- {}\n", r));
                    }
                    report.push_str("\n");
                }

                report.push_str("---\n\n");
            }
        }

        if finding_number == 0 {
            report.push_str("No findings were identified during this assessment.\n\n");
            report.push_str("---\n\n");
        }

        // Methodology
        report.push_str("## Methodology\n\n");
        report.push_str(
            "The following automated modules were used during this assessment:\n\n",
        );
        report.push_str("| Module | Type | Description |\n");
        report.push_str("|--------|------|-------------|\n");
        report.push_str("| dns-enum | Recon | DNS record enumeration |\n");
        report.push_str("| port-scan | Recon | TCP port scanning |\n");
        report.push_str("| service-probe | Recon | Service fingerprinting |\n");
        report.push_str("| ssl-tls-check | Vulnerability | TLS certificate and configuration analysis |\n");
        report.push_str("| http-headers-check | Vulnerability | HTTP security header analysis |\n");
        report.push_str("| ssh-version-check | Vulnerability | SSH version and protocol analysis |\n");
        report.push_str("\n");

        // Scope
        report.push_str("## Scope\n\n");
        report.push_str(&format!("**Targets:** {}\n\n", targets_str));
        report.push_str(&format!("**Exclusions:** {}\n\n", exclusions_str));

        if !config.scope.time_windows.is_empty() {
            report.push_str("**Time Windows:**\n\n");
            for tw in &config.scope.time_windows {
                let days_str = tw
                    .days
                    .as_ref()
                    .map(|d| d.join(", "))
                    .unwrap_or_else(|| "All days".to_string());
                let tz = tw.timezone.as_deref().unwrap_or("UTC");
                report.push_str(&format!(
                    "- {} - {} ({}) [{}]\n",
                    tw.start, tw.end, tz, days_str
                ));
            }
            report.push_str("\n");
        }

        report.push_str(&format!(
            "**Authorization Level:** {}\n\n",
            config.authorization.max_level
        ));

        if let Some(ref roe) = config.roe_document {
            report.push_str(&format!("**Rules of Engagement:** {}\n\n", roe));
        }

        // Footer
        report.push_str("---\n\n");
        report.push_str("*Generated by SENTINEL Security Assessment Scanner*\n");

        // Write file
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

        let path = output_dir.join("report.md");
        std::fs::write(&path, &report)
            .with_context(|| format!("Failed to write report to {}", path.display()))?;

        tracing::info!("Markdown report written to {}", path.display());
        Ok(path)
    }
}
