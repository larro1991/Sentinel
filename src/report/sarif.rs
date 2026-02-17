use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::EngagementConfig;
use crate::finding::{FindingsManager, Finding, Severity};
use super::ReportGenerator;

/// Generates a SARIF 2.1.0 report (Static Analysis Results Interchange Format).
pub struct SarifReport;

impl ReportGenerator for SarifReport {
    fn format_name(&self) -> &str {
        "sarif"
    }

    fn generate(
        &self,
        _config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf> {
        // Build the list of unique rules keyed by (module_name, title).
        // Using BTreeMap for deterministic ordering.
        let mut rules_map: BTreeMap<(String, String), RuleInfo> = BTreeMap::new();

        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        // Collect findings in severity order for the results array.
        let mut ordered_findings: Vec<&Finding> = Vec::new();
        for severity in &severity_order {
            ordered_findings.extend(findings.by_severity(severity));
        }

        for finding in &ordered_findings {
            let key = (finding.module_name.clone(), finding.title.clone());
            rules_map.entry(key).or_insert_with(|| {
                let help_uri = finding.references.first().cloned();
                RuleInfo {
                    id: finding.module_name.clone(),
                    short_description: finding.title.clone(),
                    help_uri,
                }
            });
        }

        // Build rules array
        let rules: Vec<serde_json::Value> = rules_map
            .values()
            .map(|rule| {
                let mut r = serde_json::json!({
                    "id": rule.id,
                    "shortDescription": {
                        "text": rule.short_description
                    }
                });
                if let Some(ref uri) = rule.help_uri {
                    r.as_object_mut()
                        .expect("rule must be an object")
                        .insert("helpUri".to_string(), serde_json::json!(uri));
                }
                r
            })
            .collect();

        // Build results array
        let results: Vec<serde_json::Value> = ordered_findings
            .iter()
            .map(|finding| {
                let level = sarif_level(&finding.severity);

                let mut properties = serde_json::json!({
                    "severity": finding.severity.label(),
                    "remediation": finding.remediation,
                });

                if let Some(score) = finding.cvss_score {
                    properties.as_object_mut()
                        .expect("properties must be an object")
                        .insert("cvss_score".to_string(), serde_json::json!(score));
                }
                if let Some(ref cwe) = finding.cwe_id {
                    properties.as_object_mut()
                        .expect("properties must be an object")
                        .insert("cwe_id".to_string(), serde_json::json!(cwe));
                }
                if !finding.cve_ids.is_empty() {
                    properties.as_object_mut()
                        .expect("properties must be an object")
                        .insert("cve_ids".to_string(), serde_json::json!(finding.cve_ids));
                }

                serde_json::json!({
                    "ruleId": finding.module_name,
                    "level": level,
                    "message": {
                        "text": finding.description
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "address": {
                                    "absoluteAddress": 0
                                }
                            },
                            "logicalLocations": [
                                {
                                    "name": finding.affected_asset
                                }
                            ]
                        }
                    ],
                    "properties": properties
                })
            })
            .collect();

        // Assemble the full SARIF document
        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SENTINEL",
                            "version": env!("CARGO_PKG_VERSION"),
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        });

        let json = serde_json::to_string_pretty(&sarif)
            .context("Failed to serialize SARIF report to JSON")?;

        // Write file
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

        let path = output_dir.join("report.sarif.json");
        std::fs::write(&path, &json)
            .with_context(|| format!("Failed to write SARIF report to {}", path.display()))?;

        tracing::info!("SARIF report written to {}", path.display());
        Ok(path)
    }
}

/// Intermediate representation for a SARIF rule derived from findings.
struct RuleInfo {
    id: String,
    short_description: String,
    help_uri: Option<String>,
}

/// Map Sentinel severity to SARIF result level.
///
/// SARIF defines three levels: "error", "warning", "note".
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
