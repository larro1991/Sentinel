use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::config::EngagementConfig;
use crate::finding::{FindingsManager, Severity};
use super::ReportGenerator;

/// Generates a self-contained HTML security assessment report with inline CSS and JS.
pub struct HtmlReport;

impl ReportGenerator for HtmlReport {
    fn format_name(&self) -> &str {
        "html"
    }

    fn generate(
        &self,
        config: &EngagementConfig,
        findings: &FindingsManager,
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let stats = findings.stats();
        let date = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

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

        let risk_color = match risk_rating {
            "CRITICAL" => "#dc2626",
            "HIGH" => "#ea580c",
            "MEDIUM" => "#ca8a04",
            "LOW" => "#2563eb",
            _ => "#6b7280",
        };

        let targets_str = html_escape(&config.scope.targets.join(", "));
        let exclusions_str = if config.scope.exclusions.is_empty() {
            "None".to_string()
        } else {
            html_escape(&config.scope.exclusions.join(", "))
        };

        let mut html = String::with_capacity(32_768);

        // DOCTYPE and head
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!(
            "<title>Security Assessment Report — {}</title>\n",
            html_escape(&config.name)
        ));

        // Inline CSS
        html.push_str("<style>\n");
        html.push_str(CSS);
        html.push_str("\n</style>\n");
        html.push_str("</head>\n<body>\n");

        // Header
        html.push_str("<header class=\"report-header\">\n");
        html.push_str("  <div class=\"header-brand\">SENTINEL</div>\n");
        html.push_str("  <h1>Security Assessment Report</h1>\n");
        html.push_str("  <div class=\"header-meta\">\n");
        html.push_str(&format!(
            "    <span><strong>Engagement:</strong> {}</span>\n",
            html_escape(&config.name)
        ));
        html.push_str(&format!(
            "    <span><strong>ID:</strong> {}</span>\n",
            html_escape(&config.id)
        ));
        html.push_str(&format!(
            "    <span><strong>Date:</strong> {}</span>\n",
            date
        ));
        html.push_str(&format!(
            "    <span><strong>Scope:</strong> {}</span>\n",
            targets_str
        ));
        html.push_str(&format!(
            "    <span><strong>Authorization:</strong> {}</span>\n",
            html_escape(&config.authorization.max_level)
        ));
        html.push_str(&format!(
            "    <span><strong>Emergency Contact:</strong> {}</span>\n",
            html_escape(&config.emergency_contact)
        ));
        html.push_str("  </div>\n");
        html.push_str("</header>\n\n");

        html.push_str("<main class=\"report-body\">\n");

        // Executive Summary
        html.push_str("<section class=\"executive-summary\">\n");
        html.push_str("  <h2>Executive Summary</h2>\n");
        html.push_str("  <div class=\"summary-cards\">\n");
        write_summary_card(&mut html, "Total", stats.total, "#1e293b");
        write_summary_card(&mut html, "Critical", stats.critical, "#dc2626");
        write_summary_card(&mut html, "High", stats.high, "#ea580c");
        write_summary_card(&mut html, "Medium", stats.medium, "#ca8a04");
        write_summary_card(&mut html, "Low", stats.low, "#2563eb");
        write_summary_card(&mut html, "Info", stats.info, "#6b7280");
        html.push_str("  </div>\n");

        if stats.deduplicated > 0 {
            html.push_str(&format!(
                "  <p class=\"dedup-note\">{} duplicate finding(s) removed during deduplication.</p>\n",
                stats.deduplicated
            ));
        }

        html.push_str(&format!(
            "  <p class=\"risk-rating\">Overall Risk Rating: <span style=\"color:{}; font-weight:700;\">{}</span></p>\n",
            risk_color, risk_rating
        ));
        html.push_str("</section>\n\n");

        // Findings
        html.push_str("<section class=\"findings\">\n");
        html.push_str("  <h2>Findings</h2>\n");

        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        let mut finding_number = 0u32;
        for severity in &severity_order {
            let matching = findings.by_severity(severity);
            for finding in matching {
                finding_number += 1;
                let sev_color = severity_color(severity);
                let finding_id = format!("finding-{}", finding_number);

                html.push_str(&format!(
                    "  <div class=\"finding-card\" id=\"{}\">\n",
                    finding_id
                ));
                html.push_str("    <div class=\"finding-header\" onclick=\"toggleFinding(this)\">\n");
                html.push_str(&format!(
                    "      <span class=\"severity-badge\" style=\"background:{}\">{}</span>\n",
                    sev_color,
                    severity.label()
                ));
                html.push_str(&format!(
                    "      <span class=\"finding-title\">{}. {}</span>\n",
                    finding_number,
                    html_escape(&finding.title)
                ));
                html.push_str(&format!(
                    "      <span class=\"finding-asset\">{}</span>\n",
                    html_escape(&finding.affected_asset)
                ));
                html.push_str("      <span class=\"toggle-icon\">&#9660;</span>\n");
                html.push_str("    </div>\n");

                html.push_str("    <div class=\"finding-details\">\n");

                // Metadata table
                html.push_str("      <table class=\"meta-table\">\n");
                html.push_str(&format!(
                    "        <tr><td><strong>ID</strong></td><td>{}</td></tr>\n",
                    html_escape(&finding.id)
                ));
                html.push_str(&format!(
                    "        <tr><td><strong>Asset</strong></td><td>{}</td></tr>\n",
                    html_escape(&finding.affected_asset)
                ));
                if let Some(ref component) = finding.affected_component {
                    html.push_str(&format!(
                        "        <tr><td><strong>Component</strong></td><td>{}</td></tr>\n",
                        html_escape(component)
                    ));
                }
                if let Some(score) = finding.cvss_score {
                    let vector_str = finding
                        .cvss_vector
                        .as_deref()
                        .map(|v| format!(" ({})", html_escape(v)))
                        .unwrap_or_default();
                    html.push_str(&format!(
                        "        <tr><td><strong>CVSS</strong></td><td>{:.1}{}</td></tr>\n",
                        score, vector_str
                    ));
                }
                if let Some(ref cwe) = finding.cwe_id {
                    html.push_str(&format!(
                        "        <tr><td><strong>CWE</strong></td><td>{}</td></tr>\n",
                        html_escape(cwe)
                    ));
                }
                if !finding.cve_ids.is_empty() {
                    let cves: Vec<String> = finding
                        .cve_ids
                        .iter()
                        .map(|c| html_escape(c))
                        .collect();
                    html.push_str(&format!(
                        "        <tr><td><strong>CVE</strong></td><td>{}</td></tr>\n",
                        cves.join(", ")
                    ));
                }
                html.push_str(&format!(
                    "        <tr><td><strong>Module</strong></td><td>{}</td></tr>\n",
                    html_escape(&finding.module_name)
                ));
                html.push_str(&format!(
                    "        <tr><td><strong>Timestamp</strong></td><td>{}</td></tr>\n",
                    finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                ));
                html.push_str("      </table>\n");

                // Description
                html.push_str("      <h4>Description</h4>\n");
                html.push_str(&format!(
                    "      <p>{}</p>\n",
                    html_escape(&finding.description)
                ));

                // Evidence
                if !finding.evidence.is_empty() {
                    html.push_str("      <h4>Evidence</h4>\n");
                    for ev in &finding.evidence {
                        if let Some(ref label) = ev.label {
                            html.push_str(&format!(
                                "      <p class=\"evidence-label\">{}</p>\n",
                                html_escape(label)
                            ));
                        }
                        html.push_str("      <pre><code>");
                        html.push_str(&html_escape(&ev.content));
                        html.push_str("</code></pre>\n");
                    }
                }

                // Remediation
                html.push_str("      <h4>Remediation</h4>\n");
                html.push_str(&format!(
                    "      <p>{}</p>\n",
                    html_escape(&finding.remediation)
                ));

                // References
                if !finding.references.is_empty() {
                    html.push_str("      <h4>References</h4>\n");
                    html.push_str("      <ul>\n");
                    for r in &finding.references {
                        let escaped = html_escape(r);
                        html.push_str(&format!(
                            "        <li><a href=\"{}\" target=\"_blank\" rel=\"noopener\">{}</a></li>\n",
                            escaped, escaped
                        ));
                    }
                    html.push_str("      </ul>\n");
                }

                html.push_str("    </div>\n"); // finding-details
                html.push_str("  </div>\n\n"); // finding-card
            }
        }

        if finding_number == 0 {
            html.push_str("  <p class=\"no-findings\">No findings were identified during this assessment.</p>\n");
        }

        html.push_str("</section>\n\n");

        // Methodology
        html.push_str("<section class=\"methodology\">\n");
        html.push_str("  <h2>Methodology</h2>\n");
        html.push_str("  <p>The following automated modules were used during this assessment:</p>\n");
        html.push_str("  <table class=\"methodology-table\">\n");
        html.push_str("    <thead><tr><th>Module</th><th>Type</th><th>Description</th></tr></thead>\n");
        html.push_str("    <tbody>\n");
        html.push_str("      <tr><td>dns-enum</td><td>Recon</td><td>DNS record enumeration</td></tr>\n");
        html.push_str("      <tr><td>port-scan</td><td>Recon</td><td>TCP port scanning</td></tr>\n");
        html.push_str("      <tr><td>service-probe</td><td>Recon</td><td>Service fingerprinting</td></tr>\n");
        html.push_str("      <tr><td>ssl-tls-check</td><td>Vulnerability</td><td>TLS certificate and configuration analysis</td></tr>\n");
        html.push_str("      <tr><td>http-headers-check</td><td>Vulnerability</td><td>HTTP security header analysis</td></tr>\n");
        html.push_str("      <tr><td>ssh-version-check</td><td>Vulnerability</td><td>SSH version and protocol analysis</td></tr>\n");
        html.push_str("    </tbody>\n");
        html.push_str("  </table>\n");
        html.push_str("</section>\n\n");

        // Scope
        html.push_str("<section class=\"scope-section\">\n");
        html.push_str("  <h2>Scope</h2>\n");
        html.push_str(&format!(
            "  <p><strong>Targets:</strong> {}</p>\n",
            targets_str
        ));
        html.push_str(&format!(
            "  <p><strong>Exclusions:</strong> {}</p>\n",
            exclusions_str
        ));

        if !config.scope.time_windows.is_empty() {
            html.push_str("  <p><strong>Time Windows:</strong></p>\n");
            html.push_str("  <ul>\n");
            for tw in &config.scope.time_windows {
                let days_str = tw
                    .days
                    .as_ref()
                    .map(|d| d.join(", "))
                    .unwrap_or_else(|| "All days".to_string());
                let tz = tw.timezone.as_deref().unwrap_or("UTC");
                html.push_str(&format!(
                    "    <li>{} &ndash; {} ({}) [{}]</li>\n",
                    html_escape(&tw.start),
                    html_escape(&tw.end),
                    html_escape(tz),
                    html_escape(&days_str),
                ));
            }
            html.push_str("  </ul>\n");
        }

        html.push_str(&format!(
            "  <p><strong>Authorization Level:</strong> {}</p>\n",
            html_escape(&config.authorization.max_level)
        ));

        if let Some(ref roe) = config.roe_document {
            html.push_str(&format!(
                "  <p><strong>Rules of Engagement:</strong> {}</p>\n",
                html_escape(roe)
            ));
        }

        html.push_str("</section>\n\n");

        html.push_str("</main>\n\n");

        // Footer
        html.push_str("<footer class=\"report-footer\">\n");
        html.push_str("  <p>Generated by <strong>SENTINEL</strong> Security Assessment Scanner</p>\n");
        html.push_str("</footer>\n\n");

        // Inline JS for toggling finding details
        html.push_str("<script>\n");
        html.push_str(JS);
        html.push_str("\n</script>\n");

        html.push_str("</body>\n</html>\n");

        // Write file
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

        let path = output_dir.join("report.html");
        std::fs::write(&path, &html)
            .with_context(|| format!("Failed to write HTML report to {}", path.display()))?;

        tracing::info!("HTML report written to {}", path.display());
        Ok(path)
    }
}

/// Return the color hex for a given severity level.
fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "#dc2626",
        Severity::High => "#ea580c",
        Severity::Medium => "#ca8a04",
        Severity::Low => "#2563eb",
        Severity::Info => "#6b7280",
    }
}

/// Minimal HTML entity escaping for safe insertion into HTML content and attributes.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn write_summary_card(html: &mut String, label: &str, count: usize, color: &str) {
    html.push_str(&format!(
        "    <div class=\"summary-card\" style=\"border-top: 4px solid {}\">\n",
        color
    ));
    html.push_str(&format!(
        "      <div class=\"card-count\" style=\"color:{}\">{}</div>\n",
        color, count
    ));
    html.push_str(&format!(
        "      <div class=\"card-label\">{}</div>\n",
        label
    ));
    html.push_str("    </div>\n");
}

/// Inline CSS for the report.
const CSS: &str = r#"
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.6;
    color: #1e293b;
    background: #f8fafc;
}
.report-header {
    background: #0f172a;
    color: #f1f5f9;
    padding: 2rem 2.5rem;
}
.header-brand {
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.25em;
    color: #38bdf8;
    margin-bottom: 0.25rem;
}
.report-header h1 {
    font-size: 1.75rem;
    font-weight: 700;
    margin-bottom: 1rem;
}
.header-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 2rem;
    font-size: 0.9rem;
    color: #cbd5e1;
}
.header-meta strong { color: #e2e8f0; }
.report-body {
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem 2.5rem;
}
h2 {
    font-size: 1.4rem;
    margin-bottom: 1rem;
    padding-bottom: 0.4rem;
    border-bottom: 2px solid #e2e8f0;
}
/* Executive Summary Cards */
.executive-summary { margin-bottom: 2.5rem; }
.summary-cards {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1rem;
}
.summary-card {
    background: #fff;
    border-radius: 6px;
    padding: 1rem 1.5rem;
    min-width: 120px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
.card-count { font-size: 2rem; font-weight: 700; }
.card-label { font-size: 0.85rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
.dedup-note { font-size: 0.9rem; color: #64748b; margin-bottom: 0.5rem; }
.risk-rating { font-size: 1.1rem; margin-top: 0.5rem; }
/* Findings */
.findings { margin-bottom: 2.5rem; }
.finding-card {
    background: #fff;
    border-radius: 6px;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    overflow: hidden;
}
.finding-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.85rem 1.25rem;
    cursor: pointer;
    user-select: none;
    background: #fff;
    transition: background 0.15s;
}
.finding-header:hover { background: #f1f5f9; }
.severity-badge {
    display: inline-block;
    color: #fff;
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
}
.finding-title { font-weight: 600; flex: 1; }
.finding-asset { font-size: 0.85rem; color: #64748b; flex-shrink: 0; }
.toggle-icon { font-size: 0.7rem; color: #94a3b8; transition: transform 0.2s; }
.finding-details {
    display: none;
    padding: 1rem 1.25rem 1.25rem;
    border-top: 1px solid #e2e8f0;
}
.finding-details h4 { font-size: 1rem; margin: 1rem 0 0.4rem; color: #334155; }
.finding-details h4:first-child { margin-top: 0; }
.finding-details p { margin-bottom: 0.5rem; }
.meta-table { width: 100%; border-collapse: collapse; margin-bottom: 0.5rem; font-size: 0.9rem; }
.meta-table td { padding: 0.3rem 0.75rem 0.3rem 0; vertical-align: top; }
.meta-table td:first-child { white-space: nowrap; width: 130px; color: #64748b; }
.evidence-label { font-style: italic; color: #475569; margin-bottom: 0.25rem; }
pre {
    background: #1e293b;
    color: #e2e8f0;
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.85rem;
    line-height: 1.5;
    margin-bottom: 0.75rem;
}
code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
.finding-details ul { padding-left: 1.5rem; margin-bottom: 0.5rem; }
.finding-details li { margin-bottom: 0.2rem; }
.finding-details a { color: #2563eb; text-decoration: none; }
.finding-details a:hover { text-decoration: underline; }
.no-findings { color: #64748b; font-style: italic; }
/* Methodology */
.methodology { margin-bottom: 2.5rem; }
.methodology-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.9rem; }
.methodology-table th {
    text-align: left;
    padding: 0.6rem 0.75rem;
    background: #f1f5f9;
    border-bottom: 2px solid #cbd5e1;
    font-weight: 600;
}
.methodology-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #e2e8f0;
}
/* Scope */
.scope-section { margin-bottom: 2.5rem; }
.scope-section p { margin-bottom: 0.5rem; }
.scope-section ul { padding-left: 1.5rem; margin-bottom: 0.75rem; }
/* Footer */
.report-footer {
    text-align: center;
    padding: 1.5rem;
    font-size: 0.85rem;
    color: #64748b;
    border-top: 1px solid #e2e8f0;
}
/* Print */
@media print {
    body { background: #fff; }
    .report-header { background: #1e293b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .finding-details { display: block !important; }
    .toggle-icon { display: none; }
    .finding-header { cursor: default; }
    .finding-card { break-inside: avoid; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
    a[href]::after { content: " (" attr(href) ")"; font-size: 0.8em; color: #475569; }
}
/* Responsive */
@media (max-width: 800px) {
    .report-header, .report-body { padding: 1.25rem; }
    .summary-cards { gap: 0.5rem; }
    .summary-card { min-width: 90px; padding: 0.75rem; }
    .card-count { font-size: 1.5rem; }
    .finding-header { flex-wrap: wrap; }
    .finding-asset { width: 100%; }
}
"#;

/// Inline JavaScript for expanding/collapsing finding detail sections.
const JS: &str = r#"
function toggleFinding(header) {
    var details = header.nextElementSibling;
    var icon = header.querySelector('.toggle-icon');
    if (details.style.display === 'block') {
        details.style.display = 'none';
        icon.style.transform = 'rotate(0deg)';
    } else {
        details.style.display = 'block';
        icon.style.transform = 'rotate(180deg)';
    }
}
"#;
