use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use super::WatchEvent;

/// Statistics derived from watch event analysis.
#[derive(Debug)]
pub struct WatchReportData {
    pub total_events: usize,
    pub event_type_counts: Vec<(String, usize)>,
    pub severity_counts: Vec<(String, usize)>,
    pub top_source_ips: Vec<(String, usize)>,
    pub top_credentials: Vec<(String, usize)>,
    pub per_listener: Vec<(String, usize)>,
    pub hourly_timeline: Vec<(String, usize)>,
    pub top_countries: Vec<(String, usize)>,
}

/// Load watch events from an NDJSON (.jsonl) file.
pub fn load_jsonl(path: &Path) -> Result<Vec<WatchEvent>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut events = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<WatchEvent>(line) {
            Ok(event) => events.push(event),
            Err(e) => {
                tracing::warn!("Skipping invalid event on line {}: {}", i + 1, e);
            }
        }
    }

    Ok(events)
}

/// Analyze a set of watch events and produce statistics.
pub fn analyze_events(events: &[WatchEvent]) -> WatchReportData {
    let total_events = events.len();

    // Event type counts.
    let mut type_map: HashMap<String, usize> = HashMap::new();
    let mut severity_map: HashMap<String, usize> = HashMap::new();
    let mut ip_map: HashMap<String, usize> = HashMap::new();
    let mut cred_map: HashMap<String, usize> = HashMap::new();
    let mut listener_map: HashMap<String, usize> = HashMap::new();
    let mut hour_map: HashMap<String, usize> = HashMap::new();
    let mut country_map: HashMap<String, usize> = HashMap::new();

    for event in events {
        *type_map.entry(event.event_type.to_string()).or_default() += 1;
        *severity_map.entry(event.severity.label().to_string()).or_default() += 1;
        *ip_map.entry(event.source_ip.to_string()).or_default() += 1;
        *listener_map.entry(event.listener.clone()).or_default() += 1;

        let hour = event.timestamp.format("%Y-%m-%d %H:00").to_string();
        *hour_map.entry(hour).or_default() += 1;

        if let Some(ref data) = event.captured_data {
            if event.event_type.to_string() == "CredentialCapture" {
                *cred_map.entry(data.clone()).or_default() += 1;
            }
        }

        if let Some(ref cc) = event.geo_country_code {
            *country_map.entry(cc.clone()).or_default() += 1;
        }
    }

    WatchReportData {
        total_events,
        event_type_counts: sorted_vec(type_map),
        severity_counts: sorted_vec(severity_map),
        top_source_ips: sorted_vec_top(ip_map, 20),
        top_credentials: sorted_vec_top(cred_map, 20),
        per_listener: sorted_vec(listener_map),
        hourly_timeline: {
            let mut v: Vec<(String, usize)> = hour_map.into_iter().collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v
        },
        top_countries: sorted_vec_top(country_map, 20),
    }
}

fn sorted_vec(map: HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

fn sorted_vec_top(map: HashMap<String, usize>, top: usize) -> Vec<(String, usize)> {
    let mut v = sorted_vec(map);
    v.truncate(top);
    v
}

/// Print a colored console report.
pub fn print_console_report(data: &WatchReportData) {
    println!();
    println!("{}", "╔═══════════════════════════════════════════╗".cyan());
    println!("{}", "║      S E N T I N E L  W A T C H           ║".cyan());
    println!("{}", "║          Event Analysis Report             ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════╝".cyan());
    println!();

    println!(
        "{} {}",
        "Total Events:".bold(),
        data.total_events
    );
    println!();

    // Severity breakdown.
    println!("{}", "Severity Breakdown:".bold());
    for (sev, count) in &data.severity_counts {
        let colored_sev = match sev.as_str() {
            "CRITICAL" => sev.red().bold().to_string(),
            "HIGH" => sev.red().to_string(),
            "MEDIUM" => sev.yellow().to_string(),
            "LOW" => sev.blue().to_string(),
            _ => sev.white().to_string(),
        };
        println!("  {:>10}  {}", colored_sev, count);
    }
    println!();

    // Event types.
    println!("{}", "Event Types:".bold());
    for (et, count) in &data.event_type_counts {
        println!("  {:>25}  {}", et.cyan(), count);
    }
    println!();

    // Per listener.
    println!("{}", "Per Listener:".bold());
    for (listener, count) in &data.per_listener {
        println!("  {:>25}  {}", listener, count);
    }
    println!();

    // Top source IPs.
    if !data.top_source_ips.is_empty() {
        println!("{}", "Top Source IPs:".bold());
        for (ip, count) in &data.top_source_ips {
            println!("  {:>20}  {}", ip, count);
        }
        println!();
    }

    // Top credentials.
    if !data.top_credentials.is_empty() {
        println!("{}", "Top Captured Credentials:".bold());
        for (cred, count) in &data.top_credentials {
            println!("  {:>30}  {}", cred.red(), count);
        }
        println!();
    }

    // Top countries.
    if !data.top_countries.is_empty() {
        println!("{}", "Top Countries:".bold());
        for (cc, count) in &data.top_countries {
            println!("  {:>6}  {}", cc, count);
        }
        println!();
    }

    // Timeline.
    if !data.hourly_timeline.is_empty() {
        println!("{}", "Hourly Timeline:".bold());
        let max_count = data.hourly_timeline.iter().map(|(_, c)| *c).max().unwrap_or(1);
        for (hour, count) in &data.hourly_timeline {
            let bar_width = (*count as f64 / max_count as f64 * 40.0) as usize;
            let bar: String = "#".repeat(bar_width);
            println!("  {} {:>5}  {}", hour.dimmed(), count, bar.green());
        }
        println!();
    }
}

/// Generate a self-contained HTML report.
pub fn generate_html_report(data: &WatchReportData, path: &Path) -> Result<()> {
    let mut html = String::with_capacity(16_384);

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>Sentinel Watch — Event Analysis Report</title>\n");
    html.push_str("<style>\n");
    html.push_str(REPORT_CSS);
    html.push_str("\n</style>\n</head>\n<body>\n");

    // Header.
    html.push_str("<header class=\"report-header\">\n");
    html.push_str("  <div class=\"brand\">SENTINEL</div>\n");
    html.push_str("  <h1>Watch — Event Analysis Report</h1>\n");
    html.push_str(&format!(
        "  <div class=\"meta\"><strong>Total Events:</strong> {}</div>\n",
        data.total_events
    ));
    html.push_str("</header>\n");

    html.push_str("<main>\n");

    // Summary cards.
    html.push_str("<section class=\"summary-cards\">\n");
    let severity_colors = [
        ("CRITICAL", "#dc2626"),
        ("HIGH", "#ea580c"),
        ("MEDIUM", "#ca8a04"),
        ("LOW", "#2563eb"),
        ("INFO", "#6b7280"),
    ];
    for (sev, color) in &severity_colors {
        let count = data
            .severity_counts
            .iter()
            .find(|(s, _)| s == sev)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        html.push_str(&format!(
            "  <div class=\"card\" style=\"border-top:4px solid {}\">\n    <div class=\"value\" style=\"color:{}\">{}</div>\n    <div class=\"label\">{}</div>\n  </div>\n",
            color, color, count, sev
        ));
    }
    html.push_str("</section>\n");

    // Event types table.
    html.push_str("<section>\n<h2>Event Types</h2>\n<table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>\n");
    for (et, count) in &data.event_type_counts {
        html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(et), count));
    }
    html.push_str("</tbody></table>\n</section>\n");

    // Per listener.
    html.push_str("<section>\n<h2>Per Listener</h2>\n<table><thead><tr><th>Listener</th><th>Events</th></tr></thead><tbody>\n");
    for (l, count) in &data.per_listener {
        html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(l), count));
    }
    html.push_str("</tbody></table>\n</section>\n");

    // Top IPs.
    if !data.top_source_ips.is_empty() {
        html.push_str("<section>\n<h2>Top Source IPs</h2>\n<table><thead><tr><th>IP</th><th>Events</th></tr></thead><tbody>\n");
        for (ip, count) in &data.top_source_ips {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(ip), count));
        }
        html.push_str("</tbody></table>\n</section>\n");
    }

    // Top credentials.
    if !data.top_credentials.is_empty() {
        html.push_str("<section>\n<h2>Top Captured Credentials</h2>\n<table><thead><tr><th>Credentials</th><th>Count</th></tr></thead><tbody>\n");
        for (cred, count) in &data.top_credentials {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(cred), count));
        }
        html.push_str("</tbody></table>\n</section>\n");
    }

    // Top countries.
    if !data.top_countries.is_empty() {
        html.push_str("<section>\n<h2>Top Countries</h2>\n<table><thead><tr><th>Country Code</th><th>Events</th></tr></thead><tbody>\n");
        for (cc, count) in &data.top_countries {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(cc), count));
        }
        html.push_str("</tbody></table>\n</section>\n");
    }

    // Timeline.
    if !data.hourly_timeline.is_empty() {
        html.push_str("<section>\n<h2>Hourly Timeline</h2>\n<table><thead><tr><th>Hour</th><th>Events</th><th>Chart</th></tr></thead><tbody>\n");
        let max_count = data.hourly_timeline.iter().map(|(_, c)| *c).max().unwrap_or(1);
        for (hour, count) in &data.hourly_timeline {
            let pct = (*count as f64 / max_count as f64 * 100.0) as u32;
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><div style=\"background:#38bdf8;height:16px;width:{}%;border-radius:2px;\"></div></td></tr>\n",
                html_escape(hour), count, pct
            ));
        }
        html.push_str("</tbody></table>\n</section>\n");
    }

    html.push_str("</main>\n");
    html.push_str("<footer>Generated by <strong>SENTINEL</strong> Watch</footer>\n");
    html.push_str("</body>\n</html>\n");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &html)
        .with_context(|| format!("Failed to write HTML report to {}", path.display()))?;

    Ok(())
}

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

const REPORT_CSS: &str = r#"
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
.report-header { background: #0f172a; color: #f1f5f9; padding: 2rem 2.5rem; }
.brand { font-size: 0.85rem; font-weight: 700; letter-spacing: 0.25em; color: #38bdf8; margin-bottom: 0.25rem; }
.report-header h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
.meta { font-size: 0.9rem; color: #cbd5e1; }
main { max-width: 1100px; margin: 0 auto; padding: 2rem 2.5rem; }
.summary-cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }
.card { background: #fff; border-radius: 6px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.card .value { font-size: 2rem; font-weight: 700; }
.card .label { font-size: 0.8rem; color: #64748b; text-transform: uppercase; }
section { margin-bottom: 2rem; }
h2 { font-size: 1.2rem; margin-bottom: 0.75rem; padding-bottom: 0.3rem; border-bottom: 2px solid #e2e8f0; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; padding: 0.5rem 0.75rem; background: #f1f5f9; border-bottom: 2px solid #cbd5e1; }
td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #e2e8f0; }
footer { text-align: center; padding: 1.5rem; font-size: 0.85rem; color: #64748b; border-top: 1px solid #e2e8f0; }
"#;
