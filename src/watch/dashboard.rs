use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};

use super::alert::AlertSink;
use super::WatchEvent;

/// Maximum number of events kept in the ring buffer.
const MAX_EVENTS: usize = 1000;

#[derive(Debug, Clone, Serialize)]
struct DashboardStats {
    total_events: u64,
    events_by_listener: HashMap<String, u64>,
    events_by_severity: HashMap<String, u64>,
    events_by_type: HashMap<String, u64>,
    top_source_ips: Vec<(String, u64)>,
}

impl DashboardStats {
    fn new() -> Self {
        Self {
            total_events: 0,
            events_by_listener: HashMap::new(),
            events_by_severity: HashMap::new(),
            events_by_type: HashMap::new(),
            top_source_ips: Vec::new(),
        }
    }
}

struct DashboardState {
    events: Mutex<Vec<WatchEvent>>,
    stats: Mutex<DashboardStats>,
    ip_counts: Mutex<HashMap<String, u64>>,
    sse_tx: broadcast::Sender<String>,
    start_time: Instant,
    listener_count: u32,
}

/// Dashboard alert sink — also serves a live web dashboard via embedded HTTP.
pub struct DashboardSink {
    bind_address: String,
    port: u16,
    state: Arc<DashboardState>,
}

impl DashboardSink {
    pub fn new(bind_address: &str, port: u16, listener_count: u32) -> Self {
        let (sse_tx, _) = broadcast::channel(256);
        Self {
            bind_address: bind_address.to_string(),
            port,
            state: Arc::new(DashboardState {
                events: Mutex::new(Vec::new()),
                stats: Mutex::new(DashboardStats::new()),
                ip_counts: Mutex::new(HashMap::new()),
                sse_tx,
                start_time: Instant::now(),
                listener_count,
            }),
        }
    }
}

#[async_trait]
impl AlertSink for DashboardSink {
    fn name(&self) -> &str {
        "dashboard"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        // Update ring buffer.
        {
            let mut events = self.state.events.lock().await;
            events.push(event.clone());
            let len = events.len();
            if len > MAX_EVENTS {
                events.drain(0..len - MAX_EVENTS);
            }
        }

        // Update stats.
        {
            let mut stats = self.state.stats.lock().await;
            stats.total_events += 1;
            *stats.events_by_listener.entry(event.listener.clone()).or_default() += 1;
            *stats
                .events_by_severity
                .entry(event.severity.label().to_string())
                .or_default() += 1;
            *stats
                .events_by_type
                .entry(event.event_type.to_string())
                .or_default() += 1;
        }

        // Update IP counts.
        {
            let mut ip_counts = self.state.ip_counts.lock().await;
            *ip_counts.entry(event.source_ip.to_string()).or_default() += 1;

            // Rebuild top IPs.
            let mut sorted: Vec<(String, u64)> = ip_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            sorted.truncate(20);

            let mut stats = self.state.stats.lock().await;
            stats.top_source_ips = sorted;
        }

        // Broadcast to SSE clients.
        if let Ok(json) = serde_json::to_string(event) {
            let _ = self.state.sse_tx.send(json);
        }

        // Start the HTTP server on first emit (lazy start).
        // We use a one-time check by seeing if there are no receivers yet.
        static START: std::sync::Once = std::sync::Once::new();
        let state = self.state.clone();
        let bind = self.bind_address.clone();
        let port = self.port;
        START.call_once(move || {
            tokio::spawn(async move {
                if let Err(e) = run_http_server(&bind, port, state).await {
                    tracing::error!("[dashboard] HTTP server error: {}", e);
                }
            });
        });

        Ok(())
    }
}

async fn run_http_server(bind: &str, port: u16, state: Arc<DashboardState>) -> Result<()> {
    let addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("[dashboard] Dashboard available at http://{}", addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http(stream, state).await {
                tracing::debug!("[dashboard] HTTP handler error: {}", e);
            }
        });
    }
}

async fn handle_http(
    mut stream: tokio::net::TcpStream,
    state: Arc<DashboardState>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let raw = String::from_utf8_lossy(&buf[..n]);
    let request_line = raw.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/" => {
            let body = DASHBOARD_HTML;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/api/stats" => {
            let stats = state.stats.lock().await;
            let body = serde_json::to_string(&*stats)?;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/health" => {
            let stats = state.stats.lock().await;
            let uptime_secs = state.start_time.elapsed().as_secs();
            let body = format!(
                r#"{{"status":"ok","uptime_secs":{},"listeners":{},"total_events":{}}}"#,
                uptime_secs, state.listener_count, stats.total_events,
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/api/metrics" => {
            let stats = state.stats.lock().await;
            let uptime_secs = state.start_time.elapsed().as_secs();

            let mut body = String::new();
            body.push_str("# HELP sentinel_watch_uptime_seconds Time since watch mode started\n");
            body.push_str("# TYPE sentinel_watch_uptime_seconds gauge\n");
            body.push_str(&format!("sentinel_watch_uptime_seconds {}\n", uptime_secs));
            body.push_str("# HELP sentinel_watch_events_total Total events by listener\n");
            body.push_str("# TYPE sentinel_watch_events_total counter\n");
            for (listener, count) in &stats.events_by_listener {
                body.push_str(&format!(
                    "sentinel_watch_events_total{{listener=\"{}\"}} {}\n",
                    listener, count,
                ));
            }
            body.push_str("# HELP sentinel_watch_events_by_severity Total events by severity\n");
            body.push_str("# TYPE sentinel_watch_events_by_severity counter\n");
            for (severity, count) in &stats.events_by_severity {
                body.push_str(&format!(
                    "sentinel_watch_events_by_severity{{severity=\"{}\"}} {}\n",
                    severity, count,
                ));
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/events" => {
            // SSE stream.
            let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
            stream.write_all(headers.as_bytes()).await?;
            stream.flush().await?;

            let mut rx = state.sse_tx.subscribe();
            loop {
                match rx.recv().await {
                    Ok(data) => {
                        let msg = format!("data: {}\n\n", data);
                        if stream.write_all(msg.as_bytes()).await.is_err() {
                            break;
                        }
                        if stream.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        }
        _ => {
            let body = "404 Not Found";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Watch — Live Dashboard</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }
header { background: #1e293b; padding: 1rem 2rem; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 1rem; }
header .brand { font-size: 0.8rem; font-weight: 700; letter-spacing: 0.2em; color: #38bdf8; }
header h1 { font-size: 1.25rem; font-weight: 600; }
header .status { margin-left: auto; font-size: 0.85rem; color: #4ade80; }
main { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
.stats-row { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
.stat-card { background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; min-width: 140px; text-align: center; border-top: 3px solid #334155; }
.stat-card .value { font-size: 2rem; font-weight: 700; color: #f1f5f9; }
.stat-card .label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
.stat-card.critical { border-top-color: #dc2626; }
.stat-card.critical .value { color: #dc2626; }
.stat-card.high { border-top-color: #ea580c; }
.stat-card.high .value { color: #ea580c; }
.stat-card.medium { border-top-color: #ca8a04; }
.stat-card.medium .value { color: #ca8a04; }
h2 { font-size: 1.1rem; margin-bottom: 0.75rem; color: #cbd5e1; }
.events-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.events-table th { text-align: left; padding: 0.5rem 0.75rem; background: #1e293b; color: #94a3b8; border-bottom: 2px solid #334155; position: sticky; top: 0; }
.events-table td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #1e293b; }
.events-table tr:hover { background: #1e293b; }
.sev-CRITICAL { color: #dc2626; font-weight: 700; }
.sev-HIGH { color: #ea580c; font-weight: 600; }
.sev-MEDIUM { color: #ca8a04; }
.sev-LOW { color: #2563eb; }
.sev-INFO { color: #6b7280; }
.event-type { color: #38bdf8; }
.footer { text-align: center; padding: 1.5rem; font-size: 0.8rem; color: #475569; }
</style>
</head>
<body>
<header>
  <span class="brand">SENTINEL</span>
  <h1>Watch — Live Dashboard</h1>
  <span class="status" id="conn-status">Connecting...</span>
</header>
<main>
  <div class="stats-row">
    <div class="stat-card"><div class="value" id="stat-total">0</div><div class="label">Total</div></div>
    <div class="stat-card critical"><div class="value" id="stat-critical">0</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="value" id="stat-high">0</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="value" id="stat-medium">0</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="value" id="stat-low">0</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="value" id="stat-info">0</div><div class="label">Info</div></div>
  </div>

  <h2>Live Events</h2>
  <table class="events-table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Severity</th>
        <th>Listener</th>
        <th>Source</th>
        <th>Port</th>
        <th>Type</th>
        <th>Data</th>
        <th>Geo</th>
      </tr>
    </thead>
    <tbody id="events-body"></tbody>
  </table>
</main>
<div class="footer">Sentinel Watch — Honeypot / Passive Defense</div>

<script>
var total = 0, counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

function updateStats() {
  document.getElementById('stat-total').textContent = total;
  document.getElementById('stat-critical').textContent = counts.CRITICAL || 0;
  document.getElementById('stat-high').textContent = counts.HIGH || 0;
  document.getElementById('stat-medium').textContent = counts.MEDIUM || 0;
  document.getElementById('stat-low').textContent = counts.LOW || 0;
  document.getElementById('stat-info').textContent = counts.INFO || 0;
}

function sevLabel(sev) {
  var map = { Critical: 'CRITICAL', High: 'HIGH', Medium: 'MEDIUM', Low: 'LOW', Info: 'INFO' };
  return map[sev] || sev;
}

function addEvent(ev) {
  var tbody = document.getElementById('events-body');
  var row = document.createElement('tr');
  var sev = sevLabel(ev.severity);
  total++;
  counts[sev] = (counts[sev] || 0) + 1;
  updateStats();

  var ts = ev.timestamp ? ev.timestamp.substring(11, 19) : '';
  var geo = ev.geo_country_code || '';

  row.innerHTML =
    '<td>' + ts + '</td>' +
    '<td class="sev-' + sev + '">' + sev + '</td>' +
    '<td>' + (ev.listener || '') + '</td>' +
    '<td>' + (ev.source_ip || '') + ':' + (ev.source_port || '') + '</td>' +
    '<td>' + (ev.dest_port || '') + '</td>' +
    '<td class="event-type">' + (ev.event_type || '') + '</td>' +
    '<td>' + (ev.captured_data || '') + '</td>' +
    '<td>' + geo + '</td>';

  if (tbody.firstChild) {
    tbody.insertBefore(row, tbody.firstChild);
  } else {
    tbody.appendChild(row);
  }

  // Keep max 500 rows in DOM.
  while (tbody.children.length > 500) {
    tbody.removeChild(tbody.lastChild);
  }
}

// SSE connection.
var evtSource = new EventSource('/events');
evtSource.onopen = function() {
  document.getElementById('conn-status').textContent = 'Live';
  document.getElementById('conn-status').style.color = '#4ade80';
};
evtSource.onerror = function() {
  document.getElementById('conn-status').textContent = 'Disconnected';
  document.getElementById('conn-status').style.color = '#ef4444';
};
evtSource.onmessage = function(e) {
  try {
    var ev = JSON.parse(e.data);
    addEvent(ev);
  } catch(err) {}
};

// Initial load from stats endpoint.
fetch('/api/stats')
  .then(function(r) { return r.json(); })
  .then(function(data) {
    total = data.total_events || 0;
    if (data.events_by_severity) {
      for (var k in data.events_by_severity) {
        counts[k] = data.events_by_severity[k];
      }
    }
    updateStats();
  })
  .catch(function() {});
</script>
</body>
</html>"##;
