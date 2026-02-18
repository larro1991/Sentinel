use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio_rusqlite::Connection;

use crate::watch::WatchEvent;

/// SQLite-backed event store for persistence and querying.
#[derive(Clone)]
pub struct EventStore {
    conn: Arc<Connection>,
}

impl EventStore {
    /// Open (or create) a SQLite database at the given path and run migrations.
    pub async fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .await
            .with_context(|| format!("Failed to open SQLite database: {}", path))?;

        // Run migrations.
        conn.call(|conn| {
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    listener TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    dest_port INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    captured_data TEXT,
                    details TEXT NOT NULL DEFAULT '{}',
                    severity TEXT NOT NULL,
                    geo_country TEXT,
                    geo_country_code TEXT,
                    geo_city TEXT,
                    geo_asn TEXT,
                    geo_org TEXT,
                    dedup_count INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_listener ON events(listener);

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe_id TEXT,
                    cve_ids TEXT NOT NULL DEFAULT '[]',
                    affected_asset TEXT NOT NULL,
                    affected_component TEXT,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '[]',
                    remediation TEXT NOT NULL,
                    refs TEXT NOT NULL DEFAULT '[]',
                    module_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(affected_asset);
                CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module_name);

                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    trigger_event_ids TEXT NOT NULL DEFAULT '[]',
                    event_count INTEGER NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_corr_rule ON correlations(rule_name);
                CREATE INDEX IF NOT EXISTS idx_corr_source_ip ON correlations(source_ip);
                CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlations(severity);
                CREATE INDEX IF NOT EXISTS idx_corr_created ON correlations(created_at);",
            )?;
            Ok(())
        })
        .await
        .context("Failed to run database migrations")?;

        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    /// Open an in-memory database (for testing).
    pub async fn open_memory() -> Result<Self> {
        Self::open(":memory:").await
    }

    /// Insert a watch event.
    pub async fn insert_event(&self, event: &WatchEvent) -> Result<()> {
        let id = event.id.clone();
        let timestamp = event.timestamp.to_rfc3339();
        let listener = event.listener.clone();
        let protocol = event.protocol.clone();
        let source_ip = event.source_ip.to_string();
        let source_port = event.source_port as i64;
        let dest_port = event.dest_port as i64;
        let event_type = event.event_type.to_string();
        let captured_data = event.captured_data.clone();
        let details = serde_json::to_string(&event.details).unwrap_or_else(|_| "{}".into());
        let severity = event.severity.label().to_string();
        let geo_country = event.geo_country.clone();
        let geo_country_code = event.geo_country_code.clone();
        let geo_city = event.geo_city.clone();
        let geo_asn = event.geo_asn.clone();
        let geo_org = event.geo_org.clone();
        let dedup_count = event.dedup_count.map(|c| c as i64);

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO events
                     (id, timestamp, listener, protocol, source_ip, source_port, dest_port,
                      event_type, captured_data, details, severity,
                      geo_country, geo_country_code, geo_city, geo_asn, geo_org, dedup_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                    rusqlite::params![
                        id, timestamp, listener, protocol, source_ip, source_port, dest_port,
                        event_type, captured_data, details, severity,
                        geo_country, geo_country_code, geo_city, geo_asn, geo_org, dedup_count,
                    ],
                )?;
                Ok(())
            })
            .await
            .context("Failed to insert event")?;
        Ok(())
    }

    /// Insert a finding.
    pub async fn insert_finding(&self, finding: &crate::finding::Finding) -> Result<()> {
        let id = finding.id.clone();
        let title = finding.title.clone();
        let severity = finding.severity.label().to_string();
        let cvss_score = finding.cvss_score;
        let cvss_vector = finding.cvss_vector.clone();
        let cwe_id = finding.cwe_id.clone();
        let cve_ids = serde_json::to_string(&finding.cve_ids).unwrap_or_else(|_| "[]".into());
        let affected_asset = finding.affected_asset.clone();
        let affected_component = finding.affected_component.clone();
        let description = finding.description.clone();
        let evidence = serde_json::to_string(&finding.evidence).unwrap_or_else(|_| "[]".into());
        let remediation = finding.remediation.clone();
        let refs = serde_json::to_string(&finding.references).unwrap_or_else(|_| "[]".into());
        let module_name = finding.module_name.clone();
        let timestamp = finding.timestamp.to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO findings
                     (id, title, severity, cvss_score, cvss_vector, cwe_id, cve_ids,
                      affected_asset, affected_component, description, evidence,
                      remediation, refs, module_name, timestamp)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    rusqlite::params![
                        id, title, severity, cvss_score, cvss_vector, cwe_id, cve_ids,
                        affected_asset, affected_component, description, evidence,
                        remediation, refs, module_name, timestamp,
                    ],
                )?;
                Ok(())
            })
            .await
            .context("Failed to insert finding")?;
        Ok(())
    }

    /// Insert a correlation alert.
    pub async fn insert_correlation(&self, alert: &CorrelationRow) -> Result<()> {
        let rule_name = alert.rule_name.clone();
        let severity = alert.severity.clone();
        let source_ip = alert.source_ip.clone();
        let trigger_ids =
            serde_json::to_string(&alert.trigger_event_ids).unwrap_or_else(|_| "[]".into());
        let event_count = alert.event_count as i64;
        let window_start = alert.window_start.clone();
        let window_end = alert.window_end.clone();
        let created_at = alert.created_at.clone();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO correlations
                     (rule_name, severity, source_ip, trigger_event_ids, event_count,
                      window_start, window_end, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        rule_name, severity, source_ip, trigger_ids, event_count,
                        window_start, window_end, created_at,
                    ],
                )?;
                Ok(())
            })
            .await
            .context("Failed to insert correlation")?;
        Ok(())
    }

    /// Query events with optional filters.
    pub async fn query_events(&self, filter: EventFilter) -> Result<Vec<StoredEvent>> {
        self.conn
            .call(move |conn| {
                let mut sql = String::from("SELECT * FROM events WHERE 1=1");
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

                if let Some(ref ip) = filter.source_ip {
                    sql.push_str(" AND source_ip = ?");
                    params.push(Box::new(ip.clone()));
                }
                if let Some(ref et) = filter.event_type {
                    sql.push_str(" AND event_type = ?");
                    params.push(Box::new(et.clone()));
                }
                if let Some(ref sev) = filter.severity {
                    sql.push_str(" AND severity = ?");
                    params.push(Box::new(sev.clone()));
                }
                if let Some(ref listener) = filter.listener {
                    sql.push_str(" AND listener = ?");
                    params.push(Box::new(listener.clone()));
                }
                if let Some(ref since) = filter.since {
                    sql.push_str(" AND timestamp >= ?");
                    params.push(Box::new(since.clone()));
                }
                if let Some(ref until) = filter.until {
                    sql.push_str(" AND timestamp <= ?");
                    params.push(Box::new(until.clone()));
                }

                sql.push_str(" ORDER BY timestamp DESC");

                if let Some(limit) = filter.limit {
                    sql.push_str(&format!(" LIMIT {}", limit));
                }
                if let Some(offset) = filter.offset {
                    sql.push_str(&format!(" OFFSET {}", offset));
                }

                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(StoredEvent {
                        id: row.get("id")?,
                        timestamp: row.get("timestamp")?,
                        listener: row.get("listener")?,
                        protocol: row.get("protocol")?,
                        source_ip: row.get("source_ip")?,
                        source_port: row.get::<_, i64>("source_port")? as u16,
                        dest_port: row.get::<_, i64>("dest_port")? as u16,
                        event_type: row.get("event_type")?,
                        captured_data: row.get("captured_data")?,
                        details: row.get("details")?,
                        severity: row.get("severity")?,
                        geo_country: row.get("geo_country")?,
                        geo_country_code: row.get("geo_country_code")?,
                        geo_city: row.get("geo_city")?,
                        geo_asn: row.get("geo_asn")?,
                        geo_org: row.get("geo_org")?,
                        dedup_count: row.get::<_, Option<i64>>("dedup_count")?.map(|c| c as u32),
                    })
                })?;
                let mut events = Vec::new();
                for row in rows {
                    events.push(row?);
                }
                Ok(events)
            })
            .await
            .context("Failed to query events")
    }

    /// Query findings with optional filters.
    pub async fn query_findings(&self, filter: FindingFilter) -> Result<Vec<StoredFinding>> {
        self.conn
            .call(move |conn| {
                let mut sql = String::from("SELECT * FROM findings WHERE 1=1");
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

                if let Some(ref sev) = filter.severity {
                    sql.push_str(" AND severity = ?");
                    params.push(Box::new(sev.clone()));
                }
                if let Some(ref asset) = filter.asset {
                    sql.push_str(" AND affected_asset = ?");
                    params.push(Box::new(asset.clone()));
                }
                if let Some(ref module) = filter.module {
                    sql.push_str(" AND module_name = ?");
                    params.push(Box::new(module.clone()));
                }

                sql.push_str(" ORDER BY timestamp DESC");

                if let Some(limit) = filter.limit {
                    sql.push_str(&format!(" LIMIT {}", limit));
                }
                if let Some(offset) = filter.offset {
                    sql.push_str(&format!(" OFFSET {}", offset));
                }

                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(StoredFinding {
                        id: row.get("id")?,
                        title: row.get("title")?,
                        severity: row.get("severity")?,
                        cvss_score: row.get("cvss_score")?,
                        affected_asset: row.get("affected_asset")?,
                        description: row.get("description")?,
                        module_name: row.get("module_name")?,
                        timestamp: row.get("timestamp")?,
                    })
                })?;
                let mut findings = Vec::new();
                for row in rows {
                    findings.push(row?);
                }
                Ok(findings)
            })
            .await
            .context("Failed to query findings")
    }

    /// Query correlations with optional filters.
    pub async fn query_correlations(
        &self,
        filter: CorrelationFilter,
    ) -> Result<Vec<StoredCorrelation>> {
        self.conn
            .call(move |conn| {
                let mut sql = String::from("SELECT * FROM correlations WHERE 1=1");
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

                if let Some(ref rule) = filter.rule_name {
                    sql.push_str(" AND rule_name = ?");
                    params.push(Box::new(rule.clone()));
                }
                if let Some(ref ip) = filter.source_ip {
                    sql.push_str(" AND source_ip = ?");
                    params.push(Box::new(ip.clone()));
                }
                if let Some(ref sev) = filter.severity {
                    sql.push_str(" AND severity = ?");
                    params.push(Box::new(sev.clone()));
                }
                if let Some(ref since) = filter.since {
                    sql.push_str(" AND created_at >= ?");
                    params.push(Box::new(since.clone()));
                }

                sql.push_str(" ORDER BY created_at DESC");

                if let Some(limit) = filter.limit {
                    sql.push_str(&format!(" LIMIT {}", limit));
                }
                if let Some(offset) = filter.offset {
                    sql.push_str(&format!(" OFFSET {}", offset));
                }

                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(StoredCorrelation {
                        id: row.get("id")?,
                        rule_name: row.get("rule_name")?,
                        severity: row.get("severity")?,
                        source_ip: row.get("source_ip")?,
                        trigger_event_ids: row.get("trigger_event_ids")?,
                        event_count: row.get::<_, i64>("event_count")? as u32,
                        window_start: row.get("window_start")?,
                        window_end: row.get("window_end")?,
                        created_at: row.get("created_at")?,
                    })
                })?;
                let mut corrs = Vec::new();
                for row in rows {
                    corrs.push(row?);
                }
                Ok(corrs)
            })
            .await
            .context("Failed to query correlations")
    }

    /// Get aggregate statistics.
    pub async fn stats(&self) -> Result<StoreStats> {
        self.conn
            .call(|conn| {
                let event_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
                let finding_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
                let correlation_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM correlations", [], |r| r.get(0))?;

                // Events by severity.
                let mut severity_counts = HashMap::new();
                let mut stmt = conn
                    .prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (sev, count) = row?;
                    severity_counts.insert(sev, count as u64);
                }

                // Events by listener.
                let mut listener_counts = HashMap::new();
                let mut stmt = conn
                    .prepare("SELECT listener, COUNT(*) FROM events GROUP BY listener")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (listener, count) = row?;
                    listener_counts.insert(listener, count as u64);
                }

                // Events by type.
                let mut type_counts = HashMap::new();
                let mut stmt = conn
                    .prepare("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (et, count) = row?;
                    type_counts.insert(et, count as u64);
                }

                // Top source IPs.
                let mut top_ips = Vec::new();
                let mut stmt = conn.prepare(
                    "SELECT source_ip, COUNT(*) as cnt FROM events GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (ip, count) = row?;
                    top_ips.push((ip, count as u64));
                }

                Ok(StoreStats {
                    event_count: event_count as u64,
                    finding_count: finding_count as u64,
                    correlation_count: correlation_count as u64,
                    events_by_severity: severity_counts,
                    events_by_listener: listener_counts,
                    events_by_type: type_counts,
                    top_source_ips: top_ips,
                })
            })
            .await
            .context("Failed to compute stats")
    }

    /// Prune events older than the given number of days.
    pub async fn prune_events(&self, days: u32) -> Result<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        self.conn
            .call(move |conn| {
                let deleted = conn.execute(
                    "DELETE FROM events WHERE timestamp < ?1",
                    rusqlite::params![cutoff_str],
                )?;
                Ok(deleted as u64)
            })
            .await
            .context("Failed to prune events")
    }
}

// ── Query Filter Structs ─────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct EventFilter {
    pub source_ip: Option<String>,
    pub event_type: Option<String>,
    pub severity: Option<String>,
    pub listener: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct FindingFilter {
    pub severity: Option<String>,
    pub asset: Option<String>,
    pub module: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CorrelationFilter {
    pub rule_name: Option<String>,
    pub source_ip: Option<String>,
    pub severity: Option<String>,
    pub since: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

// ── Stored Row Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: String,
    pub timestamp: String,
    pub listener: String,
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub event_type: String,
    pub captured_data: Option<String>,
    pub details: String,
    pub severity: String,
    pub geo_country: Option<String>,
    pub geo_country_code: Option<String>,
    pub geo_city: Option<String>,
    pub geo_asn: Option<String>,
    pub geo_org: Option<String>,
    pub dedup_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub affected_asset: String,
    pub description: String,
    pub module_name: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCorrelation {
    pub id: i64,
    pub rule_name: String,
    pub severity: String,
    pub source_ip: String,
    pub trigger_event_ids: String,
    pub event_count: u32,
    pub window_start: String,
    pub window_end: String,
    pub created_at: String,
}

/// Row struct for inserting correlations.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationRow {
    pub rule_name: String,
    pub severity: String,
    pub source_ip: String,
    pub trigger_event_ids: Vec<String>,
    pub event_count: u32,
    pub window_start: String,
    pub window_end: String,
    pub created_at: String,
}

/// Aggregate statistics across all tables.
#[derive(Debug, Clone, Serialize)]
pub struct StoreStats {
    pub event_count: u64,
    pub finding_count: u64,
    pub correlation_count: u64,
    pub events_by_severity: HashMap<String, u64>,
    pub events_by_listener: HashMap<String, u64>,
    pub events_by_type: HashMap<String, u64>,
    pub top_source_ips: Vec<(String, u64)>,
}
