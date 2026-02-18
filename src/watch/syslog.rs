use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::finding::Severity;
use super::alert::AlertSink;
use super::WatchEvent;

/// Output mode for the syslog sink.
enum SyslogOutput {
    File {
        _path: PathBuf,
        file: Mutex<tokio::fs::File>,
    },
    Udp {
        socket: UdpSocket,
        target: SocketAddr,
    },
}

/// CEF-format syslog alert sink.
///
/// Outputs events in ArcSight Common Event Format (CEF) either to a file
/// or over UDP to a remote syslog collector.
pub struct SyslogSink {
    output: SyslogOutput,
}

impl SyslogSink {
    /// Create a syslog sink that writes CEF lines to a file.
    pub async fn new_file(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create directory for {}", path.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("Failed to open syslog file {}", path.display()))?;

        Ok(Self {
            output: SyslogOutput::File {
                _path: path.to_path_buf(),
                file: Mutex::new(file),
            },
        })
    }

    /// Create a syslog sink that sends CEF messages over UDP.
    pub async fn new_udp(host: &str, port: u16) -> Result<Self> {
        let target: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .with_context(|| format!("Invalid syslog target address: {}:{}", host, port))?;

        // Bind to any available local port.
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket for syslog")?;

        Ok(Self {
            output: SyslogOutput::Udp { socket, target },
        })
    }
}

#[async_trait]
impl AlertSink for SyslogSink {
    fn name(&self) -> &str {
        "syslog"
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        let cef_line = format_cef(event);

        match &self.output {
            SyslogOutput::File { file, .. } => {
                let mut f = file.lock().await;
                f.write_all(cef_line.as_bytes()).await
                    .context("Failed to write to syslog file")?;
                f.write_all(b"\n").await?;
                f.flush().await
                    .context("Failed to flush syslog file")?;
            }
            SyslogOutput::Udp { socket, target } => {
                // Fire-and-forget: log errors but don't propagate.
                if let Err(e) = socket.send_to(cef_line.as_bytes(), target).await {
                    tracing::warn!("[syslog] Failed to send CEF to {}: {}", target, e);
                }
            }
        }

        Ok(())
    }
}

/// Map Severity to CEF severity integer (0-10 scale).
pub fn severity_to_cef(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 10,
        Severity::High => 8,
        Severity::Medium => 5,
        Severity::Low => 3,
        Severity::Info => 1,
    }
}

/// Escape special characters in CEF extension values.
///
/// CEF spec requires escaping: backslash, equals, newlines.
pub fn cef_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '|' => out.push_str("\\|"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format a WatchEvent as a CEF string.
///
/// Format: `CEF:0|Sentinel|Watch|1.0|{event_type}|{description}|{severity}|extensions`
pub fn format_cef(event: &WatchEvent) -> String {
    let event_type = event.event_type.to_string();
    let severity = severity_to_cef(&event.severity);

    let description = match &event.captured_data {
        Some(data) => cef_escape(data),
        None => event_type.clone(),
    };

    let mut extensions = format!(
        "src={} spt={} dst={}",
        event.source_ip, event.source_port, event.dest_port
    );

    if let Some(ref data) = event.captured_data {
        extensions.push_str(&format!(" msg={}", cef_escape(data)));
    }

    // Add geo info if available.
    if let Some(ref country) = event.geo_country_code {
        extensions.push_str(&format!(" cs1={}", cef_escape(country)));
        extensions.push_str(" cs1Label=GeoCountry");
    }

    format!(
        "CEF:0|Sentinel|Watch|1.0|{}|{}|{}|{}",
        cef_escape(&event_type),
        description,
        severity,
        extensions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use chrono::Utc;

    fn make_test_event() -> WatchEvent {
        WatchEvent {
            id: "test-id".to_string(),
            timestamp: Utc::now(),
            listener: "tls-honeypot".to_string(),
            protocol: "tcp".to_string(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            source_port: 54321,
            dest_port: 8443,
            event_type: super::super::WatchEventType::ConnectionAttempt,
            captured_data: Some("SNI: evil.example.com".to_string()),
            details: HashMap::new(),
            severity: Severity::Medium,
            geo_country: None,
            geo_country_code: None,
            geo_city: None,
            geo_asn: None,
            geo_org: None,
            dedup_count: None,
        }
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_cef(&Severity::Critical), 10);
        assert_eq!(severity_to_cef(&Severity::High), 8);
        assert_eq!(severity_to_cef(&Severity::Medium), 5);
        assert_eq!(severity_to_cef(&Severity::Low), 3);
        assert_eq!(severity_to_cef(&Severity::Info), 1);
    }

    #[test]
    fn test_cef_escape_special_chars() {
        assert_eq!(cef_escape("hello"), "hello");
        assert_eq!(cef_escape("a=b"), "a\\=b");
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
        assert_eq!(cef_escape("line1\nline2"), "line1\\nline2");
        assert_eq!(cef_escape("a|b"), "a\\|b");
        assert_eq!(cef_escape("a\rb"), "a\\rb");
    }

    #[test]
    fn test_cef_escape_combined() {
        assert_eq!(cef_escape("a=b\\c|d\ne"), "a\\=b\\\\c\\|d\\ne");
    }

    #[test]
    fn test_format_cef_basic() {
        let event = make_test_event();
        let cef = format_cef(&event);

        assert!(cef.starts_with("CEF:0|Sentinel|Watch|1.0|"));
        assert!(cef.contains("ConnectionAttempt"));
        assert!(cef.contains("src=192.168.1.100"));
        assert!(cef.contains("spt=54321"));
        assert!(cef.contains("dst=8443"));
        assert!(cef.contains("msg=SNI: evil.example.com"));
        assert!(cef.contains("|5|")); // Medium severity = 5
    }

    #[test]
    fn test_format_cef_no_captured_data() {
        let mut event = make_test_event();
        event.captured_data = None;
        let cef = format_cef(&event);

        assert!(cef.starts_with("CEF:0|Sentinel|Watch|1.0|"));
        assert!(cef.contains("ConnectionAttempt"));
        assert!(!cef.contains("msg="));
    }

    #[test]
    fn test_format_cef_with_geo() {
        let mut event = make_test_event();
        event.geo_country_code = Some("US".to_string());
        let cef = format_cef(&event);

        assert!(cef.contains("cs1=US"));
        assert!(cef.contains("cs1Label=GeoCountry"));
    }

    #[test]
    fn test_format_cef_escaping_in_data() {
        let mut event = make_test_event();
        event.captured_data = Some("user=admin|pass=test\\123\nmore".to_string());
        let cef = format_cef(&event);

        assert!(cef.contains("msg=user\\=admin\\|pass\\=test\\\\123\\nmore"));
    }

    #[test]
    fn test_format_cef_critical_severity() {
        let mut event = make_test_event();
        event.severity = Severity::Critical;
        let cef = format_cef(&event);
        assert!(cef.contains("|10|")); // Critical = 10
    }

    #[test]
    fn test_format_cef_info_severity() {
        let mut event = make_test_event();
        event.severity = Severity::Info;
        let cef = format_cef(&event);
        assert!(cef.contains("|1|")); // Info = 1
    }
}
