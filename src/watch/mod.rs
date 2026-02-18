pub mod alert;
pub mod correlation;
pub mod dashboard;
pub mod dedup;
pub mod dns;
pub mod engine;
pub mod ftp;
pub mod geo;
pub mod http;
pub mod mysql;
pub mod postgres;
pub mod rate_limit;
pub mod rdp;
pub mod report;
pub mod smb;
pub mod smtp;
pub mod sqlite_sink;
pub mod ssh;
pub mod syslog;
pub mod telnet;
pub mod threat_intel;
pub mod tls;
pub mod webhook;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use crate::finding::Severity;

/// Trait implemented by each honeypot listener.
#[async_trait]
pub trait WatchListener: Send + Sync {
    /// Human-readable name, e.g. "ssh-honeypot".
    fn name(&self) -> &str;

    /// Protocol label, e.g. "tcp".
    fn protocol(&self) -> &str;

    /// Default port for this listener.
    fn default_port(&self) -> u16;

    /// Run the listener until the shutdown signal fires.
    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()>;
}

/// Classification of a watch event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchEventType {
    ConnectionAttempt,
    CredentialCapture,
    BannerGrab,
    NegotiateAttempt,
    LoginAttempt,
    ProtocolProbe,
    CommandCapture,
    DnsQuery,
    EmailAttempt,
}

impl std::fmt::Display for WatchEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionAttempt => write!(f, "ConnectionAttempt"),
            Self::CredentialCapture => write!(f, "CredentialCapture"),
            Self::BannerGrab => write!(f, "BannerGrab"),
            Self::NegotiateAttempt => write!(f, "NegotiateAttempt"),
            Self::LoginAttempt => write!(f, "LoginAttempt"),
            Self::ProtocolProbe => write!(f, "ProtocolProbe"),
            Self::CommandCapture => write!(f, "CommandCapture"),
            Self::DnsQuery => write!(f, "DnsQuery"),
            Self::EmailAttempt => write!(f, "EmailAttempt"),
        }
    }
}

/// A single event captured by a watch listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub listener: String,
    pub protocol: String,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub event_type: WatchEventType,
    pub captured_data: Option<String>,
    pub details: HashMap<String, String>,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dedup_count: Option<u32>,
}

impl WatchEvent {
    /// Create a new event with common fields filled in.
    pub fn new(
        listener: &str,
        protocol: &str,
        source: SocketAddr,
        dest_port: u16,
        event_type: WatchEventType,
        severity: Severity,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            listener: listener.to_string(),
            protocol: protocol.to_string(),
            source_ip: source.ip(),
            source_port: source.port(),
            dest_port,
            event_type,
            captured_data: None,
            details: HashMap::new(),
            severity,
            geo_country: None,
            geo_country_code: None,
            geo_city: None,
            geo_asn: None,
            geo_org: None,
            dedup_count: None,
        }
    }
}
