pub mod alert;
pub mod engine;
pub mod ftp;
pub mod http;
pub mod rdp;
pub mod smb;
pub mod ssh;
pub mod telnet;

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
        }
    }
}
