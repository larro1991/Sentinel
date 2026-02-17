use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::AuthorizationLevel;

pub mod dns;
pub mod ports;
pub mod service;

/// Result produced by a recon module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub module_name: String,
    pub target: String,
    pub data: ReconData,
    pub timestamp: DateTime<Utc>,
}

/// The type of reconnaissance data collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReconData {
    DnsRecords(Vec<DnsRecord>),
    OpenPorts(Vec<DiscoveredPort>),
    ServiceInfo(Vec<ServiceInfo>),
}

/// A DNS record discovered during enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: Option<u32>,
}

/// A port discovered during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// Detailed service information from fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
}

/// Trait that all recon modules must implement.
#[async_trait]
pub trait ReconModule: Send + Sync {
    /// The machine-readable name of this module.
    fn name(&self) -> &str;

    /// Human-readable description of what this module does.
    fn description(&self) -> &str;

    /// The minimum authorization level required to run this module.
    fn authorization_level(&self) -> AuthorizationLevel;

    /// Execute the module against a target (hostname or IP).
    async fn execute(&self, target: &str) -> Result<ReconResult>;
}

/// Get all built-in recon modules.
pub fn default_modules() -> Vec<Box<dyn ReconModule>> {
    vec![
        Box::new(dns::DnsEnumerator::new()),
        Box::new(ports::PortScanner::new()),
        Box::new(service::ServiceProber::new()),
    ]
}
