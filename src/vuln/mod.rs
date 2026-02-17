use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::auth::AuthorizationLevel;
use crate::finding::Finding;

pub mod ssl;
pub mod headers;
pub mod ssh;
pub mod smb;
pub mod default_creds;
pub mod dir_enum;
pub mod snmp;

/// A discovered network service that vulnerability checks can be run against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
}

/// Trait that all vulnerability check modules must implement.
#[async_trait]
pub trait VulnCheck: Send + Sync {
    /// Machine-readable name of this check.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Minimum authorization level required.
    fn authorization_level(&self) -> AuthorizationLevel;

    /// Whether this check is safe (non-disruptive) to run.
    fn is_safe(&self) -> bool;

    /// Run the check against a service and return any findings.
    async fn check(&self, service: &Service) -> Result<Vec<Finding>>;

    /// Whether this check applies to the given service type.
    fn applies_to(&self, service: &Service) -> bool;
}

/// Get all built-in vulnerability check modules.
pub fn default_checks() -> Vec<Box<dyn VulnCheck>> {
    vec![
        Box::new(ssl::SslCheck::new()),
        Box::new(headers::HeaderCheck::new()),
        Box::new(ssh::SshCheck::new()),
        Box::new(smb::SmbCheck::new()),
        Box::new(default_creds::DefaultCredsCheck::new()),
        Box::new(dir_enum::DirEnumCheck::new()),
        Box::new(snmp::SnmpCheck::new()),
    ]
}
