use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::auth::AuthorizationLevel;
use super::{DnsRecord, ReconData, ReconModule, ReconResult};

/// DNS enumeration module — queries multiple record types to build a picture of
/// the target's DNS infrastructure.
pub struct DnsEnumerator;

impl DnsEnumerator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ReconModule for DnsEnumerator {
    fn name(&self) -> &str {
        "dns-enum"
    }

    fn description(&self) -> &str {
        "Enumerates DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME) for a target domain"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Passive
    }

    async fn execute(&self, target: &str) -> Result<ReconResult> {
        tracing::info!("[dns-enum] Starting DNS enumeration for {}", target);

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let mut records = Vec::new();

        // A / AAAA records via lookup_ip
        match resolver.lookup_ip(target).await {
            Ok(response) => {
                for addr in response.iter() {
                    let record_type = if addr.is_ipv4() { "A" } else { "AAAA" };
                    records.push(DnsRecord {
                        record_type: record_type.to_string(),
                        name: target.to_string(),
                        value: addr.to_string(),
                        ttl: None,
                    });
                }
                tracing::info!("[dns-enum] Found {} A/AAAA records for {}", records.len(), target);
            }
            Err(e) => {
                tracing::debug!("[dns-enum] A/AAAA lookup failed for {}: {}", target, e);
            }
        }

        // MX records
        match resolver.mx_lookup(target).await {
            Ok(response) => {
                for mx in response.iter() {
                    records.push(DnsRecord {
                        record_type: "MX".to_string(),
                        name: target.to_string(),
                        value: format!("{} {}", mx.preference(), mx.exchange()),
                        ttl: None,
                    });
                }
                tracing::info!("[dns-enum] Found MX records for {}", target);
            }
            Err(e) => {
                tracing::debug!("[dns-enum] MX lookup failed for {}: {}", target, e);
            }
        }

        // TXT records
        match resolver.txt_lookup(target).await {
            Ok(response) => {
                for txt in response.iter() {
                    let txt_data: String = txt.iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    records.push(DnsRecord {
                        record_type: "TXT".to_string(),
                        name: target.to_string(),
                        value: txt_data,
                        ttl: None,
                    });
                }
                tracing::info!("[dns-enum] Found TXT records for {}", target);
            }
            Err(e) => {
                tracing::debug!("[dns-enum] TXT lookup failed for {}: {}", target, e);
            }
        }

        // NS records
        match resolver.ns_lookup(target).await {
            Ok(response) => {
                for ns in response.iter() {
                    records.push(DnsRecord {
                        record_type: "NS".to_string(),
                        name: target.to_string(),
                        value: ns.to_string(),
                        ttl: None,
                    });
                }
                tracing::info!("[dns-enum] Found NS records for {}", target);
            }
            Err(e) => {
                tracing::debug!("[dns-enum] NS lookup failed for {}: {}", target, e);
            }
        }

        // SOA record
        match resolver.soa_lookup(target).await {
            Ok(response) => {
                for soa in response.iter() {
                    records.push(DnsRecord {
                        record_type: "SOA".to_string(),
                        name: target.to_string(),
                        value: format!(
                            "{} {} {} {} {} {} {}",
                            soa.mname(),
                            soa.rname(),
                            soa.serial(),
                            soa.refresh(),
                            soa.retry(),
                            soa.expire(),
                            soa.minimum()
                        ),
                        ttl: None,
                    });
                }
                tracing::info!("[dns-enum] Found SOA record for {}", target);
            }
            Err(e) => {
                tracing::debug!("[dns-enum] SOA lookup failed for {}: {}", target, e);
            }
        }

        tracing::info!(
            "[dns-enum] Completed DNS enumeration for {}: {} records found",
            target,
            records.len()
        );

        Ok(ReconResult {
            module_name: self.name().to_string(),
            target: target.to_string(),
            data: ReconData::DnsRecords(records),
            timestamp: Utc::now(),
        })
    }
}
