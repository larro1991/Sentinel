use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
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

/// Build a resolver with IPv4-only DNS servers and aggressive timeouts.
fn build_resolver() -> TokioAsyncResolver {
    // IPv4-only nameservers — avoids IPv6 timeout stalls on systems without IPv6.
    let nameservers = NameServerConfigGroup::from_ips_clear(
        &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),       // Google primary
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),       // Cloudflare primary
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),       // Google secondary
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),       // Cloudflare secondary
        ],
        53,
        true, // trust_negative_responses
    );

    let config = ResolverConfig::from_parts(None, vec![], nameservers);

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);  // 3s per query attempt
    opts.attempts = 2;                       // 2 retries max
    opts.rotate = true;                      // rotate between nameservers

    TokioAsyncResolver::tokio(config, opts)
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

        // Safety timeout: DNS enumeration must complete within 15 seconds total.
        match tokio::time::timeout(Duration::from_secs(15), self.run_queries(target)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("[dns-enum] DNS enumeration timed out after 15s for {}", target);
                Ok(ReconResult {
                    module_name: self.name().to_string(),
                    target: target.to_string(),
                    data: ReconData::DnsRecords(vec![]),
                    timestamp: Utc::now(),
                })
            }
        }
    }
}

impl DnsEnumerator {
    async fn run_queries(&self, target: &str) -> Result<ReconResult> {
        let resolver = build_resolver();

        // Run all DNS queries concurrently instead of sequentially.
        let (ip_result, mx_result, txt_result, ns_result, soa_result) = tokio::join!(
            resolver.lookup_ip(target),
            resolver.mx_lookup(target),
            resolver.txt_lookup(target),
            resolver.ns_lookup(target),
            resolver.soa_lookup(target),
        );

        let mut records = Vec::new();

        // A / AAAA records
        match ip_result {
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
        match mx_result {
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
        match txt_result {
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
        match ns_result {
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
        match soa_result {
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
