use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// DNS zone transfer (AXFR) detection — attempts a TCP AXFR query
/// and reports if the server returns DNS records.
pub struct DnsZoneTransferCheck;

impl DnsZoneTransferCheck {
    pub fn new() -> Self {
        Self
    }

    /// Build a minimal DNS AXFR query for the given domain.
    fn build_axfr_query(domain: &str) -> Vec<u8> {
        let mut query = Vec::new();
        // Transaction ID.
        query.extend_from_slice(&[0x00, 0x01]);
        // Flags: standard query.
        query.extend_from_slice(&[0x00, 0x00]);
        // Questions: 1, Answers: 0, Authority: 0, Additional: 0.
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Encode domain name.
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // Root label.
        // QTYPE = AXFR (252).
        query.extend_from_slice(&[0x00, 0xFC]);
        // QCLASS = IN (1).
        query.extend_from_slice(&[0x00, 0x01]);

        // Wrap in TCP DNS message (2-byte length prefix).
        let len = query.len() as u16;
        let mut msg = Vec::with_capacity(2 + query.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend(query);
        msg
    }
}

#[async_trait]
impl VulnCheck for DnsZoneTransferCheck {
    fn name(&self) -> &str {
        "dns-zone-transfer-check"
    }

    fn description(&self) -> &str {
        "Checks if DNS server allows zone transfers (AXFR)"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        name.contains("dns") || name.contains("domain") || service.port == 53
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[dns-zone-transfer] Checking AXFR on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);

        // Build AXFR query for the service host.
        let domain = &service.host;
        let query = Self::build_axfr_query(domain);

        let addr = format!("{}:{}", service.host, service.port);
        let stream = match tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                tracing::debug!(
                    "[dns-zone-transfer] Could not connect to {}",
                    addr
                );
                return Ok(findings);
            }
        };

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Send the AXFR query.
        if writer.write_all(&query).await.is_err() {
            return Ok(findings);
        }

        // Read the response (TCP DNS: 2-byte length prefix + message).
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut len_buf)).await
        {
            Ok(Ok(_)) => {}
            _ => return Ok(findings),
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < 12 {
            return Ok(findings);
        }

        let mut resp_buf = vec![0u8; resp_len.min(4096)];
        match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut resp_buf)).await
        {
            Ok(Ok(_)) => {}
            _ => return Ok(findings),
        }

        // Parse minimal DNS header: answer count at bytes 6-7.
        let answer_count = u16::from_be_bytes([resp_buf[6], resp_buf[7]]);
        // Check RCODE (bits 12-15 of flags at bytes 2-3).
        let rcode = resp_buf[3] & 0x0F;

        if rcode == 0 && answer_count > 0 {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "DNS Zone Transfer (AXFR) Allowed".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                ),
                cwe_id: Some("CWE-200".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("DNS Server".to_string()),
                description: format!(
                    "The DNS server at {} allows zone transfers (AXFR). \
                     {} answer records were returned, potentially exposing the entire \
                     DNS zone including internal hostnames and network topology.",
                    addr, answer_count
                ),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Raw,
                    content: format!(
                        "AXFR query for {} returned {} answer records (RCODE=0)",
                        domain, answer_count
                    ),
                    label: Some("AXFR Response".to_string()),
                }],
                remediation: "Restrict zone transfers to authorized secondary DNS servers only. \
                    Configure allow-transfer ACLs on the DNS server."
                    .to_string(),
                references: vec![
                    "https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[dns-zone-transfer] Completed on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
