use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// SNMP community string checker — sends SNMP v1/v2c GetRequest packets with
/// common community strings and reports any that produce a valid response.
pub struct SnmpCheck;

impl SnmpCheck {
    pub fn new() -> Self {
        Self
    }
}

/// Community strings to test, in order of likelihood.
const COMMUNITY_STRINGS: &[&str] = &[
    "public",
    "private",
    "community",
    "snmp",
    "monitor",
    "admin",
];

/// Build an SNMP v2c GetRequest packet for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
/// with the given community string.
///
/// The packet is a minimal ASN.1/BER encoding:
///
/// ```text
/// SEQUENCE {                          -- Message envelope
///   INTEGER  1                        -- SNMP version: 2c (0-indexed, so value = 1)
///   OCTET STRING  <community>         -- Community string
///   GetRequest-PDU (0xA0) {           -- PDU type
///     INTEGER  <request-id>           -- Request ID (we use a fixed 1)
///     INTEGER  0                      -- Error status
///     INTEGER  0                      -- Error index
///     SEQUENCE {                      -- Variable bindings
///       SEQUENCE {                    -- Single varbind
///         OID  1.3.6.1.2.1.1.1.0     -- sysDescr.0
///         NULL                        -- Value placeholder
///       }
///     }
///   }
/// }
/// ```
fn build_snmp_get_request(community: &str) -> Vec<u8> {
    let community_bytes = community.as_bytes();

    // ── OID: 1.3.6.1.2.1.1.1.0 ─────────────────────────────────────────
    // BER-encoded OID bytes (first two components 1.3 merge into 0x2B):
    //   0x2B 0x06 0x01 0x02 0x01 0x01 0x01 0x00
    let oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_tlv_len = 2 + oid_value.len(); // tag(1) + len(1) + value

    // NULL value: 05 00
    let null_tlv_len: usize = 2;

    // Varbind SEQUENCE: tag(1) + len(1) + OID TLV + NULL TLV
    let varbind_content_len = oid_tlv_len + null_tlv_len;
    let varbind_tlv_len = 2 + varbind_content_len;

    // Varbind list SEQUENCE: tag(1) + len(1) + single varbind
    let varbind_list_content_len = varbind_tlv_len;
    let varbind_list_tlv_len = 2 + varbind_list_content_len;

    // Request ID INTEGER: 02 01 01  (value = 1)
    let request_id_tlv_len: usize = 3;
    // Error status INTEGER: 02 01 00
    let error_status_tlv_len: usize = 3;
    // Error index INTEGER: 02 01 00
    let error_index_tlv_len: usize = 3;

    // GetRequest PDU (0xA0): tag(1) + len(1) + contents
    let pdu_content_len = request_id_tlv_len
        + error_status_tlv_len
        + error_index_tlv_len
        + varbind_list_tlv_len;
    let pdu_tlv_len = 2 + pdu_content_len;

    // SNMP version INTEGER: 02 01 01  (version 2c = value 1)
    let version_tlv_len: usize = 3;

    // Community OCTET STRING: 04 <len> <bytes>
    let community_tlv_len = 2 + community_bytes.len();

    // Outer SEQUENCE: tag(1) + len(1) + version + community + PDU
    let message_content_len = version_tlv_len + community_tlv_len + pdu_tlv_len;

    // Allocate buffer and write the packet.
    let total_len = 2 + message_content_len;
    let mut pkt = Vec::with_capacity(total_len);

    // Outer SEQUENCE
    pkt.push(0x30);
    push_ber_length(&mut pkt, message_content_len);

    // Version: INTEGER 1 (SNMPv2c)
    pkt.extend_from_slice(&[0x02, 0x01, 0x01]);

    // Community: OCTET STRING
    pkt.push(0x04);
    push_ber_length(&mut pkt, community_bytes.len());
    pkt.extend_from_slice(community_bytes);

    // GetRequest PDU (context-specific constructed, tag 0)
    pkt.push(0xA0);
    push_ber_length(&mut pkt, pdu_content_len);

    // Request ID: INTEGER 1
    pkt.extend_from_slice(&[0x02, 0x01, 0x01]);
    // Error status: INTEGER 0
    pkt.extend_from_slice(&[0x02, 0x01, 0x00]);
    // Error index: INTEGER 0
    pkt.extend_from_slice(&[0x02, 0x01, 0x00]);

    // Varbind list SEQUENCE
    pkt.push(0x30);
    push_ber_length(&mut pkt, varbind_list_content_len);

    // Varbind SEQUENCE
    pkt.push(0x30);
    push_ber_length(&mut pkt, varbind_content_len);

    // OID
    pkt.push(0x06);
    push_ber_length(&mut pkt, oid_value.len());
    pkt.extend_from_slice(oid_value);

    // NULL
    pkt.extend_from_slice(&[0x05, 0x00]);

    pkt
}

/// Push a BER definite-form length.  Handles lengths up to 127 with the
/// short form and larger lengths with the long form (1-byte count).
fn push_ber_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Attempt to extract the sysDescr value from an SNMP GetResponse.
///
/// This is a best-effort parser: we look for the varbind list inside the
/// response PDU and extract the OCTET STRING value of the first binding.
fn parse_sys_descr(data: &[u8]) -> Option<String> {
    // The response is: SEQUENCE { version, community, GetResponse-PDU { ... } }
    // We walk through the BER structure to reach the first varbind value.

    let mut pos = 0;

    // Outer SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_outer_len, consumed) = read_ber_length(&data[pos..])?;
    pos += consumed;

    // Version INTEGER — skip
    pos = skip_tlv(data, pos)?;

    // Community OCTET STRING — skip
    pos = skip_tlv(data, pos)?;

    // GetResponse PDU — tag should be 0xA2
    if pos >= data.len() || data[pos] != 0xA2 {
        return None;
    }
    pos += 1;
    let (_pdu_len, consumed) = read_ber_length(&data[pos..])?;
    pos += consumed;

    // Request ID — skip
    pos = skip_tlv(data, pos)?;
    // Error status — skip
    pos = skip_tlv(data, pos)?;
    // Error index — skip
    pos = skip_tlv(data, pos)?;

    // Varbind list SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_vbl_len, consumed) = read_ber_length(&data[pos..])?;
    pos += consumed;

    // First varbind SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_vb_len, consumed) = read_ber_length(&data[pos..])?;
    pos += consumed;

    // OID — skip
    pos = skip_tlv(data, pos)?;

    // Value — should be OCTET STRING (0x04)
    if pos >= data.len() {
        return None;
    }
    let tag = data[pos];
    pos += 1;
    let (val_len, consumed) = read_ber_length(&data[pos..])?;
    pos += consumed;

    if pos + val_len > data.len() {
        return None;
    }

    if tag == 0x04 {
        // OCTET STRING — return as UTF-8 (lossy)
        Some(String::from_utf8_lossy(&data[pos..pos + val_len]).to_string())
    } else {
        // Some other type — just hex-encode it.
        let hex: String = data[pos..pos + val_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("[type 0x{:02x}] {}", tag, hex))
    }
}

/// Read a BER length and return (length_value, bytes_consumed).
fn read_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return None;
        }
        Some((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return None;
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Some((len, 3))
    } else {
        None
    }
}

/// Skip over one TLV element and return the new position.
fn skip_tlv(data: &[u8], pos: usize) -> Option<usize> {
    if pos >= data.len() {
        return None;
    }
    let mut p = pos + 1; // skip tag
    let (len, consumed) = read_ber_length(&data[p..])?;
    p += consumed;
    p += len;
    if p > data.len() {
        return None;
    }
    Some(p)
}

#[async_trait]
impl VulnCheck for SnmpCheck {
    fn name(&self) -> &str {
        "snmp-community-check"
    }

    fn description(&self) -> &str {
        "Checks for default or weak SNMP community strings"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        service.port == 161 || name.contains("snmp")
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[snmp-community-check] Checking SNMP on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);
        let target_addr = format!("{}:{}", service.host, service.port);

        // Bind to an ephemeral local UDP port.  Use 0.0.0.0:0 so the OS
        // picks a free port.
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "[snmp-community-check] Failed to bind UDP socket: {}",
                    e
                );
                return Ok(findings);
            }
        };

        for community in COMMUNITY_STRINGS {
            let pkt = build_snmp_get_request(community);

            // Send the request.
            if let Err(e) = socket.send_to(&pkt, &target_addr).await {
                tracing::debug!(
                    "[snmp-community-check] Send to {} with community '{}' failed: {}",
                    target_addr,
                    community,
                    e
                );
                continue;
            }

            // Wait for a response with a 3-second timeout.
            let mut recv_buf = vec![0u8; 4096];
            let recv_result = tokio::time::timeout(
                Duration::from_secs(3),
                socket.recv_from(&mut recv_buf),
            )
            .await;

            let (n, _from) = match recv_result {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    tracing::debug!(
                        "[snmp-community-check] Recv error for '{}' from {}: {}",
                        community,
                        target_addr,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    // Timeout — community string not accepted.
                    tracing::debug!(
                        "[snmp-community-check] Timeout for community '{}' on {}",
                        community,
                        target_addr
                    );
                    continue;
                }
            };

            let response = &recv_buf[..n];

            // A valid SNMP response starts with 0x30 (SEQUENCE) and should
            // contain a GetResponse PDU (tag 0xA2).
            if response.is_empty() || response[0] != 0x30 {
                continue;
            }

            tracing::warn!(
                "[snmp-community-check] Community '{}' accepted by {}",
                community,
                target_addr
            );

            // Try to extract sysDescr.
            let sys_descr = parse_sys_descr(response);
            let sys_descr_text = sys_descr
                .as_deref()
                .unwrap_or("<could not parse>");

            // Determine severity based on which community string was accepted.
            let (title, severity, cvss, cwe) = if *community == "public"
                || *community == "private"
            {
                (
                    "SNMP Default Community String".to_string(),
                    Severity::High,
                    Some(7.5),
                    "CWE-798",
                )
            } else {
                (
                    "SNMP Weak Community String".to_string(),
                    Severity::Medium,
                    Some(5.3),
                    "CWE-521",
                )
            };

            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title,
                severity,
                cvss_score: cvss,
                cvss_vector: Some(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                ),
                cwe_id: Some(cwe.to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("SNMP".to_string()),
                description: format!(
                    "The SNMP agent on {} accepted the community string '{}'. \
                     This allows an attacker to read device configuration, routing tables, \
                     interface details, and other sensitive management data. \
                     sysDescr: {}",
                    target_addr, community, sys_descr_text
                ),
                evidence: vec![
                    Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Community string: '{}'", community),
                        label: Some("Accepted Community String".to_string()),
                    },
                    Evidence {
                        evidence_type: EvidenceType::Banner,
                        content: sys_descr_text.to_string(),
                        label: Some("sysDescr.0".to_string()),
                    },
                ],
                remediation: format!(
                    "Change the SNMP community string '{}' to a strong, unique value. \
                     Prefer SNMPv3 with authentication and encryption (authPriv). \
                     Restrict SNMP access to management networks via ACLs.",
                    community
                ),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/798.html".to_string(),
                    "https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[snmp-community-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
