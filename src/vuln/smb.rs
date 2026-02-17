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

/// SMB signing checker — connects to port 445 and sends an SMB1 Negotiate
/// Protocol Request to determine whether SMB signing is required, enabled, or
/// disabled.  Also flags the availability of SMBv1 itself (EternalBlue risk).
pub struct SmbCheck;

impl SmbCheck {
    pub fn new() -> Self {
        Self
    }
}

// ─── SMB1 Negotiate Protocol Request ────────────────────────────────────────
//
// This is a minimal, well-known SMB1 Negotiate Protocol Request that proposes
// only "NT LM 0.12" (the NT LAN Manager dialect, i.e. SMBv1/CIFS).  The
// response tells us the server's capabilities and signing policy.
//
// Layout:
//   NetBIOS Session Service header  (4 bytes)
//     ├─ Type:   0x00 (Session Message)
//     └─ Length: 0x00 0x00 0x54 (84 bytes follow)
//   SMB Header (32 bytes)
//     ├─ Protocol: 0xFF 'S' 'M' 'B'
//     ├─ Command:  0x72  (Negotiate)
//     ├─ Status:   0x00000000
//     ├─ Flags:    0x18  (Canonicalized paths | Case-insensitive)
//     ├─ Flags2:   0xC853  (Unicode | NT Status | Extended Security | Long Names)
//     └─ rest zeroed (PID/MID/TID etc.)
//   Negotiate Request body (52 bytes)
//     ├─ Word Count: 0x00
//     ├─ Byte Count: 0x31 0x00  (49 bytes of dialects)
//     └─ Dialect: 0x02 "NT LM 0.12" 0x00
//                 0x02 "SMB 2.002"  0x00
//                 0x02 "SMB 2.???"  0x00

const SMB1_NEGOTIATE_REQUEST: [u8; 84] = [
    // --- NetBIOS Session Service header ---
    0x00,                               // Type: Session Message
    0x00, 0x00, 0x54,                   // Length: 84 bytes
    // --- SMB Header ---
    0xFF, 0x53, 0x4D, 0x42,            // Protocol: \xFFSMB
    0x72,                               // Command: Negotiate (0x72)
    0x00, 0x00, 0x00, 0x00,            // Status: SUCCESS
    0x18,                               // Flags: 0x18
    0x53, 0xC8,                         // Flags2: 0xC853
    0x00, 0x00,                         // PID High
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,            // Signature
    0x00, 0x00,                         // Reserved
    0x00, 0x00,                         // Tree ID
    0x00, 0x00,                         // Process ID
    0x00, 0x00,                         // User ID
    0x00, 0x00,                         // Multiplex ID
    // --- Negotiate Request ---
    0x00,                               // Word Count: 0
    0x31, 0x00,                         // Byte Count: 49
    // Dialect: "NT LM 0.12"
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30,
    0x2E, 0x31, 0x32, 0x00,
    // Dialect: "SMB 2.002"
    0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30,
    0x30, 0x32, 0x00,
    // Dialect: "SMB 2.???"
    0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F,
    0x3F, 0x3F, 0x00,
    // padding to reach stated length
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

// SMB1 Negotiate Response — SecurityMode flag bits (byte at offset 39 in the
// full packet, i.e. offset 35 from start of SMB header).
//
// For an SMB1 Negotiate response with Word Count > 0:
//   SecurityMode lives at SMB_Header(32 bytes) + WordCount(1 byte) + 2 bytes
//   = offset 39 in the full TCP payload (after the 4-byte NetBIOS header).
//
// Bit 0: Negotiate Security – User level (1) vs Share level (0)
// Bit 1: Negotiate Security – Challenge/Response (1) vs Plaintext passwords (0)
// Bit 2: Negotiate Security – Security Signatures (signing) enabled (1)
// Bit 3: Negotiate Security – Security Signatures required (1)
const SMB1_SECURITY_MODE_SIGNING_ENABLED: u8 = 0x04;
const SMB1_SECURITY_MODE_SIGNING_REQUIRED: u8 = 0x08;

/// Hex-encode a byte slice (lowercase).
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

#[async_trait]
impl VulnCheck for SmbCheck {
    fn name(&self) -> &str {
        "smb-signing-check"
    }

    fn description(&self) -> &str {
        "Checks SMB signing configuration and flags SMBv1 availability"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        service.port == 445
            || name.contains("microsoft-ds")
            || name.contains("smb")
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[smb-signing-check] Checking SMB on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);
        let addr = format!("{}:{}", service.host, service.port);

        // ── Connect ─────────────────────────────────────────────────────
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("[smb-signing-check] TCP connect failed to {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::warn!("[smb-signing-check] TCP connect timed out to {}", addr);
                return Ok(findings);
            }
        };

        // ── Send Negotiate Request ──────────────────────────────────────
        if let Err(e) = tokio::time::timeout(
            Duration::from_secs(5),
            stream.write_all(&SMB1_NEGOTIATE_REQUEST),
        )
        .await
        {
            tracing::warn!("[smb-signing-check] Write failed/timed out to {}: {}", addr, e);
            return Ok(findings);
        }

        // ── Read response ───────────────────────────────────────────────
        let mut buf = vec![0u8; 1024];
        let n = match tokio::time::timeout(
            Duration::from_secs(5),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => {
                tracing::warn!("[smb-signing-check] Empty response from {}", addr);
                return Ok(findings);
            }
            Ok(Err(e)) => {
                tracing::warn!("[smb-signing-check] Read error from {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::warn!("[smb-signing-check] Read timed out from {}", addr);
                return Ok(findings);
            }
        };

        let response = &buf[..n];

        // Build evidence from the first 64 bytes of the raw response.
        let evidence_len = std::cmp::min(64, response.len());
        let raw_hex = hex_encode(&response[..evidence_len]);
        let raw_evidence = Evidence {
            evidence_type: EvidenceType::Raw,
            content: raw_hex,
            label: Some("SMB Negotiate Response (first 64 bytes, hex)".to_string()),
        };

        // ── Validate SMB1 response ──────────────────────────────────────
        // Minimum: 4 (NetBIOS) + 32 (SMB Header) + 1 (Word Count) = 37 bytes
        // Security Mode is at offset 39 in the TCP payload (after NetBIOS header
        // at offset 0-3).
        //
        // Check the SMB1 magic: bytes 4..8 should be \xFFSMB
        let is_smb1 = response.len() >= 40
            && response[4] == 0xFF
            && response[5] == 0x53
            && response[6] == 0x4D
            && response[7] == 0x42;

        if !is_smb1 {
            // The server may have responded with SMB2/3 (0xFE 'SMB') instead,
            // meaning SMBv1 is not enabled.  Nothing further to check here with
            // our SMB1-only probe.
            tracing::info!(
                "[smb-signing-check] Server {} did not respond with SMB1 — likely SMBv1 disabled",
                addr
            );
            return Ok(findings);
        }

        // ── SMBv1 is enabled — that is itself a finding ─────────────────
        findings.push(Finding {
            id: Uuid::new_v4().to_string(),
            title: "SMBv1 Enabled".to_string(),
            severity: Severity::Medium,
            cvss_score: Some(7.5),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()),
            cwe_id: Some("CWE-327".to_string()),
            cve_ids: vec!["CVE-2017-0144".to_string()],
            affected_asset: asset.clone(),
            affected_component: Some("SMB".to_string()),
            description: "The server supports SMBv1, a deprecated protocol with known \
                          critical vulnerabilities including EternalBlue (CVE-2017-0144). \
                          SMBv1 should be disabled entirely."
                .to_string(),
            evidence: vec![raw_evidence.clone()],
            remediation: "Disable SMBv1 on the server. On Windows: \
                          Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. \
                          On Linux/Samba: set 'server min protocol = SMB2' in smb.conf."
                .to_string(),
            references: vec![
                "https://support.microsoft.com/en-us/topic/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-1a9b6349-4590-ce3e-52b1-b467e5b8e0b8".to_string(),
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144".to_string(),
            ],
            module_name: self.name().to_string(),
            timestamp: Utc::now(),
        });

        // ── Parse Security Mode ─────────────────────────────────────────
        // In an SMB1 Negotiate Response the Word Count lives at offset 36
        // (4 NetBIOS + 32 SMB header).  If Word Count > 0 the Security Mode
        // byte is at offset 39 (offset 36 + 1 WordCount byte + 2 bytes for
        // DialectIndex).
        let word_count = response[36];
        if word_count == 0 || response.len() < 40 {
            tracing::warn!(
                "[smb-signing-check] Unexpected word count {} or short response from {}",
                word_count,
                addr
            );
            return Ok(findings);
        }

        let security_mode = response[39];
        tracing::info!(
            "[smb-signing-check] SecurityMode byte from {}: 0x{:02x}",
            addr,
            security_mode
        );

        let signing_enabled = security_mode & SMB1_SECURITY_MODE_SIGNING_ENABLED != 0;
        let signing_required = security_mode & SMB1_SECURITY_MODE_SIGNING_REQUIRED != 0;

        if !signing_enabled {
            // Signing not even supported.
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "SMB Signing Disabled".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.3),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N".to_string()),
                cwe_id: Some("CWE-311".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("SMB".to_string()),
                description: format!(
                    "SMB signing is disabled on this server (SecurityMode: 0x{:02x}). \
                     Without signing support, an attacker on the network can tamper with \
                     SMB traffic or perform relay attacks.",
                    security_mode
                ),
                evidence: vec![
                    raw_evidence.clone(),
                    Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!(
                            "SecurityMode: 0x{:02x} — signing_enabled={}, signing_required={}",
                            security_mode, signing_enabled, signing_required
                        ),
                        label: Some("SMB Security Mode Flags".to_string()),
                    },
                ],
                remediation: "Enable and require SMB signing. On Windows domain controllers \
                              this is configured via Group Policy: \
                              'Microsoft network server: Digitally sign communications (always)'."
                    .to_string(),
                references: vec![
                    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing".to_string(),
                    "https://cwe.mitre.org/data/definitions/311.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        } else if !signing_required {
            // Signing supported but not enforced — relay attacks possible.
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "SMB Signing Not Required".to_string(),
                severity: Severity::High,
                cvss_score: Some(5.9),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                cwe_id: Some("CWE-311".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("SMB".to_string()),
                description: format!(
                    "SMB signing is enabled but not required on this server \
                     (SecurityMode: 0x{:02x}). An attacker can negotiate an unsigned \
                     session and perform SMB relay attacks (e.g., ntlmrelayx).",
                    security_mode
                ),
                evidence: vec![
                    raw_evidence.clone(),
                    Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!(
                            "SecurityMode: 0x{:02x} — signing_enabled={}, signing_required={}",
                            security_mode, signing_enabled, signing_required
                        ),
                        label: Some("SMB Security Mode Flags".to_string()),
                    },
                ],
                remediation: "Require SMB signing on all systems. On Windows: enable the \
                              Group Policy setting 'Microsoft network server: Digitally sign \
                              communications (always)'. On Samba: set 'server signing = mandatory' \
                              in smb.conf."
                    .to_string(),
                references: vec![
                    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing".to_string(),
                    "https://cwe.mitre.org/data/definitions/311.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[smb-signing-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
