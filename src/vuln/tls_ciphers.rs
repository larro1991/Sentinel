use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// Weak TLS cipher enumeration — checks protocol version and cipher suites
/// for RC4, 3DES, CBC, and old protocol versions.
pub struct TlsCipherCheck;

impl TlsCipherCheck {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VulnCheck for TlsCipherCheck {
    fn name(&self) -> &str {
        "tls-cipher-check"
    }

    fn description(&self) -> &str {
        "Enumerates TLS cipher suites and protocol versions for weak configurations"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        service.tls
            || matches!(
                service.port,
                443 | 465 | 636 | 853 | 993 | 995 | 5986 | 8443
            )
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[tls-cipher-check] Checking TLS on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);

        // Use rustls to connect and inspect the negotiated cipher/protocol.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let server_name = match rustls_pki_types::ServerName::try_from(service.host.as_str()) {
            Ok(name) => name.to_owned(),
            Err(_) => {
                // Try as IP.
                match service.host.parse::<std::net::IpAddr>() {
                    Ok(ip) => rustls_pki_types::ServerName::from(ip),
                    Err(_) => return Ok(findings),
                }
            }
        };

        let addr = format!("{}:{}", service.host, service.port);
        let tcp = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return Ok(findings),
        };

        let tls_stream = match tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                // TLS handshake failed — might indicate older protocol only.
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "TLS Handshake Failed".to_string(),
                    severity: Severity::Medium,
                    cvss_score: Some(5.3),
                    cvss_vector: None,
                    cwe_id: Some("CWE-326".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "TLS handshake with {} failed using modern cipher suites. \
                         The server may only support deprecated protocols (TLS 1.0/1.1) \
                         or weak cipher suites not supported by the client.",
                        addr
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("TLS handshake to {} failed", addr),
                        label: Some("Handshake Result".to_string()),
                    }],
                    remediation: "Ensure the server supports TLS 1.2 or higher with \
                        modern cipher suites."
                        .to_string(),
                    references: vec![
                        "https://wiki.mozilla.org/Security/Server_Side_TLS".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
                return Ok(findings);
            }
        };

        let (_, conn) = tls_stream.get_ref();

        // Check negotiated protocol version.
        let protocol_version = conn.protocol_version();
        let cipher_suite = conn.negotiated_cipher_suite();

        let mut evidence_lines = Vec::new();

        if let Some(version) = protocol_version {
            let version_str = format!("{:?}", version);
            evidence_lines.push(format!("Protocol: {}", version_str));

            // TLS 1.0 and 1.1 are deprecated.
            if version_str.contains("1.0") || version_str.contains("1.1") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "Deprecated TLS Protocol Version".to_string(),
                    severity: Severity::Medium,
                    cvss_score: Some(5.3),
                    cvss_vector: None,
                    cwe_id: Some("CWE-326".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "The server negotiated {} which is deprecated. \
                         TLS 1.0 and 1.1 have known vulnerabilities including BEAST and POODLE.",
                        version_str
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Negotiated protocol: {}", version_str),
                        label: Some("TLS Version".to_string()),
                    }],
                    remediation: "Disable TLS 1.0 and 1.1. Configure the server to \
                        only support TLS 1.2 and TLS 1.3."
                        .to_string(),
                    references: vec![
                        "https://datatracker.ietf.org/doc/rfc8996/".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Check if TLS 1.3 is not used (informational).
            if !version_str.contains("1.3") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "TLS 1.3 Not Negotiated".to_string(),
                    severity: Severity::Info,
                    cvss_score: None,
                    cvss_vector: None,
                    cwe_id: None,
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "The server negotiated {} instead of TLS 1.3. While TLS 1.2 is \
                         still considered secure, TLS 1.3 offers improved performance \
                         and stronger security guarantees.",
                        version_str
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Negotiated: {}", version_str),
                        label: Some("TLS Version".to_string()),
                    }],
                    remediation: "Consider enabling TLS 1.3 support on the server.".to_string(),
                    references: vec![
                        "https://wiki.mozilla.org/Security/Server_Side_TLS".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        // Check negotiated cipher suite for weak algorithms.
        if let Some(suite) = cipher_suite {
            let suite_name = format!("{:?}", suite.suite());
            evidence_lines.push(format!("Cipher: {}", suite_name));
            let suite_lower = suite_name.to_lowercase();

            if suite_lower.contains("rc4") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "RC4 Cipher Suite Accepted".to_string(),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    cvss_vector: None,
                    cwe_id: Some("CWE-327".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "The server negotiated an RC4-based cipher suite ({}). \
                         RC4 is cryptographically broken and should not be used.",
                        suite_name
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Cipher suite: {}", suite_name),
                        label: Some("Weak Cipher".to_string()),
                    }],
                    remediation: "Disable all RC4 cipher suites on the server.".to_string(),
                    references: vec!["https://datatracker.ietf.org/doc/rfc7465/".to_string()],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }

            if suite_lower.contains("3des") || suite_lower.contains("des_ede3") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "3DES Cipher Suite Accepted".to_string(),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    cvss_vector: None,
                    cwe_id: Some("CWE-327".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "The server negotiated a 3DES cipher suite ({}). \
                         3DES has a 64-bit block size vulnerable to Sweet32 attacks.",
                        suite_name
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Cipher suite: {}", suite_name),
                        label: Some("Weak Cipher".to_string()),
                    }],
                    remediation: "Disable all 3DES cipher suites. Use AES-GCM or \
                        ChaCha20 ciphers instead."
                        .to_string(),
                    references: vec![
                        "https://sweet32.info/".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }

            if suite_lower.contains("cbc") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "CBC Mode Cipher Suite Negotiated".to_string(),
                    severity: Severity::Low,
                    cvss_score: Some(3.7),
                    cvss_vector: None,
                    cwe_id: Some("CWE-327".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Configuration".to_string()),
                    description: format!(
                        "The server negotiated a CBC-mode cipher suite ({}). \
                         CBC ciphers in TLS are susceptible to padding oracle attacks \
                         (POODLE, Lucky13).",
                        suite_name
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Raw,
                        content: format!("Cipher suite: {}", suite_name),
                        label: Some("CBC Cipher".to_string()),
                    }],
                    remediation: "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) \
                        over CBC mode."
                        .to_string(),
                    references: vec![
                        "https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/"
                            .to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        tracing::info!(
            "[tls-cipher-check] Completed on {}: {} findings ({})",
            asset,
            findings.len(),
            evidence_lines.join(", "),
        );

        Ok(findings)
    }
}
