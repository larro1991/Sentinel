use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x509_parser::prelude::*;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// SSL/TLS configuration checker — inspects certificate chains and TLS parameters.
pub struct SslCheck;

impl SslCheck {
    pub fn new() -> Self {
        Self
    }
}

/// A permissive certificate verifier that captures the cert chain for inspection
/// without rejecting any connections.
#[derive(Debug)]
struct CaptureVerifier;

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[async_trait]
impl VulnCheck for SslCheck {
    fn name(&self) -> &str {
        "ssl-tls-check"
    }

    fn description(&self) -> &str {
        "Checks SSL/TLS configuration: certificate validity, key strength, and common misconfigurations"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        service.tls
            || matches!(service.port, 443 | 8443 | 993 | 995 | 465 | 636)
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[ssl-tls-check] Checking TLS on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);

        // Build TLS config with our permissive verifier.
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CaptureVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));

        // Determine the server name for SNI.
        let server_name: ServerName<'static> = match ServerName::try_from(service.host.clone()) {
            Ok(name) => name,
            Err(_) => {
                tracing::warn!("[ssl-tls-check] Cannot create DNS name for '{}', skipping", service.host);
                return Ok(findings);
            }
        };

        // Connect with timeout.
        let addr = format!("{}:{}", service.host, service.port);
        let tcp_stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("[ssl-tls-check] TCP connect failed to {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::warn!("[ssl-tls-check] TCP connect timed out to {}", addr);
                return Ok(findings);
            }
        };

        let tls_stream = match tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, tcp_stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("[ssl-tls-check] TLS handshake failed to {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::warn!("[ssl-tls-check] TLS handshake timed out to {}", addr);
                return Ok(findings);
            }
        };

        // Get the peer certificates from the TLS connection.
        let (_io, client_conn) = tls_stream.into_inner();
        let peer_certs = match client_conn.peer_certificates() {
            Some(certs) if !certs.is_empty() => certs.to_vec(),
            _ => {
                tracing::warn!("[ssl-tls-check] No peer certificates from {}", addr);
                return Ok(findings);
            }
        };

        // Parse the end-entity (leaf) certificate.
        let leaf_der = &peer_certs[0];
        let (_, cert) = match X509Certificate::from_der(leaf_der.as_ref()) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!("[ssl-tls-check] Failed to parse certificate from {}: {}", addr, e);
                return Ok(findings);
            }
        };

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let not_before_str = cert.validity().not_before.to_string();
        let not_after_str = cert.validity().not_after.to_string();
        let now = Utc::now();

        let mut cert_details = format!(
            "Subject: {}\nIssuer: {}\nNot Before: {}\nNot After: {}",
            subject, issuer, not_before_str, not_after_str
        );

        // Extract key size.
        let key_info = cert.public_key();
        let key_algorithm = format!("{:?}", key_info.algorithm.algorithm);
        cert_details.push_str(&format!("\nKey Algorithm: {}", key_algorithm));

        // Extract SANs.
        let sans: Vec<String> = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san_ext| {
                san_ext
                    .value
                    .general_names
                    .iter()
                    .map(|name| format!("{:?}", name))
                    .collect()
            })
            .unwrap_or_default();

        if !sans.is_empty() {
            cert_details.push_str(&format!("\nSANs: {}", sans.join(", ")));
        }

        // Check certificate validity using raw timestamps.
        let not_after_ts = cert.validity().not_after.timestamp();
        let now_ts = now.timestamp();
        let thirty_days_secs: i64 = 30 * 24 * 60 * 60;

        if not_after_ts < now_ts {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Expired SSL/TLS Certificate".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.4),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string()),
                cwe_id: Some("CWE-295".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("TLS Certificate".to_string()),
                description: format!(
                    "The SSL/TLS certificate has expired. Expiry: {}",
                    not_after_str
                ),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Certificate,
                    content: cert_details.clone(),
                    label: Some("Certificate Details".to_string()),
                }],
                remediation: "Renew the SSL/TLS certificate immediately.".to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/295.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        } else if not_after_ts - now_ts < thirty_days_secs {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "SSL/TLS Certificate Expiring Soon".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.3),
                cvss_vector: None,
                cwe_id: Some("CWE-298".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("TLS Certificate".to_string()),
                description: format!(
                    "The SSL/TLS certificate will expire within 30 days. Expiry: {}",
                    not_after_str
                ),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Certificate,
                    content: cert_details.clone(),
                    label: Some("Certificate Details".to_string()),
                }],
                remediation: "Renew the SSL/TLS certificate before it expires.".to_string(),
                references: vec![],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Self-signed certificate (issuer == subject)
        if cert.issuer() == cert.subject() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Self-Signed SSL/TLS Certificate".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.9),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                cwe_id: Some("CWE-295".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("TLS Certificate".to_string()),
                description: "The SSL/TLS certificate is self-signed, which prevents proper chain-of-trust validation.".to_string(),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Certificate,
                    content: cert_details.clone(),
                    label: Some("Certificate Details".to_string()),
                }],
                remediation: "Replace the self-signed certificate with one issued by a trusted Certificate Authority.".to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/295.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Weak RSA key (< 2048 bits)
        // Use the raw SPKI length to estimate RSA key size.
        let spki_len = key_info.raw.len();
        if key_algorithm.contains("rsa") || key_algorithm.contains("RSA") {
            let key_len = spki_len;
            // Rough heuristic from DER-encoded SPKI size:
            // 1024-bit RSA SPKI: ~160-170 bytes, 2048-bit: ~290-300 bytes, 4096-bit: ~550+ bytes
            let estimated_bits = if key_len < 200 {
                1024
            } else if key_len < 400 {
                2048
            } else {
                4096
            };

            cert_details.push_str(&format!("\nEstimated RSA Key Size: {} bits", estimated_bits));

            if estimated_bits < 2048 {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "Weak RSA Key Size".to_string(),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                    cwe_id: Some("CWE-326".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("TLS Certificate".to_string()),
                    description: format!(
                        "The RSA key size is approximately {} bits, which is below the recommended minimum of 2048 bits.",
                        estimated_bits
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::Certificate,
                        content: cert_details.clone(),
                        label: Some("Certificate Details".to_string()),
                    }],
                    remediation: "Generate a new certificate with at least a 2048-bit RSA key, or preferably use ECDSA with P-256 or P-384.".to_string(),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/326.html".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        // Check: Missing SANs
        if sans.is_empty() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing Subject Alternative Names (SANs)".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.7),
                cvss_vector: None,
                cwe_id: Some("CWE-295".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("TLS Certificate".to_string()),
                description: "The certificate does not contain Subject Alternative Name extensions. Modern browsers require SANs for hostname verification.".to_string(),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Certificate,
                    content: cert_details.clone(),
                    label: Some("Certificate Details".to_string()),
                }],
                remediation: "Regenerate the certificate with appropriate Subject Alternative Name entries.".to_string(),
                references: vec![],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Hostname mismatch — see if any SAN or CN matches the target host
        let host_lower = service.host.to_lowercase();
        let cn_matches = subject.to_lowercase().contains(&host_lower);
        let san_matches = sans.iter().any(|s| {
            let s_lower = s.to_lowercase();
            s_lower.contains(&host_lower)
        });

        if !cn_matches && !san_matches && !sans.is_empty() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Certificate Hostname Mismatch".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.4),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string()),
                cwe_id: Some("CWE-297".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("TLS Certificate".to_string()),
                description: format!(
                    "The certificate does not match the hostname '{}'. Subject: {}, SANs: {:?}",
                    service.host, subject, sans
                ),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Certificate,
                    content: cert_details.clone(),
                    label: Some("Certificate Details".to_string()),
                }],
                remediation: "Ensure the certificate includes the correct hostname in the Subject Alternative Name field.".to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/297.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[ssl-tls-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
