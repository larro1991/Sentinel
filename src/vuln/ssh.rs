use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// SSH version checker — connects to SSH services and checks for outdated
/// or insecure protocol versions.
pub struct SshCheck;

impl SshCheck {
    pub fn new() -> Self {
        Self
    }
}

/// Parse the SSH banner to extract the software name and version.
/// Example banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
fn parse_ssh_banner(banner: &str) -> Option<SshVersion> {
    let trimmed = banner.trim();
    if !trimmed.starts_with("SSH-") {
        return None;
    }

    let parts: Vec<&str> = trimmed.splitn(3, '-').collect();
    if parts.len() < 3 {
        return None;
    }

    let protocol = parts[1].to_string(); // "2.0" or "1.99" or "1.0"
    let software_str = parts[2].to_string();

    // Try to extract the software name and version number.
    let (software, version) = if software_str.starts_with("OpenSSH_") {
        let ver_part = &software_str["OpenSSH_".len()..];
        // Version like "8.9p1 Ubuntu-3" — take up to first space or letter after digits.
        let version_num = extract_version_number(ver_part);
        ("OpenSSH".to_string(), version_num)
    } else if software_str.starts_with("dropbear_") || software_str.starts_with("dropbear") {
        let offset = if software_str.starts_with("dropbear_") {
            "dropbear_".len()
        } else {
            "dropbear".len()
        };
        let ver_part = &software_str[offset..];
        let version_num = extract_version_number(ver_part);
        ("Dropbear".to_string(), version_num)
    } else {
        (software_str.clone(), None)
    };

    Some(SshVersion {
        protocol,
        software,
        version,
        raw: trimmed.to_string(),
    })
}

/// Extract a version number (major.minor or just a number) from the start of a string.
fn extract_version_number(s: &str) -> Option<(u32, u32)> {
    // Try "X.Y" pattern first.
    let numeric_part: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();

    let parts: Vec<&str> = numeric_part.split('.').collect();
    match parts.len() {
        1 => {
            // Single number like "2022" for Dropbear
            parts[0].parse::<u32>().ok().map(|major| (major, 0))
        }
        2.. => {
            let major = parts[0].parse::<u32>().ok()?;
            let minor = parts[1].parse::<u32>().ok()?;
            Some((major, minor))
        }
        _ => None,
    }
}

struct SshVersion {
    protocol: String,
    software: String,
    version: Option<(u32, u32)>,
    #[allow(dead_code)]
    raw: String,
}

impl SshVersion {
    /// Check if this is SSH protocol v1.
    fn is_v1(&self) -> bool {
        self.protocol.starts_with("1.") && !self.protocol.starts_with("1.99")
    }
}

#[async_trait]
impl VulnCheck for SshCheck {
    fn name(&self) -> &str {
        "ssh-version-check"
    }

    fn description(&self) -> &str {
        "Checks SSH version for known vulnerabilities and outdated software"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        name.contains("ssh") || service.port == 22
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[ssh-version-check] Checking SSH on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);

        // Connect and read the SSH banner.
        let addr = format!("{}:{}", service.host, service.port);
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("[ssh-version-check] TCP connect failed to {}: {}", addr, e);
                return Ok(findings);
            }
            Err(_) => {
                tracing::warn!("[ssh-version-check] TCP connect timed out to {}", addr);
                return Ok(findings);
            }
        };

        // SSH servers send their identification string immediately upon connection.
        let mut buf = vec![0u8; 512];
        let banner = match tokio::time::timeout(
            Duration::from_secs(5),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
            _ => {
                tracing::warn!("[ssh-version-check] No banner received from {}", addr);
                return Ok(findings);
            }
        };

        tracing::info!("[ssh-version-check] Banner from {}: {}", addr, banner);

        let evidence = vec![Evidence {
            evidence_type: EvidenceType::Banner,
            content: banner.clone(),
            label: Some("SSH Banner".to_string()),
        }];

        let parsed = match parse_ssh_banner(&banner) {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "[ssh-version-check] Could not parse SSH banner: {}",
                    banner
                );
                return Ok(findings);
            }
        };

        // Check: SSH protocol version 1
        if parsed.is_v1() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "SSH Protocol Version 1 Detected".to_string(),
                severity: Severity::Critical,
                cvss_score: Some(9.8),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                cwe_id: Some("CWE-327".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("SSH".to_string()),
                description: "The SSH server supports protocol version 1, which has known cryptographic weaknesses including susceptibility to man-in-the-middle attacks.".to_string(),
                evidence: evidence.clone(),
                remediation: "Disable SSH protocol version 1 and only allow protocol version 2.".to_string(),
                references: vec![
                    "https://www.openssh.com/legacy.html".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check software-specific versions.
        if parsed.software == "OpenSSH" {
            if let Some((major, minor)) = parsed.version {
                if major < 8 {
                    // OpenSSH < 8.0 has multiple CVEs
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: "Outdated OpenSSH Version (< 8.0)".to_string(),
                        severity: Severity::High,
                        cvss_score: Some(7.5),
                        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                        cwe_id: Some("CWE-327".to_string()),
                        cve_ids: vec![
                            "CVE-2019-6111".to_string(),
                            "CVE-2019-6109".to_string(),
                            "CVE-2018-15919".to_string(),
                        ],
                        affected_asset: asset.clone(),
                        affected_component: Some("SSH".to_string()),
                        description: format!(
                            "OpenSSH version {}.{} is significantly outdated and affected by multiple known vulnerabilities.",
                            major, minor
                        ),
                        evidence: evidence.clone(),
                        remediation: "Upgrade OpenSSH to the latest stable version (9.x or later).".to_string(),
                        references: vec![
                            "https://www.openssh.com/security.html".to_string(),
                        ],
                        module_name: self.name().to_string(),
                        timestamp: Utc::now(),
                    });
                } else if major < 9 {
                    // OpenSSH >= 8.0 but < 9.0
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: "Aging OpenSSH Version (< 9.0)".to_string(),
                        severity: Severity::Medium,
                        cvss_score: Some(5.3),
                        cvss_vector: None,
                        cwe_id: Some("CWE-327".to_string()),
                        cve_ids: vec![],
                        affected_asset: asset.clone(),
                        affected_component: Some("SSH".to_string()),
                        description: format!(
                            "OpenSSH version {}.{} is aging and may be missing important security patches. OpenSSH 9.x includes improvements to key exchange and deprecated algorithms.",
                            major, minor
                        ),
                        evidence: evidence.clone(),
                        remediation: "Upgrade OpenSSH to the latest stable version (9.x or later).".to_string(),
                        references: vec![
                            "https://www.openssh.com/releasenotes.html".to_string(),
                        ],
                        module_name: self.name().to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        } else if parsed.software == "Dropbear" {
            if let Some((major, _minor)) = parsed.version {
                // Dropbear versions are year-based: 2022.83, 2020.81, etc.
                if major < 2022 {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: "Outdated Dropbear SSH Version".to_string(),
                        severity: Severity::Medium,
                        cvss_score: Some(5.3),
                        cvss_vector: None,
                        cwe_id: Some("CWE-327".to_string()),
                        cve_ids: vec![],
                        affected_asset: asset.clone(),
                        affected_component: Some("SSH".to_string()),
                        description: format!(
                            "Dropbear SSH version {} is outdated (< 2022.83) and may contain known vulnerabilities.",
                            major
                        ),
                        evidence: evidence.clone(),
                        remediation: "Upgrade Dropbear to the latest stable version.".to_string(),
                        references: vec![
                            "https://matt.ucc.asn.au/dropbear/CHANGES".to_string(),
                        ],
                        module_name: self.name().to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        tracing::info!(
            "[ssh-version-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
