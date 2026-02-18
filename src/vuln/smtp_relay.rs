use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// Open SMTP relay detection — connects, issues EHLO, MAIL FROM, and RCPT TO
/// with an external domain. Never sends DATA.
pub struct SmtpRelayCheck;

impl SmtpRelayCheck {
    pub fn new() -> Self {
        Self
    }
}

/// Read a single line from the SMTP connection with a timeout.
async fn read_smtp_line(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> Option<String> {
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => Some(line),
        _ => None,
    }
}

#[async_trait]
impl VulnCheck for SmtpRelayCheck {
    fn name(&self) -> &str {
        "smtp-relay-check"
    }

    fn description(&self) -> &str {
        "Detects open SMTP relay (stops before DATA)"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true // Never sends DATA, so no email is actually relayed.
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        name.contains("smtp") || name.contains("mail") || matches!(service.port, 25 | 465 | 587)
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[smtp-relay-check] Checking relay on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);
        let addr = format!("{}:{}", service.host, service.port);

        let stream = match tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return Ok(findings),
        };

        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let mut transcript = String::new();

        // Read banner.
        match read_smtp_line(&mut reader).await {
            Some(line) => {
                transcript.push_str(&format!("S: {}", line));
            }
            None => return Ok(findings),
        }

        // Send EHLO.
        let ehlo_cmd = "EHLO sentinel.test\r\n";
        transcript.push_str(&format!("C: {}", ehlo_cmd));
        if writer.write_all(ehlo_cmd.as_bytes()).await.is_err() {
            return Ok(findings);
        }

        // Read EHLO response (may be multi-line).
        loop {
            match read_smtp_line(&mut reader).await {
                Some(resp) => {
                    transcript.push_str(&format!("S: {}", resp));
                    // Multi-line responses have '-' at position 3; last line has ' '.
                    if resp.len() >= 4 && resp.as_bytes()[3] == b' ' {
                        break;
                    }
                }
                None => break,
            }
        }

        // Send MAIL FROM with an external address.
        let mail_from = "MAIL FROM:<test@sentinel.test>\r\n";
        transcript.push_str(&format!("C: {}", mail_from));
        if writer.write_all(mail_from.as_bytes()).await.is_err() {
            return Ok(findings);
        }

        let mail_resp = match read_smtp_line(&mut reader).await {
            Some(line) => {
                transcript.push_str(&format!("S: {}", line));
                line
            }
            None => return Ok(findings),
        };
        let _ = mail_resp; // Acknowledge MAIL FROM response.

        // Send RCPT TO with an external domain.
        let rcpt_to = "RCPT TO:<test@external-domain.com>\r\n";
        transcript.push_str(&format!("C: {}", rcpt_to));
        if writer.write_all(rcpt_to.as_bytes()).await.is_err() {
            return Ok(findings);
        }

        let rcpt_resp = match read_smtp_line(&mut reader).await {
            Some(line) => {
                transcript.push_str(&format!("S: {}", line));
                line
            }
            None => return Ok(findings),
        };

        // Send QUIT (clean disconnect).
        let _ = writer.write_all(b"QUIT\r\n").await;

        // Check if RCPT TO was accepted (250 or 251).
        let rcpt_code = rcpt_resp.trim().chars().take(3).collect::<String>();
        if rcpt_code == "250" || rcpt_code == "251" {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Open SMTP Relay Detected".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N".to_string(),
                ),
                cwe_id: Some("CWE-284".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("SMTP Server".to_string()),
                description: format!(
                    "The SMTP server at {} accepted RCPT TO for an external domain \
                     (external-domain.com) with response code {}. This indicates an \
                     open relay that can be abused to send spam or phishing emails.",
                    addr, rcpt_code
                ),
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::Raw,
                    content: transcript,
                    label: Some("SMTP Relay Test Transcript".to_string()),
                }],
                remediation: "Configure the SMTP server to only relay mail for authenticated \
                    users or authorized domains. Ensure relay restrictions are properly set."
                    .to_string(),
                references: vec![
                    "https://www.mailradar.com/openrelay/".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[smtp-relay-check] Completed on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
