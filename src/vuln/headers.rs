use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// HTTP security headers checker — verifies the presence and configuration
/// of important security response headers.
pub struct HeaderCheck;

impl HeaderCheck {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VulnCheck for HeaderCheck {
    fn name(&self) -> &str {
        "http-headers-check"
    }

    fn description(&self) -> &str {
        "Checks for missing or misconfigured HTTP security headers"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn applies_to(&self, service: &Service) -> bool {
        let name = service.service_name.to_lowercase();
        name.contains("http")
            || matches!(service.port, 80 | 443 | 8080 | 8443)
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[http-headers-check] Checking headers on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);

        let scheme = if service.tls || service.port == 443 || service.port == 8443 {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}/", scheme, service.host, service.port);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "[http-headers-check] Request failed to {}: {}",
                    url,
                    e
                );
                return Ok(findings);
            }
        };

        let headers = resp.headers().clone();

        // Build a string of all response headers for evidence.
        let headers_text: String = headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<binary>")))
            .collect::<Vec<_>>()
            .join("\n");

        let evidence = vec![Evidence {
            evidence_type: EvidenceType::HttpResponse,
            content: headers_text,
            label: Some("Response Headers".to_string()),
        }];

        // Check: Strict-Transport-Security (HTTPS only)
        if scheme == "https" && !headers.contains_key("strict-transport-security") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing Strict-Transport-Security Header".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.4),
                cvss_vector: None,
                cwe_id: Some("CWE-319".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The Strict-Transport-Security (HSTS) header is not set. This leaves users vulnerable to SSL stripping attacks and protocol downgrade attacks.".to_string(),
                evidence: evidence.clone(),
                remediation: "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: X-Content-Type-Options
        if !headers.contains_key("x-content-type-options") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing X-Content-Type-Options Header".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.7),
                cvss_vector: None,
                cwe_id: Some("CWE-16".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The X-Content-Type-Options header is not set. This allows browsers to MIME-sniff responses, potentially executing malicious content.".to_string(),
                evidence: evidence.clone(),
                remediation: "Add the header: X-Content-Type-Options: nosniff".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: X-Frame-Options
        if !headers.contains_key("x-frame-options") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing X-Frame-Options Header".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.4),
                cvss_vector: None,
                cwe_id: Some("CWE-1021".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The X-Frame-Options header is not set. This may allow the page to be embedded in iframes, enabling clickjacking attacks.".to_string(),
                evidence: evidence.clone(),
                remediation: "Add the header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Content-Security-Policy
        if !headers.contains_key("content-security-policy") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing Content-Security-Policy Header".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.4),
                cvss_vector: None,
                cwe_id: Some("CWE-16".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The Content-Security-Policy header is not set. CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks.".to_string(),
                evidence: evidence.clone(),
                remediation: "Implement a Content-Security-Policy header with appropriate directives for your application.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: X-XSS-Protection (deprecated but worth noting)
        if !headers.contains_key("x-xss-protection") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing X-XSS-Protection Header".to_string(),
                severity: Severity::Info,
                cvss_score: None,
                cvss_vector: None,
                cwe_id: Some("CWE-16".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The X-XSS-Protection header is not set. While this header is deprecated in modern browsers, its absence may affect older browsers without CSP support.".to_string(),
                evidence: evidence.clone(),
                remediation: "Consider adding: X-XSS-Protection: 0 (to explicitly disable the flawed XSS auditor) or rely on CSP instead.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Referrer-Policy
        if !headers.contains_key("referrer-policy") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing Referrer-Policy Header".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.1),
                cvss_vector: None,
                cwe_id: Some("CWE-200".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The Referrer-Policy header is not set. Without it, the browser may leak referrer information to third-party sites.".to_string(),
                evidence: evidence.clone(),
                remediation: "Add the header: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Permissions-Policy
        if !headers.contains_key("permissions-policy") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Missing Permissions-Policy Header".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.1),
                cvss_vector: None,
                cwe_id: Some("CWE-16".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: "The Permissions-Policy header (formerly Feature-Policy) is not set. This header controls which browser features and APIs can be used.".to_string(),
                evidence: evidence.clone(),
                remediation: "Add a Permissions-Policy header that restricts unnecessary browser features.".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: Server header present (information disclosure)
        if let Some(server) = headers.get("server") {
            let server_val = server.to_str().unwrap_or("<binary>").to_string();
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Server Header Information Disclosure".to_string(),
                severity: Severity::Info,
                cvss_score: None,
                cvss_vector: None,
                cwe_id: Some("CWE-200".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: format!(
                    "The Server header reveals software information: '{}'. This assists attackers in fingerprinting the web server.",
                    server_val
                ),
                evidence: evidence.clone(),
                remediation: "Remove or obfuscate the Server header to reduce information leakage.".to_string(),
                references: vec![],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check: X-Powered-By present (information disclosure)
        if let Some(powered_by) = headers.get("x-powered-by") {
            let val = powered_by.to_str().unwrap_or("<binary>").to_string();
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "X-Powered-By Header Information Disclosure".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.7),
                cvss_vector: None,
                cwe_id: Some("CWE-200".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("HTTP Headers".to_string()),
                description: format!(
                    "The X-Powered-By header reveals technology information: '{}'. This assists attackers in targeting known vulnerabilities.",
                    val
                ),
                evidence: evidence.clone(),
                remediation: "Remove the X-Powered-By header from HTTP responses.".to_string(),
                references: vec![],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "[http-headers-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
