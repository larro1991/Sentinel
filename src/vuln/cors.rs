use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// CORS misconfiguration checker — detects wildcard, origin reflection,
/// and credential reflection vulnerabilities.
pub struct CorsCheck;

impl CorsCheck {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VulnCheck for CorsCheck {
    fn name(&self) -> &str {
        "cors-check"
    }

    fn description(&self) -> &str {
        "Checks for CORS misconfiguration (wildcard, origin reflection, credential reflection)"
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
            || matches!(service.port, 80 | 443 | 8080 | 8443 | 3000 | 5000 | 8000)
    }

    async fn check(&self, service: &Service) -> Result<Vec<Finding>> {
        tracing::info!(
            "[cors-check] Checking CORS on {}:{}",
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

        // Test 1: Send evil origin and check reflection.
        let evil_origin = "https://evil.com";
        let resp = match client
            .get(&url)
            .header("Origin", evil_origin)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[cors-check] Request failed to {}: {}", url, e);
                return Ok(findings);
            }
        };

        let headers = resp.headers().clone();
        let acao = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let acac = headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let headers_text: String = headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<binary>")))
            .collect::<Vec<_>>()
            .join("\n");

        let evidence = vec![Evidence {
            evidence_type: EvidenceType::HttpResponse,
            content: format!(
                "Request Origin: {}\nResponse Headers:\n{}",
                evil_origin, headers_text
            ),
            label: Some("CORS Response".to_string()),
        }];

        // Critical: origin reflected + credentials allowed.
        if acao == evil_origin && acac.to_lowercase() == "true" {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "CORS Credential Reflection".to_string(),
                severity: Severity::Critical,
                cvss_score: Some(9.1),
                cvss_vector: Some(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(),
                ),
                cwe_id: Some("CWE-942".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("CORS Policy".to_string()),
                description: format!(
                    "The server reflects the Origin header ({}) in Access-Control-Allow-Origin \
                     AND sets Access-Control-Allow-Credentials: true. This allows any website to \
                     make authenticated cross-origin requests and steal user data.",
                    evil_origin
                ),
                evidence: evidence.clone(),
                remediation: "Configure a strict allowlist of trusted origins. Never reflect \
                    arbitrary origins when credentials are enabled."
                    .to_string(),
                references: vec![
                    "https://portswigger.net/web-security/cors".to_string(),
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
                        .to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        } else if acao == evil_origin {
            // High: origin reflected without credentials.
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "CORS Origin Reflection".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                ),
                cwe_id: Some("CWE-942".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("CORS Policy".to_string()),
                description: format!(
                    "The server reflects the Origin header ({}) in Access-Control-Allow-Origin. \
                     While credentials are not explicitly allowed, this may expose sensitive \
                     API data to any origin.",
                    evil_origin
                ),
                evidence: evidence.clone(),
                remediation:
                    "Configure a strict allowlist of trusted origins instead of reflecting \
                     the request Origin."
                        .to_string(),
                references: vec![
                    "https://portswigger.net/web-security/cors".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        } else if acao == "*" {
            // Medium: wildcard CORS.
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "CORS Wildcard Access-Control-Allow-Origin".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.3),
                cvss_vector: None,
                cwe_id: Some("CWE-942".to_string()),
                cve_ids: vec![],
                affected_asset: asset.clone(),
                affected_component: Some("CORS Policy".to_string()),
                description:
                    "The server sets Access-Control-Allow-Origin: *, allowing any website \
                     to read responses. While browsers prevent credential inclusion with \
                     wildcard CORS, public API data may be exposed."
                        .to_string(),
                evidence: evidence.clone(),
                remediation: "If the endpoint serves sensitive data, restrict CORS to \
                    specific trusted origins."
                    .to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string(),
                ],
                module_name: self.name().to_string(),
                timestamp: Utc::now(),
            });
        }

        // Test 2: null origin.
        if let Ok(null_resp) = client
            .get(&url)
            .header("Origin", "null")
            .send()
            .await
        {
            let null_acao = null_resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if null_acao == "null" {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "CORS Null Origin Allowed".to_string(),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    cvss_vector: None,
                    cwe_id: Some("CWE-942".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some("CORS Policy".to_string()),
                    description: "The server accepts 'null' as a valid origin. Sandboxed \
                        iframes and data: URIs send Origin: null, which can be exploited \
                        to bypass CORS restrictions."
                        .to_string(),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        content: "Origin: null -> Access-Control-Allow-Origin: null".to_string(),
                        label: Some("Null Origin Test".to_string()),
                    }],
                    remediation:
                        "Do not include 'null' in the CORS origin allowlist.".to_string(),
                    references: vec![
                        "https://portswigger.net/web-security/cors".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        tracing::info!(
            "[cors-check] Completed on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
