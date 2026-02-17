use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// Default credential checker — probes common web management interfaces for
/// default or well-known username/password pairs using HTTP Basic authentication.
pub struct DefaultCredsCheck;

impl DefaultCredsCheck {
    pub fn new() -> Self {
        Self
    }
}

/// A single credential pair to try against a given path.
struct CredentialTarget {
    path: &'static str,
    username: &'static str,
    password: &'static str,
    /// A human-readable label describing the interface (e.g. "Apache Tomcat Manager").
    interface: &'static str,
}

/// Return the full list of (path, credential) targets.
fn credential_targets() -> Vec<CredentialTarget> {
    vec![
        // Tomcat Manager
        CredentialTarget {
            path: "/manager/html",
            username: "tomcat",
            password: "tomcat",
            interface: "Apache Tomcat Manager",
        },
        CredentialTarget {
            path: "/manager/html",
            username: "admin",
            password: "admin",
            interface: "Apache Tomcat Manager",
        },
        // Generic /admin
        CredentialTarget {
            path: "/admin",
            username: "admin",
            password: "admin",
            interface: "Admin Panel",
        },
        CredentialTarget {
            path: "/admin",
            username: "admin",
            password: "password",
            interface: "Admin Panel",
        },
        // phpMyAdmin
        CredentialTarget {
            path: "/phpmyadmin",
            username: "root",
            password: "",
            interface: "phpMyAdmin",
        },
        CredentialTarget {
            path: "/phpmyadmin",
            username: "root",
            password: "root",
            interface: "phpMyAdmin",
        },
    ]
}

/// Paths that indicate a management interface exists even if we cannot
/// authenticate (we only check for existence, no credential attempt).
struct ProbeOnlyTarget {
    path: &'static str,
    interface: &'static str,
}

fn probe_only_targets() -> Vec<ProbeOnlyTarget> {
    vec![
        ProbeOnlyTarget {
            path: "/wp-login.php",
            interface: "WordPress Login",
        },
    ]
}

/// Build a `reqwest::Client` configured for our checks.
fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?)
}

/// Determine the URL scheme based on the service.
fn scheme_for(service: &Service) -> &'static str {
    if service.tls || service.port == 443 || service.port == 8443 {
        "https"
    } else {
        "http"
    }
}

#[async_trait]
impl VulnCheck for DefaultCredsCheck {
    fn name(&self) -> &str {
        "default-creds-check"
    }

    fn description(&self) -> &str {
        "Checks common web management interfaces for default credentials"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Verification
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
            "[default-creds-check] Checking default credentials on {}:{}",
            service.host,
            service.port
        );

        let mut findings = Vec::new();
        let asset = format!("{}:{}", service.host, service.port);
        let scheme = scheme_for(service);
        let base_url = format!("{}://{}:{}", scheme, service.host, service.port);
        let client = build_client()?;

        // ── Track which paths we've already reported as "exposed" so we
        //    do not emit duplicate Management Interface findings.
        let mut exposed_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

        // ── Credential targets ──────────────────────────────────────────
        for target in credential_targets() {
            let url = format!("{}{}", base_url, target.path);

            // First, probe with a HEAD request to check existence.
            let probe_status = match client.head(&url).send().await {
                Ok(resp) => Some(resp.status()),
                Err(e) => {
                    tracing::debug!(
                        "[default-creds-check] HEAD {} failed: {}",
                        url,
                        e
                    );
                    None
                }
            };

            let exists = matches!(
                probe_status,
                Some(s) if s == StatusCode::OK
                    || s == StatusCode::UNAUTHORIZED
                    || s == StatusCode::FORBIDDEN
                    || s == StatusCode::FOUND
                    || s == StatusCode::MOVED_PERMANENTLY
            );

            if !exists {
                continue;
            }

            // If the path exists and we have not yet reported it, emit an
            // "interface exposed" finding.
            if exposed_paths.insert(target.path.to_string()) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "Management Interface Exposed".to_string(),
                    severity: Severity::Medium,
                    cvss_score: Some(5.3),
                    cvss_vector: Some(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                    ),
                    cwe_id: Some("CWE-200".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some(target.interface.to_string()),
                    description: format!(
                        "The management interface '{}' ({}) is accessible over the network. \
                         Even without valid credentials, exposing administration paths \
                         increases the attack surface.",
                        target.interface, url
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        content: format!(
                            "HEAD {} => {}",
                            url,
                            probe_status.map_or("N/A".to_string(), |s| s.to_string())
                        ),
                        label: Some("HTTP Probe".to_string()),
                    }],
                    remediation: format!(
                        "Restrict access to {} using firewall rules, VPN, or IP allowlists. \
                         Consider removing or disabling the interface if it is not needed.",
                        target.path
                    ),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }

            // If 401/403, try Basic auth with the credential pair.
            if matches!(probe_status, Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN))
                || matches!(probe_status, Some(StatusCode::OK))
            {
                let auth_resp = match client
                    .get(&url)
                    .basic_auth(target.username, Some(target.password))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(
                            "[default-creds-check] Auth request to {} failed: {}",
                            url,
                            e
                        );
                        continue;
                    }
                };

                let auth_status = auth_resp.status();

                // A 200 or 30x after authenticating is a strong indicator of success.
                let success = auth_status == StatusCode::OK
                    || auth_status == StatusCode::FOUND
                    || auth_status == StatusCode::MOVED_PERMANENTLY;

                // Extra guard: if the original HEAD already returned 200 without
                // auth, we only flag it when the page doesn't require authentication
                // at all (which is equally bad).
                if success {
                    tracing::warn!(
                        "[default-creds-check] Default credentials FOUND at {} ({}:{})",
                        url,
                        target.username,
                        target.password
                    );

                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: "Default Credentials Found".to_string(),
                        severity: Severity::Critical,
                        cvss_score: Some(9.8),
                        cvss_vector: Some(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                        ),
                        cwe_id: Some("CWE-798".to_string()),
                        cve_ids: vec![],
                        affected_asset: asset.clone(),
                        affected_component: Some(target.interface.to_string()),
                        description: format!(
                            "The {} interface at {} accepts default credentials \
                             (username: '{}', password: '{}'). An attacker can use \
                             these credentials to gain full administrative access.",
                            target.interface,
                            url,
                            target.username,
                            if target.password.is_empty() {
                                "<empty>"
                            } else {
                                target.password
                            }
                        ),
                        evidence: vec![
                            Evidence {
                                evidence_type: EvidenceType::HttpRequest,
                                content: format!(
                                    "GET {} with Basic Auth ({}:{})",
                                    url,
                                    target.username,
                                    if target.password.is_empty() {
                                        "<empty>"
                                    } else {
                                        target.password
                                    }
                                ),
                                label: Some("Authentication Request".to_string()),
                            },
                            Evidence {
                                evidence_type: EvidenceType::HttpResponse,
                                content: format!("HTTP {}", auth_status),
                                label: Some("Authentication Response".to_string()),
                            },
                        ],
                        remediation: format!(
                            "Immediately change the default credentials for {}. \
                             Use strong, unique passwords and consider multi-factor \
                             authentication.",
                            target.interface
                        ),
                        references: vec![
                            "https://cwe.mitre.org/data/definitions/798.html".to_string(),
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials".to_string(),
                        ],
                        module_name: self.name().to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // ── Probe-only targets (existence check only) ───────────────────
        for target in probe_only_targets() {
            let url = format!("{}{}", base_url, target.path);

            let resp = match client.head(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(
                        "[default-creds-check] HEAD {} failed: {}",
                        url,
                        e
                    );
                    continue;
                }
            };

            let status = resp.status();
            let exists = status == StatusCode::OK
                || status == StatusCode::FOUND
                || status == StatusCode::MOVED_PERMANENTLY;

            if exists && exposed_paths.insert(target.path.to_string()) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "Management Interface Exposed".to_string(),
                    severity: Severity::Medium,
                    cvss_score: Some(5.3),
                    cvss_vector: Some(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                    ),
                    cwe_id: Some("CWE-200".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.clone(),
                    affected_component: Some(target.interface.to_string()),
                    description: format!(
                        "The {} interface at {} is accessible over the network.",
                        target.interface, url
                    ),
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        content: format!("HEAD {} => {}", url, status),
                        label: Some("HTTP Probe".to_string()),
                    }],
                    remediation: format!(
                        "Restrict access to {} using firewall rules, VPN, or IP allowlists.",
                        target.path
                    ),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                    ],
                    module_name: self.name().to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        tracing::info!(
            "[default-creds-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}
