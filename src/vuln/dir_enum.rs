use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::StatusCode;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::auth::AuthorizationLevel;
use crate::finding::{Evidence, EvidenceType, Finding, Severity};
use super::{Service, VulnCheck};

/// Directory / sensitive-file enumeration checker — requests a curated set of
/// paths that commonly leak source code, configuration, backups, or internal
/// documentation.
pub struct DirEnumCheck;

impl DirEnumCheck {
    pub fn new() -> Self {
        Self
    }
}

/// Maximum number of concurrent HTTP requests per check invocation.
const MAX_CONCURRENT: usize = 5;

/// A path to probe together with metadata used for classifying the finding.
struct ProbePath {
    path: &'static str,
    category: ProbeCategory,
    label: &'static str,
}

#[derive(Clone, Copy)]
enum ProbeCategory {
    Git,
    EnvFile,
    Sensitive,
    RobotsTxt,
    ApiDocs,
    SecurityTxt,
}

fn probe_paths() -> Vec<ProbePath> {
    vec![
        // Git repository
        ProbePath { path: "/.git/HEAD",     category: ProbeCategory::Git,         label: "Git HEAD" },
        ProbePath { path: "/.git/config",   category: ProbeCategory::Git,         label: "Git Config" },
        // Environment file
        ProbePath { path: "/.env",          category: ProbeCategory::EnvFile,     label: "Environment File" },
        // robots.txt / sitemap
        ProbePath { path: "/robots.txt",    category: ProbeCategory::RobotsTxt,   label: "robots.txt" },
        ProbePath { path: "/sitemap.xml",   category: ProbeCategory::Sensitive,   label: "Sitemap XML" },
        // Apache config
        ProbePath { path: "/.htaccess",     category: ProbeCategory::Sensitive,   label: ".htaccess" },
        ProbePath { path: "/.htpasswd",     category: ProbeCategory::Sensitive,   label: ".htpasswd" },
        // Backups
        ProbePath { path: "/backup",            category: ProbeCategory::Sensitive, label: "Backup Directory" },
        ProbePath { path: "/backup.zip",        category: ProbeCategory::Sensitive, label: "Backup Archive" },
        ProbePath { path: "/backup.sql",        category: ProbeCategory::Sensitive, label: "SQL Backup" },
        ProbePath { path: "/wp-config.php.bak", category: ProbeCategory::Sensitive, label: "WordPress Config Backup" },
        ProbePath { path: "/config.php.bak",    category: ProbeCategory::Sensitive, label: "PHP Config Backup" },
        // Apache server status / info
        ProbePath { path: "/server-status", category: ProbeCategory::Sensitive, label: "Apache Server Status" },
        ProbePath { path: "/server-info",   category: ProbeCategory::Sensitive, label: "Apache Server Info" },
        // ASP.NET error log
        ProbePath { path: "/elmah.axd",     category: ProbeCategory::Sensitive, label: "ELMAH Error Log" },
        // PHP info
        ProbePath { path: "/phpinfo.php",   category: ProbeCategory::Sensitive, label: "phpinfo()" },
        // API documentation
        ProbePath { path: "/api/swagger",   category: ProbeCategory::ApiDocs,   label: "Swagger UI" },
        ProbePath { path: "/swagger.json",  category: ProbeCategory::ApiDocs,   label: "Swagger JSON" },
        ProbePath { path: "/api-docs",      category: ProbeCategory::ApiDocs,   label: "API Docs" },
        // Security policy
        ProbePath { path: "/.well-known/security.txt", category: ProbeCategory::SecurityTxt, label: "security.txt" },
        // Cross-domain policy
        ProbePath { path: "/crossdomain.xml", category: ProbeCategory::Sensitive, label: "crossdomain.xml" },
    ]
}

/// Build a `reqwest::Client` configured for directory enumeration.
fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects
        .build()?)
}

/// Determine the URL scheme for a service.
fn scheme_for(service: &Service) -> &'static str {
    if service.tls || service.port == 443 || service.port == 8443 {
        "https"
    } else {
        "http"
    }
}

/// Truncate a string to at most `max` characters.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[async_trait]
impl VulnCheck for DirEnumCheck {
    fn name(&self) -> &str {
        "dir-enum-check"
    }

    fn description(&self) -> &str {
        "Enumerates common sensitive paths and files on HTTP services"
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
            "[dir-enum-check] Enumerating paths on {}:{}",
            service.host,
            service.port
        );

        let asset = format!("{}:{}", service.host, service.port);
        let scheme = scheme_for(service);
        let base_url = format!("{}://{}:{}", scheme, service.host, service.port);
        let client = build_client()?;

        let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT));
        let paths = probe_paths();

        // Spawn one task per path, bounded by the semaphore.
        let mut handles = Vec::with_capacity(paths.len());

        for probe in paths {
            let client = client.clone();
            let url = format!("{}{}", base_url, probe.path);
            let sem = semaphore.clone();
            let asset = asset.clone();
            let module_name = self.name().to_string();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await;
                probe_single(
                    &client,
                    &url,
                    probe.path,
                    probe.category,
                    probe.label,
                    &asset,
                    &module_name,
                )
                .await
            }));
        }

        let mut findings = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(Some(f))) => findings.push(f),
                Ok(Ok(None)) => {}
                Ok(Err(e)) => {
                    tracing::debug!("[dir-enum-check] probe error: {}", e);
                }
                Err(e) => {
                    tracing::debug!("[dir-enum-check] task join error: {}", e);
                }
            }
        }

        tracing::info!(
            "[dir-enum-check] Completed check on {}: {} findings",
            asset,
            findings.len()
        );

        Ok(findings)
    }
}

/// Probe a single path and return an optional finding.
async fn probe_single(
    client: &reqwest::Client,
    url: &str,
    path: &str,
    category: ProbeCategory,
    label: &str,
    asset: &str,
    module_name: &str,
) -> Result<Option<Finding>> {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let status = resp.status();

    // We only care about 200 OK responses for actual content discovery.
    if status != StatusCode::OK {
        return Ok(None);
    }

    let body = resp.text().await.unwrap_or_default();
    let body_preview = truncate(&body, 200);

    let evidence = vec![
        Evidence {
            evidence_type: EvidenceType::HttpResponse,
            content: format!("GET {} => HTTP {}", url, status),
            label: Some("HTTP Request".to_string()),
        },
        Evidence {
            evidence_type: EvidenceType::Raw,
            content: body_preview.clone(),
            label: Some("Response Body (first 200 chars)".to_string()),
        },
    ];

    let finding = match category {
        ProbeCategory::Git => {
            // Only flag if the body looks like a real git HEAD (e.g. "ref: refs/heads/main")
            if !body.contains("ref:") {
                return Ok(None);
            }
            Some(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Git Repository Exposed".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                cwe_id: Some("CWE-538".to_string()),
                cve_ids: vec![],
                affected_asset: asset.to_string(),
                affected_component: Some("Web Server".to_string()),
                description: format!(
                    "The Git repository metadata is accessible at {}. An attacker can \
                     reconstruct the full source code, including commit history, credentials, \
                     and configuration files.",
                    url
                ),
                evidence,
                remediation: "Block access to the .git directory in the web server configuration. \
                              For Apache: `RedirectMatch 404 /\\.git`. \
                              For Nginx: `location ~ /\\.git { deny all; }`."
                    .to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/538.html".to_string(),
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces".to_string(),
                ],
                module_name: module_name.to_string(),
                timestamp: Utc::now(),
            })
        }

        ProbeCategory::EnvFile => {
            Some(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Environment File Exposed".to_string(),
                severity: Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                cwe_id: Some("CWE-538".to_string()),
                cve_ids: vec![],
                affected_asset: asset.to_string(),
                affected_component: Some("Web Server".to_string()),
                description: format!(
                    "The environment configuration file (.env) is accessible at {}. This file \
                     typically contains database credentials, API keys, and other secrets.",
                    url
                ),
                evidence,
                remediation: "Block access to .env files in the web server configuration. \
                              Ensure the file is not within the document root or add a \
                              deny rule: `location ~ /\\.env { deny all; }`."
                    .to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/538.html".to_string(),
                ],
                module_name: module_name.to_string(),
                timestamp: Utc::now(),
            })
        }

        ProbeCategory::RobotsTxt => {
            // robots.txt itself isn't sensitive but may reveal interesting paths.
            let interesting = body.contains("Disallow:")
                && (body.contains("/admin")
                    || body.contains("/api")
                    || body.contains("/internal")
                    || body.contains("/private")
                    || body.contains("/backup")
                    || body.contains("/config")
                    || body.contains("/secret"));

            if interesting {
                Some(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "Information Disclosure via robots.txt".to_string(),
                    severity: Severity::Info,
                    cvss_score: None,
                    cvss_vector: None,
                    cwe_id: Some("CWE-200".to_string()),
                    cve_ids: vec![],
                    affected_asset: asset.to_string(),
                    affected_component: Some("Web Server".to_string()),
                    description: format!(
                        "The robots.txt file at {} contains Disallow directives that reveal \
                         potentially sensitive paths. While this is not a direct vulnerability, \
                         it helps an attacker map the application structure.",
                        url
                    ),
                    evidence,
                    remediation: "Review robots.txt and remove references to sensitive paths. \
                                  Use authentication and access controls instead of relying on \
                                  robots.txt for security."
                        .to_string(),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                    ],
                    module_name: module_name.to_string(),
                    timestamp: Utc::now(),
                })
            } else {
                None
            }
        }

        ProbeCategory::ApiDocs => {
            Some(Finding {
                id: Uuid::new_v4().to_string(),
                title: "API Documentation Exposed".to_string(),
                severity: Severity::Low,
                cvss_score: Some(3.7),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string()),
                cwe_id: Some("CWE-200".to_string()),
                cve_ids: vec![],
                affected_asset: asset.to_string(),
                affected_component: Some("API".to_string()),
                description: format!(
                    "API documentation ({}) is publicly accessible at {}. This reveals \
                     endpoint structure, parameter names, and data models that an attacker \
                     can use to craft targeted requests.",
                    label, url
                ),
                evidence,
                remediation: "Restrict access to API documentation to authenticated users or \
                              internal networks only. Remove documentation endpoints from \
                              production deployments."
                    .to_string(),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                ],
                module_name: module_name.to_string(),
                timestamp: Utc::now(),
            })
        }

        ProbeCategory::SecurityTxt => {
            // security.txt is intentionally public — not a finding.
            None
        }

        ProbeCategory::Sensitive => {
            Some(Finding {
                id: Uuid::new_v4().to_string(),
                title: "Sensitive File Exposed".to_string(),
                severity: Severity::Medium,
                cvss_score: Some(5.3),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string()),
                cwe_id: Some("CWE-538".to_string()),
                cve_ids: vec![],
                affected_asset: asset.to_string(),
                affected_component: Some("Web Server".to_string()),
                description: format!(
                    "The sensitive file '{}' ({}) is accessible at {}. This may expose \
                     internal configuration, credentials, or application internals.",
                    label, path, url
                ),
                evidence,
                remediation: format!(
                    "Block access to {} in the web server configuration. Ensure sensitive \
                     files are not deployed within the document root.",
                    path
                ),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/538.html".to_string(),
                ],
                module_name: module_name.to_string(),
                timestamp: Utc::now(),
            })
        }
    };

    Ok(finding)
}
