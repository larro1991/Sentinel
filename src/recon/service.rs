use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::auth::AuthorizationLevel;
use super::{ReconData, ReconModule, ReconResult, ServiceInfo};

/// Service fingerprinting via banner grabbing and protocol-specific probes.
pub struct ServiceProber {
    timeout_ms: u64,
}

impl ServiceProber {
    pub fn new() -> Self {
        Self { timeout_ms: 3000 }
    }
}

/// Ports to probe and the type of probe to use.
const PROBE_PORTS: &[(u16, ProbeType)] = &[
    (21, ProbeType::BannerGrab),   // FTP
    (22, ProbeType::BannerGrab),   // SSH
    (25, ProbeType::BannerGrab),   // SMTP
    (80, ProbeType::Http),
    (110, ProbeType::BannerGrab),  // POP3
    (143, ProbeType::BannerGrab),  // IMAP
    (443, ProbeType::Https),
    (587, ProbeType::BannerGrab),  // SMTP submission
    (8080, ProbeType::Http),
    (8443, ProbeType::Https),
];

#[derive(Debug, Clone, Copy)]
enum ProbeType {
    BannerGrab,
    Http,
    Https,
}

/// Attempt a raw TCP banner grab — connect and read whatever the server sends.
async fn banner_grab(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let connect = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await;
    match connect {
        Ok(Ok(mut stream)) => {
            let mut buf = vec![0u8; 2048];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Attempt an HTTP HEAD request and extract the Server header.
async fn http_probe(host: &str, port: u16, tls: bool, timeout: Duration) -> Option<(String, Option<String>)> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{}://{}:{}/", scheme, host, port);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .ok()?;

    match client.head(&url).send().await {
        Ok(resp) => {
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let version_str = server.clone();
            Some((
                format!("{} {}", if tls { "https" } else { "http" }, resp.status()),
                version_str,
            ))
        }
        Err(_) => None,
    }
}

/// Parse a version string from an SSH banner.
/// Typical format: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
fn parse_ssh_version(banner: &str) -> Option<String> {
    if banner.starts_with("SSH-") {
        // Extract the software version part after "SSH-X.Y-"
        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        if parts.len() >= 3 {
            return Some(parts[2].to_string());
        }
    }
    None
}

fn classify_service(port: u16, banner: &Option<String>, tls: bool) -> String {
    if let Some(ref b) = banner {
        let lower = b.to_lowercase();
        if lower.starts_with("ssh-") {
            return "ssh".to_string();
        }
        if lower.contains("ftp") || lower.contains("220 ") {
            return "ftp".to_string();
        }
        if lower.contains("smtp") || lower.contains("esmtp") || lower.contains("postfix") {
            return "smtp".to_string();
        }
        if lower.contains("http") || lower.contains("html") {
            return if tls { "https".to_string() } else { "http".to_string() };
        }
        if lower.contains("imap") {
            return "imap".to_string();
        }
        if lower.contains("pop") {
            return "pop3".to_string();
        }
    }

    // Fall back to port-based classification.
    match port {
        21 => "ftp",
        22 => "ssh",
        25 | 587 => "smtp",
        80 | 8080 | 8888 | 9090 => "http",
        443 | 8443 => "https",
        110 => "pop3",
        143 => "imap",
        _ => "unknown",
    }
    .to_string()
}

#[async_trait]
impl ReconModule for ServiceProber {
    fn name(&self) -> &str {
        "service-probe"
    }

    fn description(&self) -> &str {
        "Fingerprints services via banner grabbing and protocol-specific probes"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    async fn execute(&self, target: &str) -> Result<ReconResult> {
        tracing::info!("[service-probe] Probing services on {}", target);

        let timeout = Duration::from_millis(self.timeout_ms);

        // Resolve hostname to IP for raw TCP connections.
        let resolved: String = if target.parse::<std::net::IpAddr>().is_ok() {
            target.to_string()
        } else {
            let lookup = tokio::net::lookup_host(format!("{}:0", target)).await;
            match lookup {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        addr.ip().to_string()
                    } else {
                        anyhow::bail!("Could not resolve hostname: {}", target);
                    }
                }
                Err(e) => {
                    anyhow::bail!("DNS resolution failed for {}: {}", target, e);
                }
            }
        };

        let mut services = Vec::new();

        for &(port, probe_type) in PROBE_PORTS {
            let info = match probe_type {
                ProbeType::BannerGrab => {
                    let banner = banner_grab(&resolved, port, timeout).await;
                    if banner.is_some() {
                        let version = if port == 22 {
                            banner.as_ref().and_then(|b| parse_ssh_version(b))
                        } else {
                            None
                        };
                        let svc_name = classify_service(port, &banner, false);
                        Some(ServiceInfo {
                            port,
                            service_name: svc_name,
                            version,
                            banner,
                            tls: false,
                        })
                    } else {
                        None
                    }
                }
                ProbeType::Http => {
                    match http_probe(target, port, false, timeout).await {
                        Some((status, server_version)) => Some(ServiceInfo {
                            port,
                            service_name: "http".to_string(),
                            version: server_version,
                            banner: Some(status),
                            tls: false,
                        }),
                        None => {
                            // Fall back to banner grab.
                            let banner = banner_grab(&resolved, port, timeout).await;
                            if banner.is_some() {
                                Some(ServiceInfo {
                                    port,
                                    service_name: "http".to_string(),
                                    version: None,
                                    banner,
                                    tls: false,
                                })
                            } else {
                                None
                            }
                        }
                    }
                }
                ProbeType::Https => {
                    match http_probe(target, port, true, timeout).await {
                        Some((status, server_version)) => Some(ServiceInfo {
                            port,
                            service_name: "https".to_string(),
                            version: server_version,
                            banner: Some(status),
                            tls: true,
                        }),
                        None => None,
                    }
                }
            };

            if let Some(svc) = info {
                tracing::info!(
                    "[service-probe] {}:{} -> {} (version: {:?})",
                    target,
                    svc.port,
                    svc.service_name,
                    svc.version
                );
                services.push(svc);
            }
        }

        tracing::info!(
            "[service-probe] Completed probing {}: {} services identified",
            target,
            services.len()
        );

        Ok(ReconResult {
            module_name: self.name().to_string(),
            target: target.to_string(),
            data: ReconData::ServiceInfo(services),
            timestamp: Utc::now(),
        })
    }
}
