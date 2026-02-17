use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::auth::AuthorizationLevel;
use super::{DiscoveredPort, ReconData, ReconModule, ReconResult};

/// Asynchronous TCP port scanner using concurrent connection attempts.
pub struct PortScanner {
    common_ports: Vec<u16>,
    timeout_ms: u64,
    concurrency: usize,
}

impl PortScanner {
    pub fn new() -> Self {
        Self {
            common_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
                993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
                8080, 8443, 8888, 9090, 27017,
            ],
            timeout_ms: 2000,
            concurrency: 100,
        }
    }

    /// Create a scanner with a custom port list.
    pub fn with_ports(ports: Vec<u16>) -> Self {
        Self {
            common_ports: ports,
            timeout_ms: 2000,
            concurrency: 100,
        }
    }

}

/// Map well-known port numbers to service names.
fn service_name_for_port(port: u16) -> Option<String> {
    let map: HashMap<u16, &str> = HashMap::from([
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (80, "http"),
        (110, "pop3"),
        (111, "rpcbind"),
        (135, "msrpc"),
        (139, "netbios-ssn"),
        (143, "imap"),
        (443, "https"),
        (445, "microsoft-ds"),
        (465, "smtps"),
        (587, "submission"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "mssql"),
        (1521, "oracle"),
        (2049, "nfs"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (5900, "vnc"),
        (5985, "winrm-http"),
        (5986, "winrm-https"),
        (6379, "redis"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (8888, "http-alt-2"),
        (9090, "http-mgmt"),
        (27017, "mongodb"),
    ]);
    map.get(&port).map(|s| s.to_string())
}

#[async_trait]
impl ReconModule for PortScanner {
    fn name(&self) -> &str {
        "port-scan"
    }

    fn description(&self) -> &str {
        "Scans common TCP ports using async connections with banner grabbing"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Scanning
    }

    async fn execute(&self, target: &str) -> Result<ReconResult> {
        tracing::info!(
            "[port-scan] Starting scan of {} ports on {}",
            self.common_ports.len(),
            target
        );

        // Resolve target to an IP address if it is a hostname.
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

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let timeout = Duration::from_millis(self.timeout_ms);
        let banner_timeout = Duration::from_secs(1);

        let mut handles = Vec::new();

        for &port in &self.common_ports {
            let sem = semaphore.clone();
            let ip = resolved.clone();
            let conn_timeout = timeout;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();

                let connect_result =
                    tokio::time::timeout(conn_timeout, TcpStream::connect(addr)).await;

                match connect_result {
                    Ok(Ok(mut stream)) => {
                        // Try to grab a banner — some services send data immediately.
                        let mut buf = vec![0u8; 1024];
                        let banner = match tokio::time::timeout(
                            banner_timeout,
                            stream.read(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
                            }
                            _ => None,
                        };

                        Some(DiscoveredPort {
                            port,
                            protocol: "tcp".to_string(),
                            state: "open".to_string(),
                            service: service_name_for_port(port),
                            banner,
                        })
                    }
                    _ => None,
                }
            });
            handles.push(handle);
        }

        let mut open_ports = Vec::new();
        for handle in handles {
            if let Ok(Some(port_result)) = handle.await {
                open_ports.push(port_result);
            }
        }

        // Sort by port number for consistent output.
        open_ports.sort_by_key(|p| p.port);

        tracing::info!(
            "[port-scan] Completed scan of {}: {} open ports found",
            target,
            open_ports.len()
        );

        Ok(ReconResult {
            module_name: self.name().to_string(),
            target: target.to_string(),
            data: ReconData::OpenPorts(open_ports),
            timestamp: Utc::now(),
        })
    }
}
