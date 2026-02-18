use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::Semaphore;

use crate::auth::AuthorizationLevel;
use super::{DnsRecord, ReconData, ReconModule, ReconResult};

/// Subdomain enumeration module — discovers subdomains via Certificate
/// Transparency (crt.sh) and DNS brute force with a built-in wordlist.
pub struct SubdomainEnumerator {
    concurrency: usize,
}

impl SubdomainEnumerator {
    pub fn new() -> Self {
        Self { concurrency: 50 }
    }

    pub fn with_concurrency(concurrency: usize) -> Self {
        Self { concurrency }
    }
}

fn build_resolver() -> TokioAsyncResolver {
    let nameservers = NameServerConfigGroup::from_ips_clear(
        &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ],
        53,
        true,
    );

    let config = ResolverConfig::from_parts(None, vec![], nameservers);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;
    opts.rotate = true;
    TokioAsyncResolver::tokio(config, opts)
}

/// Query crt.sh for Certificate Transparency subdomains.
async fn query_crtsh(domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("[subdomain-enum] crt.sh request failed: {}", e);
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(
            "[subdomain-enum] crt.sh returned status {}",
            resp.status()
        );
        return Ok(Vec::new());
    }

    let body = resp.text().await.unwrap_or_default();

    // Parse JSON array of objects, each with a "name_value" field.
    let entries: Vec<serde_json::Value> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };

    let mut subdomains = HashSet::new();
    for entry in &entries {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            // name_value can contain multiple names separated by newlines.
            for name in name_value.split('\n') {
                let name = name.trim().to_lowercase();
                // Skip wildcard entries and empty strings.
                if !name.is_empty() && !name.starts_with('*') {
                    subdomains.insert(name);
                }
            }
        }
    }

    Ok(subdomains.into_iter().collect())
}

/// DNS brute force with a built-in wordlist.
async fn dns_brute_force(
    domain: &str,
    resolver: &TokioAsyncResolver,
    concurrency: usize,
) -> Vec<String> {
    let wordlist = SUBDOMAIN_WORDLIST;
    let mut found = Vec::new();
    let mut handles = Vec::new();
    let semaphore = Arc::new(Semaphore::new(concurrency));

    for word in wordlist {
        let fqdn = format!("{}.{}", word, domain);
        let resolver = resolver.clone();
        let sem = semaphore.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            match resolver.lookup_ip(&fqdn).await {
                Ok(lookup) if lookup.iter().next().is_some() => Some(fqdn),
                _ => None,
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(fqdn)) = handle.await {
            found.push(fqdn);
        }
    }

    found
}

#[async_trait]
impl ReconModule for SubdomainEnumerator {
    fn name(&self) -> &str {
        "subdomain-enum"
    }

    fn description(&self) -> &str {
        "Subdomain enumeration via Certificate Transparency and DNS brute force"
    }

    fn authorization_level(&self) -> AuthorizationLevel {
        AuthorizationLevel::Passive
    }

    async fn execute(&self, target: &str) -> Result<ReconResult> {
        tracing::info!("[subdomain-enum] Enumerating subdomains for {}", target);

        // Skip if target is an IP address.
        if target.parse::<std::net::IpAddr>().is_ok() {
            tracing::debug!(
                "[subdomain-enum] Skipping {} — subdomain enum requires a domain name",
                target
            );
            return Ok(ReconResult {
                module_name: self.name().to_string(),
                target: target.to_string(),
                data: ReconData::DnsRecords(Vec::new()),
                timestamp: Utc::now(),
            });
        }

        // Strip leading wildcard if present.
        let domain = target.trim_start_matches("*.");

        let mut all_subdomains = HashSet::new();

        // Phase 1: Certificate Transparency.
        tracing::info!("[subdomain-enum] Querying crt.sh CT logs for {}", domain);
        match query_crtsh(domain).await {
            Ok(ct_subs) => {
                tracing::info!(
                    "[subdomain-enum] crt.sh returned {} unique subdomains",
                    ct_subs.len()
                );
                for sub in ct_subs {
                    all_subdomains.insert(sub);
                }
            }
            Err(e) => {
                tracing::warn!("[subdomain-enum] crt.sh query failed: {}", e);
            }
        }

        // Phase 2: DNS brute force.
        tracing::info!("[subdomain-enum] Running DNS brute force for {}", domain);
        let resolver = build_resolver();
        let brute_subs = dns_brute_force(domain, &resolver, self.concurrency).await;
        tracing::info!(
            "[subdomain-enum] DNS brute force found {} subdomains",
            brute_subs.len()
        );
        for sub in brute_subs {
            all_subdomains.insert(sub);
        }

        // Convert to DnsRecords with record_type "SUBDOMAIN".
        let mut records: Vec<DnsRecord> = Vec::new();
        for subdomain in &all_subdomains {
            // Resolve each subdomain to get its IP.
            let ip = match resolver.lookup_ip(subdomain.as_str()).await {
                Ok(lookup) => lookup
                    .iter()
                    .next()
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                Err(_) => String::new(),
            };

            records.push(DnsRecord {
                record_type: "SUBDOMAIN".to_string(),
                name: subdomain.clone(),
                value: ip,
                ttl: None,
            });
        }

        tracing::info!(
            "[subdomain-enum] Total: {} unique subdomains for {}",
            records.len(),
            domain
        );

        Ok(ReconResult {
            module_name: self.name().to_string(),
            target: target.to_string(),
            data: ReconData::DnsRecords(records),
            timestamp: Utc::now(),
        })
    }
}

/// Built-in wordlist (~200 common subdomain prefixes).
const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "vpn", "gateway",
    "api", "app", "apps", "dev", "staging", "stage", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview",
    "admin", "administrator", "manage", "management", "portal",
    "dashboard", "panel", "console", "login", "auth", "sso",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "upload", "uploads", "download", "downloads", "content",
    "blog", "news", "forum", "community", "support", "help", "docs",
    "documentation", "wiki", "kb", "knowledge", "faq",
    "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment",
    "billing", "invoice", "order", "orders",
    "git", "gitlab", "github", "svn", "repo", "repos", "code",
    "jenkins", "ci", "cd", "build", "deploy", "release",
    "jira", "confluence", "bitbucket", "slack", "teams",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
    "elastic", "elasticsearch", "kibana", "grafana", "prometheus",
    "monitor", "monitoring", "status", "health", "metrics",
    "log", "logs", "logging", "syslog", "splunk",
    "backup", "bak", "archive", "old", "legacy", "temp", "tmp",
    "internal", "intranet", "extranet", "private", "corp", "corporate",
    "office", "remote", "rdp", "ssh", "bastion", "jump",
    "proxy", "reverse", "lb", "load", "balancer", "cache",
    "web", "web1", "web2", "web3", "www1", "www2",
    "server", "srv", "server1", "server2", "host", "node",
    "cloud", "aws", "azure", "gcp", "s3", "storage",
    "email", "exchange", "owa", "autodiscover", "autoconfig",
    "mobile", "m", "wap", "tablet",
    "api2", "api3", "v1", "v2", "v3", "rest", "graphql", "grpc",
    "socket", "ws", "websocket", "wss", "realtime",
    "search", "solr", "lucene",
    "queue", "mq", "rabbitmq", "kafka", "amqp",
    "crm", "erp", "hr", "finance", "accounting",
    "vpn2", "openvpn", "wireguard", "ipsec",
    "cert", "certs", "pki", "ca", "ocsp",
    "ldap", "ad", "directory", "kerberos",
    "ntp", "time", "snmp", "tftp",
    "relay", "mx1", "mx2", "smtp2",
    "report", "reports", "analytics", "stats", "statistics",
    "data", "bigdata", "warehouse", "etl", "pipeline",
    "map", "maps", "geo", "location",
    "chat", "im", "messaging", "notify", "notifications",
    "calendar", "cal", "schedule",
    "video", "stream", "streaming", "live", "broadcast",
    "voip", "sip", "pbx", "phone", "tel",
];
