use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

/// Threat intelligence information for an IP address.
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    pub is_malicious: bool,
    pub abuse_score: Option<u32>,
    pub threat_categories: Vec<String>,
    pub source: String,
}

/// Trait for threat intelligence lookup providers.
#[async_trait]
pub trait ThreatIntelProvider: Send + Sync {
    async fn lookup(&self, ip: &IpAddr) -> Result<ThreatInfo>;
}

/// AbuseIPDB-based threat intelligence provider with in-memory cache.
pub struct AbuseIpDbProvider {
    client: reqwest::Client,
    api_key: String,
    cache: Mutex<HashMap<IpAddr, ThreatInfo>>,
    max_cache_size: usize,
}

impl AbuseIpDbProvider {
    pub fn new(api_key: &str, max_cache_size: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key: api_key.to_string(),
            cache: Mutex::new(HashMap::new()),
            max_cache_size,
        }
    }

    fn is_private(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        }
    }
}

#[derive(Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIpDbData {
    abuse_confidence_score: u32,
    #[serde(default)]
    is_tor: bool,
    #[serde(default)]
    total_reports: u32,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

/// Convert the AbuseIPDB categories into human-readable labels.
fn build_categories(data: &AbuseIpDbData) -> Vec<String> {
    let mut categories = Vec::new();
    if data.is_tor {
        categories.push("Tor Exit Node".to_string());
    }
    if data.total_reports > 0 {
        categories.push(format!("{} reports", data.total_reports));
    }
    if let Some(ref usage) = data.usage_type {
        if !usage.is_empty() {
            categories.push(usage.clone());
        }
    }
    if let Some(ref domain) = data.domain {
        if !domain.is_empty() {
            categories.push(format!("domain: {}", domain));
        }
    }
    categories
}

#[async_trait]
impl ThreatIntelProvider for AbuseIpDbProvider {
    async fn lookup(&self, ip: &IpAddr) -> Result<ThreatInfo> {
        // Skip private/loopback IPs.
        if Self::is_private(ip) {
            return Ok(ThreatInfo {
                is_malicious: false,
                abuse_score: None,
                threat_categories: Vec::new(),
                source: "abuseipdb".to_string(),
            });
        }

        // Check cache first.
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(ip) {
                return Ok(cached.clone());
            }
        }

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );
        let resp = self
            .client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let api_resp: AbuseIpDbResponse = resp.json().await?;

        let categories = build_categories(&api_resp.data);
        let score = api_resp.data.abuse_confidence_score;
        let info = ThreatInfo {
            is_malicious: score >= 50,
            abuse_score: Some(score),
            threat_categories: categories,
            source: "abuseipdb".to_string(),
        };

        // Insert into cache, evict if over size.
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= self.max_cache_size {
                if let Some(key) = cache.keys().next().cloned() {
                    cache.remove(&key);
                }
            }
            cache.insert(*ip, info.clone());
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ip_detection() {
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            0, 0, 0, 0
        ))));

        assert!(!AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!AbuseIpDbProvider::is_private(&IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        ))));
    }

    #[test]
    fn test_threat_info_construction() {
        let info = ThreatInfo {
            is_malicious: true,
            abuse_score: Some(85),
            threat_categories: vec!["Tor Exit Node".to_string()],
            source: "abuseipdb".to_string(),
        };
        assert!(info.is_malicious);
        assert_eq!(info.abuse_score, Some(85));
        assert_eq!(info.threat_categories.len(), 1);
        assert_eq!(info.source, "abuseipdb");
    }

    #[test]
    fn test_threat_info_not_malicious() {
        let info = ThreatInfo {
            is_malicious: false,
            abuse_score: Some(10),
            threat_categories: Vec::new(),
            source: "abuseipdb".to_string(),
        };
        assert!(!info.is_malicious);
        assert_eq!(info.abuse_score, Some(10));
        assert!(info.threat_categories.is_empty());
    }

    #[test]
    fn test_build_categories() {
        let data = AbuseIpDbData {
            abuse_confidence_score: 75,
            is_tor: true,
            total_reports: 42,
            usage_type: Some("Data Center/Web Hosting/Transit".to_string()),
            domain: Some("example.com".to_string()),
        };
        let cats = build_categories(&data);
        assert!(cats.contains(&"Tor Exit Node".to_string()));
        assert!(cats.contains(&"42 reports".to_string()));
        assert!(cats.contains(&"Data Center/Web Hosting/Transit".to_string()));
        assert!(cats.contains(&"domain: example.com".to_string()));
    }

    #[test]
    fn test_build_categories_empty() {
        let data = AbuseIpDbData {
            abuse_confidence_score: 0,
            is_tor: false,
            total_reports: 0,
            usage_type: None,
            domain: None,
        };
        let cats = build_categories(&data);
        assert!(cats.is_empty());
    }

    #[tokio::test]
    async fn test_private_ip_lookup() {
        let provider = AbuseIpDbProvider::new("test-key", 100);
        let result = provider
            .lookup(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await
            .expect("should not fail for private IP");
        assert!(!result.is_malicious);
        assert_eq!(result.abuse_score, None);
    }
}
