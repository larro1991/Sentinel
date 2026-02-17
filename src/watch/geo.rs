use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

/// Resolved geographic information for an IP address.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
}

/// Trait for GeoIP lookup providers.
#[async_trait]
pub trait GeoProvider: Send + Sync {
    async fn lookup(&self, ip: &IpAddr) -> Result<GeoInfo>;
}

/// ip-api.com based GeoIP provider with in-memory cache.
pub struct IpApiProvider {
    client: reqwest::Client,
    cache: Mutex<HashMap<IpAddr, GeoInfo>>,
    max_cache_size: usize,
}

impl IpApiProvider {
    pub fn new(max_cache_size: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            client,
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
struct IpApiResponse {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    city: Option<String>,
    #[serde(rename = "as")]
    as_field: Option<String>,
    org: Option<String>,
}

#[async_trait]
impl GeoProvider for IpApiProvider {
    async fn lookup(&self, ip: &IpAddr) -> Result<GeoInfo> {
        // Skip private/loopback IPs.
        if Self::is_private(ip) {
            return Ok(GeoInfo {
                country: None,
                country_code: None,
                city: None,
                asn: None,
                org: None,
            });
        }

        // Check cache first.
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(ip) {
                return Ok(cached.clone());
            }
        }

        let url = format!("http://ip-api.com/json/{}", ip);
        let resp: IpApiResponse = self.client.get(&url).send().await?.json().await?;

        let info = if resp.status == "success" {
            GeoInfo {
                country: resp.country,
                country_code: resp.country_code,
                city: resp.city,
                asn: resp.as_field,
                org: resp.org,
            }
        } else {
            GeoInfo {
                country: None,
                country_code: None,
                city: None,
                asn: None,
                org: None,
            }
        };

        // Insert into cache, evict oldest if over size.
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= self.max_cache_size {
                // Simple eviction: remove an arbitrary entry.
                if let Some(key) = cache.keys().next().cloned() {
                    cache.remove(&key);
                }
            }
            cache.insert(*ip, info.clone());
        }

        Ok(info)
    }
}
