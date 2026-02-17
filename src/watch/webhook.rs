use anyhow::Result;
use async_trait::async_trait;

use crate::finding::Severity;
use super::alert::AlertSink;
use super::WatchEvent;

/// Webhook alert sink — POSTs JSON events to a URL (Slack, generic endpoint).
pub struct WebhookSink {
    client: reqwest::Client,
    url: String,
    sink_name: String,
    min_severity: Severity,
}

impl WebhookSink {
    pub fn new(url: &str, name: &str, min_severity_str: &str) -> Self {
        let min_severity = parse_severity(min_severity_str);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
            url: url.to_string(),
            sink_name: format!("webhook-{}", name),
            min_severity,
        }
    }
}

#[async_trait]
impl AlertSink for WebhookSink {
    fn name(&self) -> &str {
        &self.sink_name
    }

    async fn emit(&self, event: &WatchEvent) -> Result<()> {
        // Only forward events at or above the minimum severity.
        // Severity derives Ord with Critical < High < ... < Info.
        if event.severity > self.min_severity {
            return Ok(());
        }

        let body = serde_json::to_string(event)?;

        // Fire-and-forget: log errors but don't propagate them.
        match self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    tracing::warn!(
                        "[{}] Webhook returned HTTP {}",
                        self.sink_name,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                tracing::warn!("[{}] Webhook POST failed: {}", self.sink_name, e);
            }
        }

        Ok(())
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}
