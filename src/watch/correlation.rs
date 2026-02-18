use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::WatchEvent;

/// A correlation rule loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub rule_type: CorrelationRuleType,
}

/// The type of correlation pattern to detect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CorrelationRuleType {
    #[serde(rename = "port_scan")]
    PortScan {
        threshold: u32,
        window_secs: u64,
    },
    #[serde(rename = "brute_force")]
    BruteForce {
        threshold: u32,
        window_secs: u64,
    },
    #[serde(rename = "lateral_movement")]
    LateralMovement {
        threshold: u32,
        window_secs: u64,
    },
    #[serde(rename = "event_flood")]
    EventFlood {
        threshold: u32,
        window_secs: u64,
    },
}

/// An alert produced by the correlation engine.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedAlert {
    pub rule_name: String,
    pub severity: String,
    pub source_ip: String,
    pub trigger_event_ids: Vec<String>,
    pub count: u32,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Per-IP event record for windowed analysis.
#[derive(Debug, Clone)]
struct EventRecord {
    id: String,
    timestamp: DateTime<Utc>,
    dest_port: u16,
    listener: String,
    event_type: String,
}

/// Tracks per-IP event windows and cooldowns for correlation detection.
pub struct CorrelationEngine {
    rules: Vec<CorrelationRule>,
    /// Per-source-IP rolling event windows.
    windows: HashMap<String, Vec<EventRecord>>,
    /// Cooldown: (rule_name, source_ip) -> last alert time.
    cooldowns: HashMap<(String, String), DateTime<Utc>>,
    /// Channel to send correlated alerts.
    alert_tx: mpsc::UnboundedSender<CorrelatedAlert>,
}

impl CorrelationEngine {
    pub fn new(
        rules: Vec<CorrelationRule>,
        alert_tx: mpsc::UnboundedSender<CorrelatedAlert>,
    ) -> Self {
        Self {
            rules,
            windows: HashMap::new(),
            cooldowns: HashMap::new(),
            alert_tx,
        }
    }

    /// Process an incoming event against all correlation rules.
    pub fn process(&mut self, event: &WatchEvent) {
        let ip = event.source_ip.to_string();

        // Add to the per-IP window.
        let record = EventRecord {
            id: event.id.clone(),
            timestamp: event.timestamp,
            dest_port: event.dest_port,
            listener: event.listener.clone(),
            event_type: event.event_type.to_string(),
        };
        self.windows.entry(ip.clone()).or_default().push(record);

        // Evaluate each rule.
        for rule in &self.rules {
            let (_threshold, window_secs) = match &rule.rule_type {
                CorrelationRuleType::PortScan {
                    threshold,
                    window_secs,
                } => (*threshold, *window_secs),
                CorrelationRuleType::BruteForce {
                    threshold,
                    window_secs,
                } => (*threshold, *window_secs),
                CorrelationRuleType::LateralMovement {
                    threshold,
                    window_secs,
                } => (*threshold, *window_secs),
                CorrelationRuleType::EventFlood {
                    threshold,
                    window_secs,
                } => (*threshold, *window_secs),
            };

            // Check cooldown — don't re-alert within the window period.
            let cooldown_key = (rule.name.clone(), ip.clone());
            if let Some(last_alert) = self.cooldowns.get(&cooldown_key) {
                let elapsed = (event.timestamp - *last_alert).num_seconds();
                if elapsed < window_secs as i64 {
                    continue;
                }
            }

            let cutoff = event.timestamp - chrono::Duration::seconds(window_secs as i64);
            let window_events: Vec<&EventRecord> = self
                .windows
                .get(&ip)
                .map(|events| {
                    events
                        .iter()
                        .filter(|e| e.timestamp >= cutoff)
                        .collect()
                })
                .unwrap_or_default();

            let triggered = match &rule.rule_type {
                CorrelationRuleType::PortScan { threshold, .. } => {
                    // Count unique destination ports.
                    let unique_ports: std::collections::HashSet<u16> =
                        window_events.iter().map(|e| e.dest_port).collect();
                    unique_ports.len() as u32 >= *threshold
                }
                CorrelationRuleType::BruteForce { threshold, .. } => {
                    // Count credential-related events.
                    let cred_count = window_events
                        .iter()
                        .filter(|e| {
                            e.event_type == "CredentialCapture"
                                || e.event_type == "LoginAttempt"
                        })
                        .count() as u32;
                    cred_count >= *threshold
                }
                CorrelationRuleType::LateralMovement { threshold, .. } => {
                    // Count unique listeners hit.
                    let unique_listeners: std::collections::HashSet<&str> =
                        window_events.iter().map(|e| e.listener.as_str()).collect();
                    unique_listeners.len() as u32 >= *threshold
                }
                CorrelationRuleType::EventFlood { threshold, .. } => {
                    window_events.len() as u32 >= *threshold
                }
            };

            if triggered {
                let event_ids: Vec<String> =
                    window_events.iter().map(|e| e.id.clone()).collect();
                let window_start = window_events
                    .iter()
                    .map(|e| e.timestamp)
                    .min()
                    .unwrap_or(event.timestamp);

                let alert = CorrelatedAlert {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    source_ip: ip.clone(),
                    count: window_events.len() as u32,
                    trigger_event_ids: event_ids,
                    window_start,
                    window_end: event.timestamp,
                    created_at: Utc::now(),
                };

                // Set cooldown.
                self.cooldowns
                    .insert(cooldown_key, event.timestamp);

                let _ = self.alert_tx.send(alert);
            }
        }
    }

    /// Prune expired entries from all IP windows.
    pub fn prune(&mut self) {
        let now = Utc::now();
        // Find the maximum window across all rules.
        let max_window = self
            .rules
            .iter()
            .map(|r| match &r.rule_type {
                CorrelationRuleType::PortScan { window_secs, .. } => *window_secs,
                CorrelationRuleType::BruteForce { window_secs, .. } => *window_secs,
                CorrelationRuleType::LateralMovement { window_secs, .. } => *window_secs,
                CorrelationRuleType::EventFlood { window_secs, .. } => *window_secs,
            })
            .max()
            .unwrap_or(600);

        let cutoff = now - chrono::Duration::seconds(max_window as i64 * 2);

        // Remove old events from each IP's window.
        self.windows.retain(|_ip, events| {
            events.retain(|e| e.timestamp >= cutoff);
            !events.is_empty()
        });

        // Clean up stale cooldowns.
        let cooldown_cutoff = now - chrono::Duration::seconds(max_window as i64);
        self.cooldowns
            .retain(|_, last| *last >= cooldown_cutoff);
    }
}

/// Load correlation rules from a YAML file.
pub fn load_rules(path: &str) -> Result<Vec<CorrelationRule>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read correlation rules: {}", path))?;
    let rules: Vec<CorrelationRule> = serde_yaml::from_str(&contents)
        .with_context(|| format!("Failed to parse correlation rules YAML: {}", path))?;
    Ok(rules)
}

/// Default built-in rules (used when no YAML file is configured).
pub fn default_rules() -> Vec<CorrelationRule> {
    vec![
        CorrelationRule {
            name: "port-scan".to_string(),
            description: "Detects port scanning: many unique destination ports from one IP"
                .to_string(),
            severity: "High".to_string(),
            rule_type: CorrelationRuleType::PortScan {
                threshold: 5,
                window_secs: 60,
            },
        },
        CorrelationRule {
            name: "brute-force".to_string(),
            description: "Detects brute force: many credential attempts from one IP".to_string(),
            severity: "High".to_string(),
            rule_type: CorrelationRuleType::BruteForce {
                threshold: 10,
                window_secs: 300,
            },
        },
        CorrelationRule {
            name: "lateral-movement".to_string(),
            description: "Detects lateral movement: one IP hitting many different listeners"
                .to_string(),
            severity: "Critical".to_string(),
            rule_type: CorrelationRuleType::LateralMovement {
                threshold: 3,
                window_secs: 600,
            },
        },
        CorrelationRule {
            name: "event-flood".to_string(),
            description: "Detects event flooding: high volume of events from one IP".to_string(),
            severity: "Medium".to_string(),
            rule_type: CorrelationRuleType::EventFlood {
                threshold: 50,
                window_secs: 60,
            },
        },
    ]
}
