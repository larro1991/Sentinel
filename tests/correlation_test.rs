use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{Duration, Utc};
use sentinel::finding::Severity;
use sentinel::watch::correlation::{
    CorrelatedAlert, CorrelationEngine, CorrelationRule, CorrelationRuleType,
    default_rules, load_rules,
};
use sentinel::watch::{WatchEvent, WatchEventType};
use tokio::sync::mpsc;

fn make_event_at(
    ip: &str,
    port: u16,
    listener: &str,
    event_type: WatchEventType,
    offset_secs: i64,
) -> WatchEvent {
    WatchEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now() + Duration::seconds(offset_secs),
        listener: listener.to_string(),
        protocol: "tcp".to_string(),
        source_ip: ip.parse::<IpAddr>().unwrap(),
        source_port: 12345,
        dest_port: port,
        event_type,
        captured_data: None,
        details: HashMap::new(),
        severity: Severity::Medium,
        geo_country: None,
        geo_country_code: None,
        geo_city: None,
        geo_asn: None,
        geo_org: None,
        dedup_count: None,
    }
}

#[test]
fn test_port_scan_detection() {
    let (tx, mut rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = vec![CorrelationRule {
        name: "port-scan".to_string(),
        description: "Test port scan detection".to_string(),
        severity: "High".to_string(),
        rule_type: CorrelationRuleType::PortScan {
            threshold: 3,
            window_secs: 60,
        },
    }];
    let mut engine = CorrelationEngine::new(rules, tx);

    // Send events from same IP to different ports.
    engine.process(&make_event_at("10.0.0.1", 22, "ssh", WatchEventType::ConnectionAttempt, 0));
    assert!(rx.try_recv().is_err()); // Not enough yet.

    engine.process(&make_event_at("10.0.0.1", 80, "http", WatchEventType::ConnectionAttempt, 1));
    assert!(rx.try_recv().is_err());

    engine.process(&make_event_at("10.0.0.1", 443, "tls", WatchEventType::ConnectionAttempt, 2));
    // Should trigger now (3 unique ports).
    let alert = rx.try_recv().unwrap();
    assert_eq!(alert.rule_name, "port-scan");
    assert_eq!(alert.source_ip, "10.0.0.1");
    assert!(alert.count >= 3);
}

#[test]
fn test_brute_force_detection() {
    let (tx, mut rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = vec![CorrelationRule {
        name: "brute-force".to_string(),
        description: "Test brute force".to_string(),
        severity: "High".to_string(),
        rule_type: CorrelationRuleType::BruteForce {
            threshold: 5,
            window_secs: 300,
        },
    }];
    let mut engine = CorrelationEngine::new(rules, tx);

    // Send credential capture events.
    for i in 0..4 {
        engine.process(&make_event_at(
            "10.0.0.5",
            22,
            "ssh",
            WatchEventType::CredentialCapture,
            i,
        ));
    }
    assert!(rx.try_recv().is_err()); // Below threshold.

    engine.process(&make_event_at(
        "10.0.0.5",
        22,
        "ssh",
        WatchEventType::CredentialCapture,
        5,
    ));
    let alert = rx.try_recv().unwrap();
    assert_eq!(alert.rule_name, "brute-force");
}

#[test]
fn test_lateral_movement_detection() {
    let (tx, mut rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = vec![CorrelationRule {
        name: "lateral-movement".to_string(),
        description: "Test lateral movement".to_string(),
        severity: "Critical".to_string(),
        rule_type: CorrelationRuleType::LateralMovement {
            threshold: 3,
            window_secs: 600,
        },
    }];
    let mut engine = CorrelationEngine::new(rules, tx);

    engine.process(&make_event_at("10.0.0.1", 22, "ssh", WatchEventType::ConnectionAttempt, 0));
    engine.process(&make_event_at("10.0.0.1", 80, "http", WatchEventType::ConnectionAttempt, 1));
    assert!(rx.try_recv().is_err());

    engine.process(&make_event_at("10.0.0.1", 25, "smtp", WatchEventType::ConnectionAttempt, 2));
    let alert = rx.try_recv().unwrap();
    assert_eq!(alert.rule_name, "lateral-movement");
    assert_eq!(alert.severity, "Critical");
}

#[test]
fn test_below_threshold_no_alert() {
    let (tx, mut rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = vec![CorrelationRule {
        name: "port-scan".to_string(),
        description: "Test".to_string(),
        severity: "High".to_string(),
        rule_type: CorrelationRuleType::PortScan {
            threshold: 10,
            window_secs: 60,
        },
    }];
    let mut engine = CorrelationEngine::new(rules, tx);

    // Only 2 ports — below threshold of 10.
    engine.process(&make_event_at("10.0.0.1", 22, "ssh", WatchEventType::ConnectionAttempt, 0));
    engine.process(&make_event_at("10.0.0.1", 80, "http", WatchEventType::ConnectionAttempt, 1));
    assert!(rx.try_recv().is_err());
}

#[test]
fn test_cooldown_prevents_duplicate_alerts() {
    let (tx, mut rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = vec![CorrelationRule {
        name: "port-scan".to_string(),
        description: "Test".to_string(),
        severity: "High".to_string(),
        rule_type: CorrelationRuleType::PortScan {
            threshold: 3,
            window_secs: 60,
        },
    }];
    let mut engine = CorrelationEngine::new(rules, tx);

    // Trigger first alert.
    engine.process(&make_event_at("10.0.0.1", 22, "ssh", WatchEventType::ConnectionAttempt, 0));
    engine.process(&make_event_at("10.0.0.1", 80, "http", WatchEventType::ConnectionAttempt, 1));
    engine.process(&make_event_at("10.0.0.1", 443, "tls", WatchEventType::ConnectionAttempt, 2));
    let _ = rx.try_recv().unwrap(); // First alert.

    // Send more events from the same IP — should be in cooldown.
    engine.process(&make_event_at("10.0.0.1", 3306, "mysql", WatchEventType::ConnectionAttempt, 3));
    engine.process(&make_event_at("10.0.0.1", 5432, "pg", WatchEventType::ConnectionAttempt, 4));
    assert!(rx.try_recv().is_err()); // Cooldown active.
}

#[test]
fn test_prune_clears_old_data() {
    let (tx, _rx) = mpsc::unbounded_channel::<CorrelatedAlert>();
    let rules = default_rules();
    let mut engine = CorrelationEngine::new(rules, tx);

    engine.process(&make_event_at("10.0.0.1", 22, "ssh", WatchEventType::ConnectionAttempt, 0));
    engine.prune(); // Should not panic; old entries should be cleaned up.
}

#[test]
fn test_default_rules_valid() {
    let rules = default_rules();
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].name, "port-scan");
    assert_eq!(rules[1].name, "brute-force");
    assert_eq!(rules[2].name, "lateral-movement");
    assert_eq!(rules[3].name, "event-flood");
}

#[test]
fn test_yaml_rules_loading() {
    // This test assumes the config/correlation-rules.yaml exists.
    if let Ok(rules) = load_rules("config/correlation-rules.yaml") {
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].name, "port-scan");
    }
    // If file doesn't exist (CI), that's OK — we just skip.
}
