use std::collections::HashMap;
use std::net::IpAddr;

use chrono::Utc;
use sentinel::finding::{Finding, Severity};
use sentinel::store::{CorrelationRow, EventFilter, EventStore, FindingFilter, CorrelationFilter};
use sentinel::watch::{WatchEvent, WatchEventType};

fn make_event(ip: &str, port: u16, event_type: WatchEventType, severity: Severity) -> WatchEvent {
    WatchEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        listener: "test-listener".to_string(),
        protocol: "tcp".to_string(),
        source_ip: ip.parse::<IpAddr>().unwrap(),
        source_port: 12345,
        dest_port: port,
        event_type,
        captured_data: Some("test data".to_string()),
        details: HashMap::new(),
        severity,
        geo_country: None,
        geo_country_code: None,
        geo_city: None,
        geo_asn: None,
        geo_org: None,
        dedup_count: None,
    }
}

#[tokio::test]
async fn test_store_insert_and_query_events() {
    let store = EventStore::open_memory().await.unwrap();

    let event1 = make_event("10.0.0.1", 22, WatchEventType::ConnectionAttempt, Severity::Medium);
    let event2 = make_event("10.0.0.2", 80, WatchEventType::CredentialCapture, Severity::High);
    let event3 = make_event("10.0.0.1", 443, WatchEventType::BannerGrab, Severity::Low);

    store.insert_event(&event1).await.unwrap();
    store.insert_event(&event2).await.unwrap();
    store.insert_event(&event3).await.unwrap();

    // Query all.
    let all = store.query_events(EventFilter::default()).await.unwrap();
    assert_eq!(all.len(), 3);

    // Filter by IP.
    let filtered = store
        .query_events(EventFilter {
            source_ip: Some("10.0.0.1".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(filtered.len(), 2);

    // Filter by severity.
    let high_only = store
        .query_events(EventFilter {
            severity: Some("HIGH".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(high_only.len(), 1);
    assert_eq!(high_only[0].source_ip, "10.0.0.2");
}

#[tokio::test]
async fn test_store_insert_and_query_findings() {
    let store = EventStore::open_memory().await.unwrap();

    let finding = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        title: "Test Finding".to_string(),
        severity: Severity::High,
        cvss_score: Some(7.5),
        cvss_vector: None,
        cwe_id: Some("CWE-200".to_string()),
        cve_ids: vec![],
        affected_asset: "10.0.0.1:80".to_string(),
        affected_component: Some("HTTP".to_string()),
        description: "A test finding".to_string(),
        evidence: vec![],
        remediation: "Fix it".to_string(),
        references: vec![],
        module_name: "test-check".to_string(),
        timestamp: Utc::now(),
    };

    store.insert_finding(&finding).await.unwrap();

    let results = store
        .query_findings(FindingFilter::default())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].title, "Test Finding");
    assert_eq!(results[0].severity, "HIGH");
}

#[tokio::test]
async fn test_store_insert_and_query_correlations() {
    let store = EventStore::open_memory().await.unwrap();

    let corr = CorrelationRow {
        rule_name: "port-scan".to_string(),
        severity: "High".to_string(),
        source_ip: "10.0.0.5".to_string(),
        trigger_event_ids: vec!["id1".to_string(), "id2".to_string()],
        event_count: 5,
        window_start: Utc::now().to_rfc3339(),
        window_end: Utc::now().to_rfc3339(),
        created_at: Utc::now().to_rfc3339(),
    };

    store.insert_correlation(&corr).await.unwrap();

    let results = store
        .query_correlations(CorrelationFilter::default())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_name, "port-scan");
    assert_eq!(results[0].event_count, 5);
}

#[tokio::test]
async fn test_store_stats() {
    let store = EventStore::open_memory().await.unwrap();

    // Insert events with different severities.
    for i in 0..5 {
        let sev = if i < 2 {
            Severity::High
        } else {
            Severity::Medium
        };
        let event = make_event("10.0.0.1", 22 + i, WatchEventType::ConnectionAttempt, sev);
        store.insert_event(&event).await.unwrap();
    }

    let stats = store.stats().await.unwrap();
    assert_eq!(stats.event_count, 5);
    assert_eq!(*stats.events_by_severity.get("HIGH").unwrap_or(&0), 2);
    assert_eq!(*stats.events_by_severity.get("MEDIUM").unwrap_or(&0), 3);
    assert_eq!(stats.top_source_ips.len(), 1);
    assert_eq!(stats.top_source_ips[0].0, "10.0.0.1");
}

#[tokio::test]
async fn test_store_limit_offset() {
    let store = EventStore::open_memory().await.unwrap();

    for i in 0..10 {
        let event = make_event(
            &format!("10.0.0.{}", i),
            22,
            WatchEventType::ConnectionAttempt,
            Severity::Info,
        );
        store.insert_event(&event).await.unwrap();
    }

    let page1 = store
        .query_events(EventFilter {
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page1.len(), 5);

    let page2 = store
        .query_events(EventFilter {
            limit: Some(5),
            offset: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page2.len(), 5);
}
