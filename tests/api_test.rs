use std::collections::HashMap;
use std::net::IpAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use sentinel::api::{build_router, ApiState};
use sentinel::finding::Severity;
use sentinel::store::EventStore;
use sentinel::watch::{WatchEvent, WatchEventType};
use tower::ServiceExt; // for oneshot

async fn setup() -> (ApiState, EventStore) {
    let store = EventStore::open_memory().await.unwrap();
    let state = ApiState {
        store: store.clone(),
    };
    (state, store)
}

fn make_event(ip: &str, port: u16) -> WatchEvent {
    WatchEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        listener: "test".to_string(),
        protocol: "tcp".to_string(),
        source_ip: ip.parse::<IpAddr>().unwrap(),
        source_port: 12345,
        dest_port: port,
        event_type: WatchEventType::ConnectionAttempt,
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

#[tokio::test]
async fn test_health_endpoint() {
    let (state, _store) = setup().await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn test_events_endpoint() {
    let (state, store) = setup().await;

    // Insert some events.
    store.insert_event(&make_event("10.0.0.1", 22)).await.unwrap();
    store.insert_event(&make_event("10.0.0.2", 80)).await.unwrap();

    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().len() == 2);
}

#[tokio::test]
async fn test_events_filter_by_severity() {
    let (state, store) = setup().await;

    let mut event_high = make_event("10.0.0.1", 22);
    event_high.severity = Severity::High;
    store.insert_event(&event_high).await.unwrap();
    store.insert_event(&make_event("10.0.0.2", 80)).await.unwrap(); // Medium

    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/events?severity=HIGH")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_stats_endpoint() {
    let (state, store) = setup().await;

    store.insert_event(&make_event("10.0.0.1", 22)).await.unwrap();
    store.insert_event(&make_event("10.0.0.1", 80)).await.unwrap();
    store.insert_event(&make_event("10.0.0.2", 22)).await.unwrap();

    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["event_count"], 3);
}

#[tokio::test]
async fn test_cors_headers() {
    let (state, _store) = setup().await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("Origin", "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    // CORS layer should add access-control-allow-origin header.
    assert!(resp.headers().contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn test_findings_endpoint_empty() {
    let (state, _store) = setup().await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/findings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_correlations_endpoint_empty() {
    let (state, _store) = setup().await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/correlations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}
