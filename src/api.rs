use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};

use crate::store::{
    CorrelationFilter, EventFilter, EventStore, FindingFilter,
};

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct ApiState {
    pub store: EventStore,
}

/// Build the axum router with all API endpoints.
pub fn build_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health))
        .route("/api/events", get(get_events))
        .route("/api/findings", get(get_findings))
        .route("/api/correlations", get(get_correlations))
        .route("/api/stats", get(get_stats))
        .layer(cors)
        .with_state(Arc::new(state))
}

/// Start the API server as a tokio task.
pub async fn serve(bind_addr: &str, port: u16, state: ApiState) -> anyhow::Result<()> {
    let app = build_router(state);
    let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;

    tracing::info!("REST API listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn get_events(
    State(state): State<Arc<ApiState>>,
    Query(filter): Query<EventFilter>,
) -> Result<Json<Value>, StatusCode> {
    match state.store.query_events(filter).await {
        Ok(events) => Ok(Json(json!(events))),
        Err(e) => {
            tracing::error!("Failed to query events: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_findings(
    State(state): State<Arc<ApiState>>,
    Query(filter): Query<FindingFilter>,
) -> Result<Json<Value>, StatusCode> {
    match state.store.query_findings(filter).await {
        Ok(findings) => Ok(Json(json!(findings))),
        Err(e) => {
            tracing::error!("Failed to query findings: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_correlations(
    State(state): State<Arc<ApiState>>,
    Query(filter): Query<CorrelationFilter>,
) -> Result<Json<Value>, StatusCode> {
    match state.store.query_correlations(filter).await {
        Ok(corrs) => Ok(Json(json!(corrs))),
        Err(e) => {
            tracing::error!("Failed to query correlations: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_stats(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Value>, StatusCode> {
    match state.store.stats().await {
        Ok(stats) => Ok(Json(json!(stats))),
        Err(e) => {
            tracing::error!("Failed to compute stats: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
