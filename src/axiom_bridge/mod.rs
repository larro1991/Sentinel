//! AXIOM Bridge - Secure Communication Layer
//!
//! Bridges SENTINEL to EMBER through the AXIOM protocol using axiom-client.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use axiom_client::{AxiomClient, ClientConfig, ClientError, ConnectionState as AxiomConnectionState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub ember_endpoint: String,
    pub identity_file: Option<PathBuf>,
    pub auth_token: Option<String>,
    pub max_reconnect_attempts: u32,
    pub request_timeout_secs: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            ember_endpoint: "axiom://localhost:7777".to_string(),
            identity_file: None,
            auth_token: None,
            max_reconnect_attempts: 5,
            request_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected, Connecting, Authenticating, Connected, Reconnecting, Error(String),
}

impl From<AxiomConnectionState> for ConnectionState {
    fn from(state: AxiomConnectionState) -> Self {
        match state {
            AxiomConnectionState::Disconnected => ConnectionState::Disconnected,
            AxiomConnectionState::Connecting => ConnectionState::Connecting,
            AxiomConnectionState::Authenticating => ConnectionState::Authenticating,
            AxiomConnectionState::Connected => ConnectionState::Connected,
            AxiomConnectionState::Reconnecting => ConnectionState::Reconnecting,
            AxiomConnectionState::Failed(e) => ConnectionState::Error(e),
        }
    }
}

pub struct AxiomBridge {
    config: BridgeConfig,
    client: Option<AxiomClient>,
    state: Arc<RwLock<ConnectionState>>,
}

impl AxiomBridge {
    pub fn new(config: BridgeConfig) -> Self {
        Self { config, client: None, state: Arc::new(RwLock::new(ConnectionState::Disconnected)) }
    }

    pub async fn state(&self) -> ConnectionState { self.state.read().await.clone() }
    pub async fn is_connected(&self) -> bool { matches!(*self.state.read().await, ConnectionState::Connected) }

    pub async fn connect(&mut self) -> Result<(), BridgeError> {
        *self.state.write().await = ConnectionState::Connecting;
        info!("Connecting to EMBER at {}", self.config.ember_endpoint);
        let mut cc = ClientConfig::new(&self.config.ember_endpoint)
            .with_request_timeout(Duration::from_secs(self.config.request_timeout_secs))
            .with_max_reconnect_attempts(self.config.max_reconnect_attempts);
        if let Some(ref p) = self.config.identity_file { cc = cc.with_identity_file(p); }
        if let Some(ref t) = self.config.auth_token { cc = cc.with_auth_token(t); }
        match AxiomClient::connect(cc).await {
            Ok(c) => { self.client = Some(c); *self.state.write().await = ConnectionState::Connected; Ok(()) }
            Err(e) => { let m = e.to_string(); *self.state.write().await = ConnectionState::Error(m.clone()); Err(BridgeError::ConnectionFailed(m)) }
        }
    }

    pub async fn disconnect(&mut self) -> Result<(), BridgeError> {
        if let Some(mut c) = self.client.take() { c.disconnect().await.map_err(BridgeError::from)?; }
        *self.state.write().await = ConnectionState::Disconnected;
        Ok(())
    }

    fn get_client(&self) -> Result<&AxiomClient, BridgeError> { self.client.as_ref().ok_or(BridgeError::NotConnected) }

    /// Send recon results to EMBER (fire-and-forget event).
    /// TODO: serialize to Intent::Event and send_intent_async when transport is live.
    pub fn send_recon_results(&self, results: &[serde_json::Value]) {
        info!("AXIOM: send_recon_results ({} results)", results.len());
        if self.client.is_none() {
            debug!("Bridge not connected — recon results dropped");
        }
    }

    /// Report a finding to EMBER.
    /// TODO: Intent::Event → send_intent_async when transport is live.
    pub fn report_finding(&self, finding: &crate::core::Finding) {
        info!(
            "AXIOM: report_finding id={} severity={:?} title={}",
            finding.id.0, finding.severity, finding.title
        );
        if self.client.is_none() {
            debug!("Bridge not connected — finding dropped");
        }
    }

    /// Request an attack plan from EMBER given current engagement state.
    /// TODO: Intent::Request → await AttackGraph response when transport is live.
    pub fn request_plan(&self, current_state: &serde_json::Value) {
        info!("AXIOM: request_plan state_keys={:?}", current_state.as_object().map(|o| o.keys().collect::<Vec<_>>()));
        if self.client.is_none() {
            debug!("Bridge not connected — plan request dropped");
        }
    }

    /// Request human/AI approval for a high-risk action.
    /// TODO: Intent::Request with approval flag → await ApprovalResponse when transport is live.
    pub fn request_approval(&self, action: &str, impact: crate::core::Severity) {
        info!("AXIOM: request_approval action='{}' impact={:?}", action, impact);
        if self.client.is_none() {
            warn!("Bridge not connected — approval request dropped (action will be blocked)");
        }
    }

    /// Signal emergency stop to EMBER. Always logs regardless of connection state.
    /// TODO: Intent::Command with Emergency priority → blocking send when transport is live.
    pub fn emergency_stop(&self, reason: &str) {
        warn!("AXIOM: emergency_stop reason='{}'", reason);
        if self.client.is_none() {
            warn!("Bridge not connected — emergency stop not forwarded to EMBER");
        }
    }
}

#[derive(Debug, Clone)]
pub enum BridgeError {
    NotConnected, ConnectionFailed(String), AuthenticationFailed(String), SendFailed(String),
    ReceiveFailed(String), Timeout(String), InvalidResponse(String), ApprovalFailed(String),
    ScanStartFailed(String), Client(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "Not connected to EMBER"),
            Self::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            Self::AuthenticationFailed(e) => write!(f, "Auth failed: {}", e),
            Self::SendFailed(e) => write!(f, "Send failed: {}", e),
            Self::ReceiveFailed(e) => write!(f, "Receive failed: {}", e),
            Self::Timeout(e) => write!(f, "Timeout: {}", e),
            Self::InvalidResponse(e) => write!(f, "Invalid response: {}", e),
            Self::ApprovalFailed(e) => write!(f, "Approval failed: {}", e),
            Self::ScanStartFailed(e) => write!(f, "Scan start failed: {}", e),
            Self::Client(e) => write!(f, "Client error: {}", e),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<ClientError> for BridgeError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::ConnectionFailed(e) => BridgeError::ConnectionFailed(e),
            ClientError::ConnectionClosed(_) => BridgeError::NotConnected,
            ClientError::AuthenticationFailed(e) => BridgeError::AuthenticationFailed(e),
            ClientError::Timeout(e) => BridgeError::Timeout(e),
            _ => BridgeError::Client(err.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub approved: bool, pub action: String, pub reason: Option<String>, pub modified_params: Option<serde_json::Value>,
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
