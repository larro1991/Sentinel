use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use std::time::Duration;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum bytes to read for the initial RDP connection request.
/// A typical X.224 Connection Request PDU is well under 1024 bytes.
const MAX_REQUEST_LENGTH: usize = 4096;

/// Cookie prefix used by RDP clients to send a routing token.
const COOKIE_PREFIX: &str = "Cookie: mstshash=";

/// Minimal X.224 Connection Confirm (CC) response.
///
/// - TPKT header: version 3, total length 19
/// - X.224 CC PDU with class 0
/// - RDP Negotiation Response selecting standard RDP (protocol 0)
const X224_CONNECTION_CONFIRM: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, // TPKT header (version 3, length 19)
    0x0e,                   // X.224 length
    0xd0,                   // X.224 CC (Connection Confirm)
    0x00, 0x00,             // DST-REF
    0x00, 0x00,             // SRC-REF
    0x00,                   // Class 0
    0x02, 0x00, 0x08, 0x00, // RDP Negotiation Response
    0x00, 0x00, 0x00,       // Flags + selected protocol (0 = standard RDP)
];

pub struct RdpHoneypot;

impl RdpHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for RdpHoneypot {
    fn name(&self) -> &str {
        "rdp-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        3389
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("RDP honeypot listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("RDP connection from {}", peer_addr);

                            let tx = events_tx.clone();
                            let port = bind_addr.port();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    port,
                                    tx,
                                ).await {
                                    debug!(
                                        "RDP honeypot connection from {} ended: {}",
                                        peer_addr, e
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept RDP connection: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("RDP honeypot shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single RDP honeypot connection inside the per-connection timeout.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        // ---- Step 1: Read the initial RDP connection request ----
        let mut buf = vec![0u8; MAX_REQUEST_LENGTH];
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            return Ok::<(), anyhow::Error>(());
        }

        let raw = &buf[..n];

        // ---- Step 2: Parse the X.224 Connection Request ----
        let is_tpkt = raw[0] == 0x03;
        let cookie = extract_cookie(raw);

        // Build the event.
        let mut event = WatchEvent::new(
            "rdp-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Medium,
        );

        if is_tpkt {
            event
                .details
                .insert("tpkt_version".to_string(), "3".to_string());
        }

        // If we have at least 6 bytes, check for the X.224 CR type code.
        if n >= 6 {
            let x224_type = raw[5];
            event.details.insert(
                "x224_type".to_string(),
                format!("0x{:02x}", x224_type),
            );

            // 0xe0 = Connection Request (CR) PDU
            if x224_type == 0xe0 {
                event
                    .details
                    .insert("pdu_type".to_string(), "Connection Request".to_string());
            }
        }

        event.details.insert(
            "request_length".to_string(),
            n.to_string(),
        );

        if let Some(ref cookie_value) = cookie {
            warn!(
                "RDP cookie captured from {}: {}",
                peer_addr, cookie_value
            );
            event
                .details
                .insert("cookie".to_string(), cookie_value.clone());
            event.captured_data = Some(cookie_value.clone());
        }

        let _ = events_tx.send(event);

        // ---- Step 3: Send X.224 Connection Confirm and close ----
        stream.write_all(X224_CONNECTION_CONFIRM).await?;
        stream.flush().await?;

        // Shut down the write side to signal the client we are done.
        let _ = stream.shutdown().await;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after {:?}", CONNECTION_TIMEOUT))??;

    Ok(())
}

/// Try to extract the routing cookie / token from an X.224 Connection Request.
///
/// RDP clients typically embed a cookie of the form `Cookie: mstshash=<value>\r\n`
/// inside the variable portion of the X.224 CR PDU.  We scan the raw bytes for
/// this prefix and return the value if found.
fn extract_cookie(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    if let Some(start) = text.find(COOKIE_PREFIX) {
        let after_prefix = &text[start + COOKIE_PREFIX.len()..];
        // The cookie value is terminated by \r\n or end of data.
        let value: String = after_prefix
            .chars()
            .take_while(|c| *c != '\r' && *c != '\n')
            .collect();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trait_methods() {
        let hp = RdpHoneypot::new();
        assert_eq!(hp.name(), "rdp-honeypot");
        assert_eq!(hp.protocol(), "tcp");
        assert_eq!(hp.default_port(), 3389);
    }

    #[test]
    fn test_extract_cookie_present() {
        // Simulate a minimal X.224 CR with a cookie embedded.
        let mut pdu: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x2f, // TPKT header
            0x2a,                   // X.224 length
            0xe0,                   // X.224 CR
            0x00, 0x00,             // DST-REF
            0x00, 0x00,             // SRC-REF
            0x00,                   // Class 0
        ];
        pdu.extend_from_slice(b"Cookie: mstshash=testuser\r\n");
        let result = extract_cookie(&pdu);
        assert_eq!(result, Some("testuser".to_string()));
    }

    #[test]
    fn test_extract_cookie_absent() {
        let pdu: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x0b,
            0x06,
            0xe0,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
        ];
        assert_eq!(extract_cookie(&pdu), None);
    }

    #[test]
    fn test_extract_cookie_no_crlf() {
        // Cookie at end of data without \r\n terminator.
        let mut pdu: Vec<u8> = vec![0x03, 0x00, 0x00, 0x20, 0x1b, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00];
        pdu.extend_from_slice(b"Cookie: mstshash=admin");
        let result = extract_cookie(&pdu);
        assert_eq!(result, Some("admin".to_string()));
    }

    #[test]
    fn test_connection_confirm_length() {
        // The TPKT header says total length is 19.
        assert_eq!(X224_CONNECTION_CONFIRM.len(), 19);
        assert_eq!(X224_CONNECTION_CONFIRM[3], 0x13); // 0x13 == 19
    }
}
