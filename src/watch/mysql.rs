use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// MySQL honeypot — sends a server greeting, captures client username, responds
/// with Access Denied.
pub struct MysqlHoneypot;

impl MysqlHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for MysqlHoneypot {
    fn name(&self) -> &str {
        "mysql-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("[mysql-honeypot] Listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("[mysql-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, port, tx).await {
                            tracing::debug!("[mysql-honeypot] Connection handler error ({}): {}", peer_addr, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[mysql-honeypot] Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    let timeout = tokio::time::Duration::from_secs(30);

    tokio::time::timeout(timeout, async {
        // Emit connection event.
        let conn_event = WatchEvent::new(
            "mysql-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Info,
        );
        let _ = events_tx.send(conn_event);

        // Send MySQL server greeting (protocol v10).
        let greeting = build_greeting_packet();
        stream.write_all(&greeting).await?;
        stream.flush().await?;

        // Read client handshake response.
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok::<(), anyhow::Error>(());
        }

        let response = &buf[..n];

        // Extract username from client handshake response.
        // MySQL handshake response (after 4-byte header):
        //   4 bytes: capability flags
        //   4 bytes: max packet size
        //   1 byte:  character set
        //   23 bytes: reserved (zeros)
        //   null-terminated username
        if let Some(username) = extract_username(response) {
            tracing::info!("[mysql-honeypot] Auth attempt from {}: user={}", peer_addr, username);

            let mut event = WatchEvent::new(
                "mysql-honeypot",
                "tcp",
                peer_addr,
                dest_port,
                WatchEventType::CredentialCapture,
                Severity::High,
            );
            event.captured_data = Some(format!("user={}", username));
            event.details.insert("username".to_string(), username);
            let _ = events_tx.send(event);
        }

        // Send ERR_Packet (Access denied).
        let err_packet = build_err_packet(
            1045,
            "28000",
            "Access denied for user (using password: YES)",
        );
        stream.write_all(&err_packet).await?;
        stream.flush().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("MySQL connection timed out ({})", peer_addr))??;

    Ok(())
}

/// Build a MySQL protocol v10 server greeting packet.
fn build_greeting_packet() -> Vec<u8> {
    let mut payload = Vec::new();

    // Protocol version (10).
    payload.push(10);

    // Server version string (null-terminated).
    payload.extend_from_slice(b"5.7.38-log\0");

    // Connection ID (4 bytes, little-endian).
    payload.extend_from_slice(&1u32.to_le_bytes());

    // Auth-plugin-data part 1 (8 bytes of challenge).
    payload.extend_from_slice(&[0x3a, 0x23, 0x7d, 0x4c, 0x5b, 0x60, 0x2a, 0x33]);

    // Filler.
    payload.push(0x00);

    // Capability flags (lower 2 bytes): CLIENT_PROTOCOL_41, SECURE_CONNECTION, etc.
    payload.extend_from_slice(&[0xff, 0xf7]);

    // Character set (utf8 = 33).
    payload.push(33);

    // Status flags (2 bytes).
    payload.extend_from_slice(&[0x02, 0x00]);

    // Capability flags (upper 2 bytes).
    payload.extend_from_slice(&[0xff, 0x81]);

    // Length of auth-plugin-data (21 = 8 + 13).
    payload.push(21);

    // Reserved (10 zeros).
    payload.extend_from_slice(&[0u8; 10]);

    // Auth-plugin-data part 2 (13 bytes including trailing null).
    payload.extend_from_slice(&[
        0x6b, 0x34, 0x7e, 0x29, 0x41, 0x57, 0x3e, 0x68, 0x2f, 0x55, 0x4d, 0x40, 0x00,
    ]);

    // Auth-plugin name (null-terminated).
    payload.extend_from_slice(b"mysql_native_password\0");

    // Wrap in MySQL packet: 3-byte length + 1-byte sequence number.
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(0); // Sequence number 0.
    packet.extend_from_slice(&payload);

    packet
}

/// Extract the username from a MySQL client handshake response packet.
fn extract_username(data: &[u8]) -> Option<String> {
    // Skip 4-byte MySQL packet header.
    if data.len() < 36 {
        return None;
    }
    let payload = &data[4..];

    // Skip: 4 capability + 4 max_packet + 1 charset + 23 reserved = 32 bytes.
    if payload.len() < 33 {
        return None;
    }
    let username_start = 32;

    // Find null terminator for username.
    let username_end = payload[username_start..]
        .iter()
        .position(|&b| b == 0)?;

    let username = String::from_utf8_lossy(&payload[username_start..username_start + username_end]);
    if username.is_empty() {
        return None;
    }

    Some(username.to_string())
}

/// Build a MySQL ERR_Packet.
fn build_err_packet(error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();

    // ERR marker.
    payload.push(0xFF);

    // Error code (2 bytes, little-endian).
    payload.extend_from_slice(&error_code.to_le_bytes());

    // SQL state marker + 5-char state.
    payload.push(b'#');
    let state_bytes = sql_state.as_bytes();
    for i in 0..5 {
        payload.push(if i < state_bytes.len() { state_bytes[i] } else { b' ' });
    }

    // Error message.
    payload.extend_from_slice(message.as_bytes());

    // Wrap in MySQL packet.
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(2); // Sequence number 2 (after greeting=0, client=1).
    packet.extend_from_slice(&payload);

    packet
}
