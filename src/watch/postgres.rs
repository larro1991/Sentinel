use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// PostgreSQL honeypot — reads client startup message, extracts username,
/// sends MD5 password challenge, captures password hash, responds with error.
pub struct PostgresHoneypot;

impl PostgresHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for PostgresHoneypot {
    fn name(&self) -> &str {
        "postgres-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        5432
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("[postgres-honeypot] Listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("[postgres-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, port, tx).await {
                            tracing::debug!("[postgres-honeypot] Connection handler error ({}): {}", peer_addr, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[postgres-honeypot] Shutdown signal received");
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
            "postgres-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Info,
        );
        let _ = events_tx.send(conn_event);

        // Read the startup message.
        // PostgreSQL startup message: 4-byte length (including itself), then data.
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        if msg_len < 8 || msg_len > 10000 {
            return Ok::<(), anyhow::Error>(());
        }

        let mut msg_buf = vec![0u8; msg_len - 4];
        stream.read_exact(&mut msg_buf).await?;

        // First 4 bytes of the body are the protocol version.
        let proto_major = u16::from_be_bytes([msg_buf[0], msg_buf[1]]);
        let proto_minor = u16::from_be_bytes([msg_buf[2], msg_buf[3]]);

        // Handle SSLRequest (protocol 1234.5679).
        if proto_major == 1234 && proto_minor == 5679 {
            // Deny SSL, send 'N'.
            stream.write_all(b"N").await?;
            stream.flush().await?;

            // Client should send a new startup message.
            stream.read_exact(&mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len < 8 || msg_len > 10000 {
                return Ok::<(), anyhow::Error>(());
            }
            msg_buf = vec![0u8; msg_len - 4];
            stream.read_exact(&mut msg_buf).await?;
        }

        // Parse key-value pairs from the startup message body (after 4-byte version).
        let params = parse_startup_params(&msg_buf[4..]);

        let username = params
            .iter()
            .find(|(k, _)| k == "user")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let database = params
            .iter()
            .find(|(k, _)| k == "database")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        if !username.is_empty() {
            tracing::info!(
                "[postgres-honeypot] Startup from {}: user={} database={}",
                peer_addr,
                username,
                database
            );

            let mut event = WatchEvent::new(
                "postgres-honeypot",
                "tcp",
                peer_addr,
                dest_port,
                WatchEventType::CredentialCapture,
                Severity::High,
            );
            event.captured_data = Some(format!("user={}", username));
            event.details.insert("username".to_string(), username.clone());
            if !database.is_empty() {
                event.details.insert("database".to_string(), database);
            }
            let _ = events_tx.send(event);
        }

        // Send AuthenticationMD5Password (type 'R', method 5, 4-byte salt).
        let salt: [u8; 4] = [0x7a, 0x3b, 0x2c, 0x1d];
        let mut auth_msg = Vec::new();
        auth_msg.push(b'R'); // AuthenticationXxx message type.
        let auth_len: u32 = 4 + 4 + 4; // length(4) + method(4) + salt(4)
        auth_msg.extend_from_slice(&auth_len.to_be_bytes());
        auth_msg.extend_from_slice(&5u32.to_be_bytes()); // method=5 (MD5)
        auth_msg.extend_from_slice(&salt);
        stream.write_all(&auth_msg).await?;
        stream.flush().await?;

        // Read PasswordMessage.
        let mut type_buf = [0u8; 1];
        if stream.read_exact(&mut type_buf).await.is_ok() && type_buf[0] == b'p' {
            stream.read_exact(&mut len_buf).await?;
            let pw_len = u32::from_be_bytes(len_buf) as usize;
            if pw_len > 4 && pw_len < 1024 {
                let mut pw_buf = vec![0u8; pw_len - 4];
                stream.read_exact(&mut pw_buf).await?;

                // The password is an MD5 hash string (null-terminated).
                let pw_str = String::from_utf8_lossy(&pw_buf)
                    .trim_end_matches('\0')
                    .to_string();

                if !pw_str.is_empty() {
                    let mut event = WatchEvent::new(
                        "postgres-honeypot",
                        "tcp",
                        peer_addr,
                        dest_port,
                        WatchEventType::CredentialCapture,
                        Severity::High,
                    );
                    event.captured_data = Some(format!("user={} md5hash={}", username, pw_str));
                    event.details.insert("username".to_string(), username);
                    event.details.insert("md5_hash".to_string(), pw_str);
                    let _ = events_tx.send(event);
                }
            }
        }

        // Send ErrorResponse.
        let error_msg = build_error_response(
            "FATAL",
            "28P01",
            "password authentication failed",
        );
        stream.write_all(&error_msg).await?;
        stream.flush().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("PostgreSQL connection timed out ({})", peer_addr))??;

    Ok(())
}

/// Parse null-terminated key-value pairs from a PostgreSQL startup message body.
fn parse_startup_params(data: &[u8]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() || data[pos] == 0 {
            break;
        }

        // Read key (null-terminated).
        let key_end = data[pos..].iter().position(|&b| b == 0);
        let key_end = match key_end {
            Some(e) => pos + e,
            None => break,
        };
        let key = String::from_utf8_lossy(&data[pos..key_end]).to_string();
        pos = key_end + 1;

        // Read value (null-terminated).
        if pos >= data.len() {
            break;
        }
        let val_end = data[pos..].iter().position(|&b| b == 0);
        let val_end = match val_end {
            Some(e) => pos + e,
            None => break,
        };
        let val = String::from_utf8_lossy(&data[pos..val_end]).to_string();
        pos = val_end + 1;

        params.push((key, val));
    }

    params
}

/// Build a PostgreSQL ErrorResponse message.
fn build_error_response(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut fields = Vec::new();

    // Severity field.
    fields.push(b'S');
    fields.extend_from_slice(severity.as_bytes());
    fields.push(0);

    // SQLSTATE code.
    fields.push(b'C');
    fields.extend_from_slice(code.as_bytes());
    fields.push(0);

    // Message.
    fields.push(b'M');
    fields.extend_from_slice(message.as_bytes());
    fields.push(0);

    // Terminator.
    fields.push(0);

    let mut msg = Vec::new();
    msg.push(b'E'); // ErrorResponse type.
    let len = (4 + fields.len()) as u32;
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&fields);

    msg
}
