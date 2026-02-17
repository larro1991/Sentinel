use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const DEFAULT_BANNER: &str = "220 mail.example.com ESMTP Postfix";

/// Fake SMTP server honeypot.
///
/// Accepts EHLO, AUTH LOGIN/PLAIN (base64 decoded), MAIL FROM/RCPT TO, and
/// captures credentials and email routing attempts.
pub struct SmtpHoneypot {
    banner: String,
}

impl SmtpHoneypot {
    pub fn new(banner: Option<&str>) -> Self {
        Self {
            banner: banner.unwrap_or(DEFAULT_BANNER).to_string(),
        }
    }
}

#[async_trait]
impl WatchListener for SmtpHoneypot {
    fn name(&self) -> &str {
        "smtp-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        25
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        let banner = self.banner.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("[smtp-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();
                    let banner = banner.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, port, &banner, tx).await {
                            tracing::debug!("[smtp-honeypot] Connection handler error ({}): {}", peer_addr, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[smtp-honeypot] Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    banner: &str,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    let timeout = tokio::time::Duration::from_secs(30);

    tokio::time::timeout(timeout, async {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Emit connection event.
        let conn_event = WatchEvent::new(
            "smtp-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Info,
        );
        let _ = events_tx.send(conn_event);

        // Send banner.
        writer.write_all(format!("{}\r\n", banner).as_bytes()).await?;
        writer.flush().await?;

        let mut line = String::new();
        let mut auth_state = AuthState::None;
        let mut auth_username = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim().to_string();
            let upper = trimmed.to_uppercase();

            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                let domain = trimmed.splitn(2, ' ').nth(1).unwrap_or("unknown");
                let mut event = WatchEvent::new(
                    "smtp-honeypot",
                    "tcp",
                    peer_addr,
                    dest_port,
                    WatchEventType::BannerGrab,
                    Severity::Low,
                );
                event.captured_data = Some(format!("EHLO {}", domain));
                event.details.insert("client_domain".to_string(), domain.to_string());
                let _ = events_tx.send(event);

                writer.write_all(b"250-mail.example.com\r\n").await?;
                writer.write_all(b"250-SIZE 52428800\r\n").await?;
                writer.write_all(b"250-AUTH LOGIN PLAIN\r\n").await?;
                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("AUTH LOGIN") {
                auth_state = AuthState::WaitingUsername;
                writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?; // base64("Username:")
                writer.flush().await?;
            } else if upper.starts_with("AUTH PLAIN") {
                // AUTH PLAIN may include base64 inline: AUTH PLAIN <base64>
                let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    // Inline credentials: base64(\0user\0pass)
                    if let Some((user, pass)) = decode_auth_plain(parts[2]) {
                        emit_credential_event(&events_tx, peer_addr, dest_port, &user, &pass);
                    }
                    writer.write_all(b"535 5.7.8 Authentication failed\r\n").await?;
                    writer.flush().await?;
                } else {
                    auth_state = AuthState::WaitingPlain;
                    writer.write_all(b"334\r\n").await?;
                    writer.flush().await?;
                }
            } else if auth_state == AuthState::WaitingUsername {
                // Base64-encoded username.
                auth_username = base64_decode(&trimmed);
                auth_state = AuthState::WaitingPassword;
                writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // base64("Password:")
                writer.flush().await?;
            } else if auth_state == AuthState::WaitingPassword {
                let password = base64_decode(&trimmed);
                emit_credential_event(&events_tx, peer_addr, dest_port, &auth_username, &password);
                auth_state = AuthState::None;
                auth_username.clear();
                writer.write_all(b"535 5.7.8 Authentication failed\r\n").await?;
                writer.flush().await?;
            } else if auth_state == AuthState::WaitingPlain {
                if let Some((user, pass)) = decode_auth_plain(&trimmed) {
                    emit_credential_event(&events_tx, peer_addr, dest_port, &user, &pass);
                }
                auth_state = AuthState::None;
                writer.write_all(b"535 5.7.8 Authentication failed\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("MAIL FROM:") {
                let from = trimmed[10..].trim().to_string();
                let mut event = WatchEvent::new(
                    "smtp-honeypot",
                    "tcp",
                    peer_addr,
                    dest_port,
                    WatchEventType::EmailAttempt,
                    Severity::Medium,
                );
                event.captured_data = Some(from.clone());
                event.details.insert("mail_from".to_string(), from);
                let _ = events_tx.send(event);

                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("RCPT TO:") {
                let to = trimmed[8..].trim().to_string();
                let mut event = WatchEvent::new(
                    "smtp-honeypot",
                    "tcp",
                    peer_addr,
                    dest_port,
                    WatchEventType::EmailAttempt,
                    Severity::Medium,
                );
                event.captured_data = Some(to.clone());
                event.details.insert("rcpt_to".to_string(), to);
                let _ = events_tx.send(event);

                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("DATA") {
                writer.write_all(b"354 Start mail input\r\n").await?;
                writer.flush().await?;
                // Read until lone "." on a line.
                loop {
                    line.clear();
                    let n = reader.read_line(&mut line).await?;
                    if n == 0 || line.trim() == "." {
                        break;
                    }
                }
                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("QUIT") {
                writer.write_all(b"221 Bye\r\n").await?;
                writer.flush().await?;
                break;
            } else if upper.starts_with("RSET") {
                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("NOOP") {
                writer.write_all(b"250 OK\r\n").await?;
                writer.flush().await?;
            } else {
                writer.write_all(b"502 Command not implemented\r\n").await?;
                writer.flush().await?;
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("SMTP connection timed out ({})", peer_addr))??;

    Ok(())
}

#[derive(PartialEq)]
enum AuthState {
    None,
    WaitingUsername,
    WaitingPassword,
    WaitingPlain,
}

fn emit_credential_event(
    events_tx: &mpsc::UnboundedSender<WatchEvent>,
    peer_addr: SocketAddr,
    dest_port: u16,
    username: &str,
    password: &str,
) {
    let mut event = WatchEvent::new(
        "smtp-honeypot",
        "tcp",
        peer_addr,
        dest_port,
        WatchEventType::CredentialCapture,
        Severity::High,
    );
    event.captured_data = Some(format!("{}:{}", username, password));
    event.details.insert("username".to_string(), username.to_string());
    event.details.insert("password".to_string(), password.to_string());
    let _ = events_tx.send(event);
}

/// Minimal base64 decode (for SMTP AUTH). Returns the decoded UTF-8 string or
/// the original on failure.
fn base64_decode(input: &str) -> String {
    // Simple base64 decode without pulling in a base64 crate.
    // We do a manual implementation for the small payloads expected.
    match manual_base64_decode(input.trim().as_bytes()) {
        Some(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| input.to_string()),
        None => input.to_string(),
    }
}

/// Decode a base64 AUTH PLAIN blob: \0username\0password
fn decode_auth_plain(input: &str) -> Option<(String, String)> {
    let bytes = manual_base64_decode(input.trim().as_bytes())?;
    // Format: \0username\0password or authzid\0username\0password
    let parts: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
    if parts.len() >= 3 {
        let user = String::from_utf8_lossy(parts[1]).to_string();
        let pass = String::from_utf8_lossy(parts[2]).to_string();
        if !user.is_empty() {
            return Some((user, pass));
        }
    } else if parts.len() == 2 {
        let user = String::from_utf8_lossy(parts[0]).to_string();
        let pass = String::from_utf8_lossy(parts[1]).to_string();
        if !user.is_empty() {
            return Some((user, pass));
        }
    }
    None
}

fn manual_base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let input: Vec<u8> = input.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;

    while i < input.len() {
        let a = val(input[i])?;
        let b = if i + 1 < input.len() { val(input[i + 1])? } else { return Some(out) };

        out.push((a << 2) | (b >> 4));

        if i + 2 < input.len() && input[i + 2] != b'=' {
            let c = val(input[i + 2])?;
            out.push((b << 4) | (c >> 2));

            if i + 3 < input.len() && input[i + 3] != b'=' {
                let d = val(input[i + 3])?;
                out.push((c << 6) | d);
            }
        }

        i += 4;
    }

    Some(out)
}
