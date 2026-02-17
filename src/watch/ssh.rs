use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use std::time::Duration;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_BANNER: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4";
const MAX_LINE_LENGTH: usize = 4096;

pub struct SshHoneypot {
    banner: String,
}

impl SshHoneypot {
    pub fn new(banner: Option<&str>) -> Self {
        Self {
            banner: banner.unwrap_or(DEFAULT_BANNER).to_string(),
        }
    }
}

#[async_trait]
impl WatchListener for SshHoneypot {
    fn name(&self) -> &str {
        "ssh-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        22
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("SSH honeypot listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("SSH connection from {}", peer_addr);

                            // Emit a ConnectionAttempt event for every new connection.
                            let mut event = WatchEvent::new(
                                self.name(),
                                self.protocol(),
                                peer_addr,
                                bind_addr.port(),
                                WatchEventType::ConnectionAttempt,
                                Severity::Info,
                            );
                            event.details.insert(
                                "banner".to_string(),
                                self.banner.clone(),
                            );
                            let _ = events_tx.send(event);

                            let banner = self.banner.clone();
                            let tx = events_tx.clone();
                            let port = bind_addr.port();
                            let listener_name = self.name().to_string();
                            let protocol = self.protocol().to_string();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    port,
                                    &banner,
                                    &listener_name,
                                    &protocol,
                                    tx,
                                )
                                .await
                                {
                                    debug!(
                                        "SSH honeypot connection from {} ended: {}",
                                        peer_addr, e
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept SSH connection: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("SSH honeypot shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single SSH honeypot connection inside the per-connection timeout.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    banner: &str,
    listener_name: &str,
    protocol: &str,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        // ---- Step 1: Send the server banner ----
        let server_banner = format!("{}\r\n", banner);
        stream.write_all(server_banner.as_bytes()).await?;
        stream.flush().await?;

        // ---- Step 2: Read the client banner line ----
        let client_banner = read_line(&mut stream).await?;
        let client_banner = client_banner.trim().to_string();

        if !client_banner.is_empty() {
            info!("SSH client banner from {}: {}", peer_addr, client_banner);

            let mut event = WatchEvent::new(
                listener_name,
                protocol,
                peer_addr,
                dest_port,
                WatchEventType::BannerGrab,
                Severity::Info,
            );
            event.captured_data = Some(client_banner.clone());
            event
                .details
                .insert("client_banner".to_string(), client_banner);
            let _ = events_tx.send(event);
        }

        // ---- Step 3: Simulate a simplified key-exchange / auth phase ----
        //
        // Real SSH performs a binary key-exchange, but most scanners and
        // brute-forcers send recognisable patterns even in the early bytes.
        // We read additional lines / data and try to extract credential-like
        // information.
        //
        // The honeypot does NOT implement a real SSH protocol -- it simply
        // reads whatever the client sends and looks for username:password
        // patterns that many automated tools send in plaintext or
        // weakly-encoded form.

        let mut buf = vec![0u8; MAX_LINE_LENGTH];
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
            };

            let raw = &buf[..n];
            let data = String::from_utf8_lossy(raw).to_string();

            // Try to extract username / password from the raw payload.
            // Many brute-force tools send cleartext or base64-encoded
            // credentials even before proper key exchange.
            if let Some((username, password)) = try_extract_credentials(&data) {
                warn!(
                    "SSH credential capture from {}: user={} pass={}",
                    peer_addr, username, password
                );

                let mut event = WatchEvent::new(
                    listener_name,
                    protocol,
                    peer_addr,
                    dest_port,
                    WatchEventType::CredentialCapture,
                    Severity::High,
                );
                event.captured_data = Some(format!("{}:{}", username, password));
                event
                    .details
                    .insert("username".to_string(), username);
                event
                    .details
                    .insert("password".to_string(), password);
                let _ = events_tx.send(event);
            } else if !data.trim().is_empty() {
                // Treat any other non-empty payload as a protocol probe.
                debug!("SSH probe data from {}: {:?}", peer_addr, data);

                let mut event = WatchEvent::new(
                    listener_name,
                    protocol,
                    peer_addr,
                    dest_port,
                    WatchEventType::ProtocolProbe,
                    Severity::Low,
                );
                event.captured_data = Some(data);
                let _ = events_tx.send(event);
            }

            // After reading a chunk, send a fake "permission denied" style
            // response to encourage the client to retry and reveal more
            // credentials.  We use an SSH-style disconnect message
            // (plaintext approximation).
            let denial = b"Permission denied (publickey,password).\r\n";
            if stream.write_all(denial).await.is_err() {
                break;
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after {:?}", CONNECTION_TIMEOUT))??;

    Ok(())
}

/// Read a single `\n`-terminated line from the stream, up to `MAX_LINE_LENGTH`
/// bytes.  Returns the line including the terminator so the caller can trim as
/// needed.
async fn read_line(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        match stream.read(&mut byte).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() >= MAX_LINE_LENGTH {
                    break;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(String::from_utf8_lossy(&line).to_string())
}

/// Attempt to extract a username:password pair from raw SSH data.
///
/// This is intentionally simplistic -- it catches:
///   - Literal `user:password` or `user\x00password` patterns that many
///     brute-force bots send.
///   - Null-separated strings (common in SSH userauth requests where the
///     username and password appear as length-prefixed strings).
///
/// Returns `Some((username, password))` if something plausible is found.
fn try_extract_credentials(data: &str) -> Option<(String, String)> {
    // Pattern 1: colon-separated "user:pass" somewhere in the payload.
    if let Some(idx) = data.find(':') {
        let user_part = &data[..idx];
        let pass_part = &data[idx + 1..];

        // Only accept if both sides look like printable, non-empty strings
        // of reasonable length.
        let user = user_part
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();

        let pass = pass_part
            .chars()
            .take_while(|c| !c.is_control())
            .collect::<String>();

        if !user.is_empty() && !pass.is_empty() && user.len() <= 128 && pass.len() <= 256 {
            return Some((user, pass));
        }
    }

    // Pattern 2: null-byte separated segments (binary SSH userauth).
    let segments: Vec<&str> = data.split('\x00').collect();
    if segments.len() >= 2 {
        // Walk through segments looking for two consecutive printable strings.
        for pair in segments.windows(2) {
            let u = pair[0].trim();
            let p = pair[1].trim();
            if !u.is_empty()
                && !p.is_empty()
                && u.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                && p.len() <= 256
            {
                return Some((u.to_string(), p.to_string()));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_banner() {
        let hp = SshHoneypot::new(None);
        assert_eq!(hp.banner, DEFAULT_BANNER);
    }

    #[test]
    fn test_custom_banner() {
        let hp = SshHoneypot::new(Some("SSH-2.0-CustomSSH_1.0"));
        assert_eq!(hp.banner, "SSH-2.0-CustomSSH_1.0");
    }

    #[test]
    fn test_trait_methods() {
        let hp = SshHoneypot::new(None);
        assert_eq!(hp.name(), "ssh-honeypot");
        assert_eq!(hp.protocol(), "tcp");
        assert_eq!(hp.default_port(), 22);
    }

    #[test]
    fn test_extract_colon_credentials() {
        let result = try_extract_credentials("root:toor");
        assert_eq!(result, Some(("root".to_string(), "toor".to_string())));
    }

    #[test]
    fn test_extract_null_credentials() {
        let data = "ssh-userauth\x00admin\x00hunter2\x00";
        let result = try_extract_credentials(data);
        assert_eq!(result, Some(("admin".to_string(), "hunter2".to_string())));
    }

    #[test]
    fn test_extract_no_credentials() {
        assert_eq!(try_extract_credentials("SSH-2.0-libssh_0.9.6"), None);
        assert_eq!(try_extract_credentials(""), None);
    }
}
