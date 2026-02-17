use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// A fake Telnet service that captures login credentials from attackers.
pub struct TelnetHoneypot;

impl TelnetHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for TelnetHoneypot {
    fn name(&self) -> &str {
        "telnet-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        2323
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("[telnet-honeypot] Listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("[telnet-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, port, tx).await {
                            tracing::debug!(
                                "[telnet-honeypot] Connection from {} ended: {}",
                                peer_addr,
                                e,
                            );
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[telnet-honeypot] Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single Telnet connection: present a login prompt, capture
/// credentials, then reject and close.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    let timeout = tokio::time::Duration::from_secs(30);

    tokio::time::timeout(timeout, async {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send login prompt.
        writer.write_all(b"login: ").await?;
        writer.flush().await?;

        // Read username.
        let mut username = String::new();
        reader.read_line(&mut username).await?;
        let username = username.trim().to_string();

        // Send password prompt.
        writer.write_all(b"Password: ").await?;
        writer.flush().await?;

        // Read password.
        let mut password = String::new();
        reader.read_line(&mut password).await?;
        let password = password.trim().to_string();

        // Emit credential capture event.
        let mut event = WatchEvent::new(
            "telnet-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::CredentialCapture,
            Severity::High,
        );
        event.captured_data = Some(format!("{}:{}", username, password));
        event.details.insert("username".to_string(), username);
        event.details.insert("password".to_string(), password);

        let _ = events_tx.send(event);

        // Reject the login and close.
        writer.write_all(b"Login incorrect\r\n").await?;
        writer.flush().await?;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Connection timed out"))??;

    Ok(())
}
