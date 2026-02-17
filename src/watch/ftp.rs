use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// A fake FTP server that captures connection attempts and credentials.
pub struct FtpHoneypot {
    banner: String,
}

impl FtpHoneypot {
    pub fn new(banner: Option<&str>) -> Self {
        Self {
            banner: banner.unwrap_or("220 FTP Server Ready").to_string(),
        }
    }
}

#[async_trait]
impl WatchListener for FtpHoneypot {
    fn name(&self) -> &str {
        "ftp-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        2121
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
                            tracing::warn!("[ftp-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();
                    let banner = banner.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, port, &banner, tx).await {
                            tracing::debug!("[ftp-honeypot] Connection handler error ({}): {}", peer_addr, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[ftp-honeypot] Shutdown signal received");
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

        // Emit connection attempt event.
        let conn_event = WatchEvent::new(
            "ftp-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Info,
        );
        let _ = events_tx.send(conn_event);

        // Send the FTP banner.
        writer.write_all(format!("{}\r\n", banner).as_bytes()).await?;
        writer.flush().await?;

        let mut username: Option<String> = None;
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                // Client disconnected.
                break;
            }

            let trimmed = line.trim().to_string();
            let upper = trimmed.to_uppercase();

            if upper.starts_with("USER ") {
                let user = trimmed[5..].to_string();
                username = Some(user);
                writer.write_all(b"331 Password required\r\n").await?;
                writer.flush().await?;
            } else if upper.starts_with("PASS ") {
                let pass = trimmed[5..].to_string();
                let user = username.clone().unwrap_or_default();

                // Emit credential capture event.
                let mut cred_event = WatchEvent::new(
                    "ftp-honeypot",
                    "tcp",
                    peer_addr,
                    dest_port,
                    WatchEventType::CredentialCapture,
                    Severity::High,
                );
                cred_event.captured_data = Some(format!("{}:{}", user, pass));
                cred_event.details.insert("username".to_string(), user);
                cred_event.details.insert("password".to_string(), pass);
                let _ = events_tx.send(cred_event);

                writer.write_all(b"530 Login incorrect\r\n").await?;
                writer.flush().await?;

                // Close after capturing credentials.
                break;
            } else if upper.starts_with("QUIT") {
                writer.write_all(b"221 Goodbye\r\n").await?;
                writer.flush().await?;
                break;
            } else {
                writer.write_all(b"502 Command not implemented\r\n").await?;
                writer.flush().await?;
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("FTP connection timed out ({})", peer_addr))??;

    Ok(())
}
