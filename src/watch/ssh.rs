use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use std::time::Duration;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const SHELL_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_BANNER: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4";
const MAX_LINE_LENGTH: usize = 4096;
const SHELL_PROMPT: &str = "root@ubuntu-server:~$ ";

pub struct SshHoneypot {
    banner: String,
    shell_enabled: bool,
}

impl SshHoneypot {
    pub fn new(banner: Option<&str>, shell_enabled: bool) -> Self {
        Self {
            banner: banner.unwrap_or(DEFAULT_BANNER).to_string(),
            shell_enabled,
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
                            let shell_enabled = self.shell_enabled;

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    port,
                                    &banner,
                                    &listener_name,
                                    &protocol,
                                    tx,
                                    shell_enabled,
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
    shell_enabled: bool,
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
        let mut credentials_captured = false;
        let mut buf = vec![0u8; MAX_LINE_LENGTH];
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
            };

            let raw = &buf[..n];
            let data = String::from_utf8_lossy(raw).to_string();

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
                credentials_captured = true;
                break; // Move to shell or disconnect.
            } else if !data.trim().is_empty() {
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

            let denial = b"Permission denied (publickey,password).\r\n";
            if stream.write_all(denial).await.is_err() {
                break;
            }
        }

        Ok::<(bool,), anyhow::Error>((credentials_captured,))
    })
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after {:?}", CONNECTION_TIMEOUT))??;

    // ---- Step 4: Optional fake shell session ----
    if shell_enabled {
        let _ = run_fake_shell(
            &mut stream,
            peer_addr,
            dest_port,
            listener_name,
            protocol,
            &events_tx,
        )
        .await;
    }

    Ok(())
}

/// Run a fake shell session that captures post-auth commands.
async fn run_fake_shell(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    listener_name: &str,
    protocol: &str,
    events_tx: &mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    tokio::time::timeout(SHELL_TIMEOUT, async {
        // "Accept" the login.
        stream
            .write_all(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n")
            .await?;
        stream
            .write_all(b" * Documentation:  https://help.ubuntu.com\r\n")
            .await?;
        stream
            .write_all(b" * Management:     https://landscape.canonical.com\r\n")
            .await?;
        stream
            .write_all(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")
            .await?;
        stream
            .write_all(b"Last login: Mon Feb 16 14:22:31 2026 from 10.0.0.1\r\n")
            .await?;
        stream.write_all(SHELL_PROMPT.as_bytes()).await?;
        stream.flush().await?;

        loop {
            let cmd_line = read_line(stream).await?;
            let cmd = cmd_line.trim().to_string();

            if cmd.is_empty() {
                stream.write_all(SHELL_PROMPT.as_bytes()).await?;
                stream.flush().await?;
                continue;
            }

            // Emit CommandCapture event.
            let mut event = WatchEvent::new(
                listener_name,
                protocol,
                peer_addr,
                dest_port,
                WatchEventType::CommandCapture,
                Severity::Critical,
            );
            event.captured_data = Some(cmd.clone());
            event
                .details
                .insert("command".to_string(), cmd.clone());
            let _ = events_tx.send(event);

            let cmd_lower = cmd.to_lowercase();
            let parts: Vec<&str> = cmd_lower.split_whitespace().collect();
            let base_cmd = parts.first().copied().unwrap_or("");

            if base_cmd == "exit" || base_cmd == "logout" || base_cmd == "quit" {
                stream.write_all(b"logout\r\n").await?;
                stream.flush().await?;
                break;
            }

            let response = fake_command_output(base_cmd, &cmd);
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(SHELL_PROMPT.as_bytes()).await?;
            stream.flush().await?;
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Shell session timed out"))?
}

/// Generate fake output for common commands.
fn fake_command_output(base_cmd: &str, _full_cmd: &str) -> String {
    match base_cmd {
        "whoami" => "root\r\n".to_string(),
        "id" => "uid=0(root) gid=0(root) groups=0(root)\r\n".to_string(),
        "uname" => "Linux ubuntu-server 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux\r\n"
            .to_string(),
        "hostname" => "ubuntu-server\r\n".to_string(),
        "pwd" => "/root\r\n".to_string(),
        "ls" => "Desktop  Documents  Downloads  snap\r\n".to_string(),
        "w" | "who" => "root     pts/0        2026-02-16 14:22 (10.0.0.1)\r\n".to_string(),
        "uptime" => {
            " 14:25:01 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
                .to_string()
        }
        "ifconfig" | "ip" => concat!(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n",
            "        inet 10.0.0.50  netmask 255.255.255.0  broadcast 10.0.0.255\r\n",
            "        ether 02:42:0a:00:00:32  txqueuelen 0  (Ethernet)\r\n",
            "\r\n"
        )
        .to_string(),
        "cat" => {
            if _full_cmd.contains("/etc/passwd") {
                concat!(
                    "root:x:0:0:root:/root:/bin/bash\r\n",
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n",
                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n",
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n",
                    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n",
                    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n"
                )
                .to_string()
            } else if _full_cmd.contains("/etc/shadow") {
                "cat: /etc/shadow: Permission denied\r\n".to_string()
            } else {
                "cat: No such file or directory\r\n".to_string()
            }
        }
        "ps" => concat!(
            "  PID TTY          TIME CMD\r\n",
            "    1 ?        00:00:03 systemd\r\n",
            "  412 ?        00:00:00 sshd\r\n",
            " 1024 pts/0    00:00:00 bash\r\n",
            " 1031 pts/0    00:00:00 ps\r\n"
        )
        .to_string(),
        "netstat" | "ss" => concat!(
            "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\r\n",
            "tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*\r\n",
            "tcp    LISTEN  0       128     0.0.0.0:80           0.0.0.0:*\r\n"
        )
        .to_string(),
        "curl" | "wget" => format!(
            "bash: {}: command not found\r\n",
            base_cmd
        ),
        _ => format!(
            "bash: {}: command not found\r\n",
            base_cmd
        ),
    }
}

/// Read a single `\n`-terminated line from the stream, up to `MAX_LINE_LENGTH`
/// bytes.
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
fn try_extract_credentials(data: &str) -> Option<(String, String)> {
    // Pattern 1: colon-separated "user:pass" somewhere in the payload.
    if let Some(idx) = data.find(':') {
        let user_part = &data[..idx];
        let pass_part = &data[idx + 1..];

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
    // Skip known SSH protocol keywords that appear as segments.
    const SSH_KEYWORDS: &[&str] = &[
        "ssh-userauth", "ssh-connection", "keyboard-interactive",
        "publickey", "password", "none", "ssh-rsa", "ssh-ed25519",
    ];
    let segments: Vec<&str> = data.split('\x00').collect();
    if segments.len() >= 2 {
        for pair in segments.windows(2) {
            let u = pair[0].trim();
            let p = pair[1].trim();
            if !u.is_empty()
                && !p.is_empty()
                && u.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                && p.len() <= 256
                && !SSH_KEYWORDS.contains(&u.to_lowercase().as_str())
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
        let hp = SshHoneypot::new(None, false);
        assert_eq!(hp.banner, DEFAULT_BANNER);
    }

    #[test]
    fn test_custom_banner() {
        let hp = SshHoneypot::new(Some("SSH-2.0-CustomSSH_1.0"), false);
        assert_eq!(hp.banner, "SSH-2.0-CustomSSH_1.0");
    }

    #[test]
    fn test_trait_methods() {
        let hp = SshHoneypot::new(None, false);
        assert_eq!(hp.name(), "ssh-honeypot");
        assert_eq!(hp.protocol(), "tcp");
        assert_eq!(hp.default_port(), 22);
    }

    #[test]
    fn test_shell_enabled() {
        let hp = SshHoneypot::new(None, true);
        assert!(hp.shell_enabled);
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

    #[test]
    fn test_fake_command_output() {
        assert_eq!(fake_command_output("whoami", "whoami"), "root\r\n");
        assert!(fake_command_output("id", "id").contains("uid=0"));
        assert!(fake_command_output("nonexistent", "nonexistent").contains("command not found"));
    }
}
