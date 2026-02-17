use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ── HTML ─────────────────────────────────────────────────────────────────────

const LOGIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel - Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #1a1a2e;
      color: #eee;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .login-card {
      background: #16213e;
      border: 1px solid #0f3460;
      border-radius: 8px;
      padding: 40px 36px;
      width: 380px;
      box-shadow: 0 8px 32px rgba(0,0,0,.45);
    }
    .login-card h1 {
      text-align: center;
      font-size: 22px;
      margin-bottom: 6px;
    }
    .login-card p.sub {
      text-align: center;
      font-size: 13px;
      color: #888;
      margin-bottom: 28px;
    }
    label { display: block; font-size: 13px; margin-bottom: 4px; color: #aaa; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 18px;
      border: 1px solid #0f3460;
      border-radius: 4px;
      background: #1a1a2e;
      color: #eee;
      font-size: 14px;
    }
    input:focus { outline: none; border-color: #e94560; }
    button {
      width: 100%;
      padding: 11px;
      background: #e94560;
      border: none;
      border-radius: 4px;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #c73a52; }
    .footer { text-align: center; margin-top: 20px; font-size: 11px; color: #555; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Admin Panel</h1>
    <p class="sub">Sign in to continue</p>
    <form method="POST" action="/">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="off" required>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">&copy; 2026 System Administration</div>
  </div>
</body>
</html>"#;

const LOGIN_FAILED_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel - Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #1a1a2e;
      color: #eee;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .login-card {
      background: #16213e;
      border: 1px solid #0f3460;
      border-radius: 8px;
      padding: 40px 36px;
      width: 380px;
      box-shadow: 0 8px 32px rgba(0,0,0,.45);
    }
    .login-card h1 {
      text-align: center;
      font-size: 22px;
      margin-bottom: 6px;
    }
    .login-card p.sub {
      text-align: center;
      font-size: 13px;
      color: #888;
      margin-bottom: 28px;
    }
    .error {
      background: rgba(233,69,96,.15);
      border: 1px solid #e94560;
      color: #e94560;
      padding: 10px;
      border-radius: 4px;
      text-align: center;
      font-size: 13px;
      margin-bottom: 18px;
    }
    label { display: block; font-size: 13px; margin-bottom: 4px; color: #aaa; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 18px;
      border: 1px solid #0f3460;
      border-radius: 4px;
      background: #1a1a2e;
      color: #eee;
      font-size: 14px;
    }
    input:focus { outline: none; border-color: #e94560; }
    button {
      width: 100%;
      padding: 11px;
      background: #e94560;
      border: none;
      border-radius: 4px;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #c73a52; }
    .footer { text-align: center; margin-top: 20px; font-size: 11px; color: #555; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Admin Panel</h1>
    <p class="sub">Sign in to continue</p>
    <div class="error">Invalid username or password.</div>
    <form method="POST" action="/">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="off" required>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">&copy; 2026 System Administration</div>
  </div>
</body>
</html>"#;

// ── HttpHoneypot ─────────────────────────────────────────────────────────────

/// Fake HTTP admin panel honeypot.
///
/// Serves a realistic-looking login page on GET and captures any credentials
/// submitted via POST.  No external HTTP framework is used; requests are
/// parsed from raw TCP streams.
pub struct HttpHoneypot;

impl HttpHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for HttpHoneypot {
    fn name(&self) -> &str {
        "http-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        8080
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("[http-honeypot] Listening on {}", bind_addr);

        loop {
            tokio::select! {
                // Accept a new connection.
                result = listener.accept() => {
                    let (stream, peer) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("[http-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let port = bind_addr.port();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, port, tx).await {
                            tracing::debug!("[http-honeypot] Connection handler error ({}): {}", peer, e);
                        }
                    });
                }

                // Shutdown signal.
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[http-honeypot] Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

// ── Connection handling ──────────────────────────────────────────────────────

/// Handle a single TCP connection: read the HTTP request, emit an event, and
/// send back an appropriate response.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    // Apply a 30-second timeout for the entire interaction.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        handle_connection_inner(&mut stream, peer, dest_port, events_tx),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timed out"))??;

    Ok(())
}

async fn handle_connection_inner(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    // Read up to 8 KiB — more than enough for a typical HTTP request with a
    // small form body.
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let raw = String::from_utf8_lossy(&buf[..n]);

    // Parse the request line (first line).
    let request_line = raw.lines().next().unwrap_or("");
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_uppercase();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/");

    // Extract User-Agent header if present.
    let user_agent = extract_header(&raw, "User-Agent");

    match method.as_str() {
        "GET" => {
            let mut event = WatchEvent::new(
                "http-honeypot",
                "tcp",
                peer,
                dest_port,
                WatchEventType::ConnectionAttempt,
                Severity::Info,
            );
            event.details.insert("method".into(), "GET".into());
            event.details.insert("path".into(), path.to_string());
            if let Some(ua) = &user_agent {
                event.details.insert("user_agent".into(), ua.clone());
            }
            let _ = events_tx.send(event);

            // Serve the login page.
            let response = build_response(200, "OK", "text/html", LOGIN_PAGE);
            stream.write_all(response.as_bytes()).await?;
        }

        "POST" => {
            // Parse the body: everything after the blank line separating
            // headers from body.
            let body = raw
                .find("\r\n\r\n")
                .map(|i| &raw[i + 4..])
                .or_else(|| raw.find("\n\n").map(|i| &raw[i + 2..]))
                .unwrap_or("");

            let params = parse_form_urlencoded(body);
            let username = params
                .iter()
                .find(|(k, _)| k == "username")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let password = params
                .iter()
                .find(|(k, _)| k == "password")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");

            let mut event = WatchEvent::new(
                "http-honeypot",
                "tcp",
                peer,
                dest_port,
                WatchEventType::CredentialCapture,
                Severity::High,
            );
            event.captured_data = Some(format!("username={}, password={}", username, password));
            event.details.insert("method".into(), "POST".into());
            event.details.insert("path".into(), path.to_string());
            event.details.insert("username".into(), username.to_string());
            event.details.insert("password".into(), password.to_string());
            if let Some(ua) = &user_agent {
                event.details.insert("user_agent".into(), ua.clone());
            }
            let _ = events_tx.send(event);

            // Respond with the login page showing an error message so the
            // attacker may try additional credentials.
            let response = build_response(200, "OK", "text/html", LOGIN_FAILED_PAGE);
            stream.write_all(response.as_bytes()).await?;
        }

        _ => {
            // Any other HTTP method (HEAD, PUT, DELETE, OPTIONS, ...) or
            // completely non-HTTP traffic: treat as a protocol probe.
            let mut event = WatchEvent::new(
                "http-honeypot",
                "tcp",
                peer,
                dest_port,
                WatchEventType::ProtocolProbe,
                Severity::Low,
            );
            event.captured_data = Some(request_line.to_string());
            event.details.insert("method".into(), method.clone());
            event.details.insert("path".into(), path.to_string());
            if let Some(ua) = &user_agent {
                event.details.insert("user_agent".into(), ua.clone());
            }
            let _ = events_tx.send(event);

            let body = "405 Method Not Allowed";
            let response = build_response(405, "Method Not Allowed", "text/plain", body);
            stream.write_all(response.as_bytes()).await?;
        }
    }

    stream.flush().await?;
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal HTTP/1.1 response with the given status, content type, and
/// body.
fn build_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: nginx/1.24.0\r\n\
         X-Powered-By: Express\r\n\
         \r\n\
         {}",
        status,
        reason,
        content_type,
        body.len(),
        body,
    )
}

/// Extract the value of an HTTP header by name (case-insensitive).
fn extract_header<'a>(raw: &'a str, name: &str) -> Option<String> {
    let prefix = format!("{}:", name);
    for line in raw.lines() {
        if line.to_lowercase().starts_with(&prefix.to_lowercase()) {
            return Some(line[prefix.len()..].trim().to_string());
        }
    }
    None
}

/// Parse a `application/x-www-form-urlencoded` body into key-value pairs.
/// Handles basic percent-decoding for `+` (space) and `%XX` sequences.
fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    body.trim()
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((url_decode(key), url_decode(value)))
        })
        .collect()
}

/// Minimal URL/percent-decode: handles `+` as space and `%XX` hex sequences.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();

    while let Some(b) = chars.next() {
        match b {
            b'+' => result.push(' '),
            b'%' => {
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(h), Some(l)) = (hi, lo) {
                    let hex = [h, l];
                    if let Ok(s) = std::str::from_utf8(&hex) {
                        if let Ok(byte) = u8::from_str_radix(s, 16) {
                            result.push(byte as char);
                            continue;
                        }
                    }
                    // Malformed sequence — emit literally.
                    result.push('%');
                    result.push(h as char);
                    result.push(l as char);
                }
            }
            _ => result.push(b as char),
        }
    }

    result
}
