/// Integration tests for all 11 Sentinel Watch honeypot listeners.
///
/// Each test: bind listener on a random port → connect → assert events → shutdown.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

use sentinel::watch::{WatchEvent, WatchListener};

use sentinel::watch::dns::DnsHoneypot;
use sentinel::watch::ftp::FtpHoneypot;
use sentinel::watch::http::HttpHoneypot;
use sentinel::watch::mysql::MysqlHoneypot;
use sentinel::watch::postgres::PostgresHoneypot;
use sentinel::watch::rdp::RdpHoneypot;
use sentinel::watch::smb::SmbHoneypot;
use sentinel::watch::smtp::SmtpHoneypot;
use sentinel::watch::ssh::SshHoneypot;
use sentinel::watch::telnet::TelnetHoneypot;
use sentinel::watch::tls::TlsHoneypot;

/// Get a random available port by binding to port 0 and reading the assigned port.
async fn get_random_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to random port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Get a random available UDP port.
async fn get_random_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to random UDP port");
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    port
}

/// Setup a listener on a random port, returning the port, event receiver, and shutdown sender.
async fn setup_listener(
    listener: Box<dyn WatchListener>,
) -> (u16, mpsc::UnboundedReceiver<WatchEvent>, watch::Sender<bool>) {
    let port = if listener.protocol() == "udp" {
        get_random_udp_port().await
    } else {
        get_random_port().await
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        if let Err(e) = listener.listen(addr, events_tx, shutdown_rx).await {
            eprintln!("Listener error: {}", e);
        }
    });

    // Give the listener a moment to start.
    tokio::time::sleep(Duration::from_millis(100)).await;

    (port, events_rx, shutdown_tx)
}

/// Collect all events within a timeout period.
async fn collect_events(
    rx: &mut mpsc::UnboundedReceiver<WatchEvent>,
    timeout: Duration,
) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                events.push(event);
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    events
}

fn has_event_type(events: &[WatchEvent], event_type: &str) -> bool {
    events.iter().any(|e| e.event_type.to_string() == event_type)
}

// ── 1. HTTP Honeypot ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_http_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(HttpHoneypot::new())).await;

    // GET → ConnectionAttempt
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await;
    drop(stream);

    tokio::time::sleep(Duration::from_millis(100)).await;

    // POST with creds → CredentialCapture
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");
    let body = "username=admin&password=secret123";
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let _ = stream.read(&mut buf).await;
    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "ConnectionAttempt"), "Expected ConnectionAttempt event");
    assert!(has_event_type(&events, "CredentialCapture"), "Expected CredentialCapture event");

    let cred_event = events.iter().find(|e| e.event_type.to_string() == "CredentialCapture").unwrap();
    assert!(cred_event.captured_data.as_ref().unwrap().contains("admin"));
    assert!(cred_event.captured_data.as_ref().unwrap().contains("secret123"));
}

// ── 2. FTP Honeypot ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ftp_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(FtpHoneypot::new(None))).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    let mut reader_buf = vec![0u8; 4096];
    // Read banner.
    let _ = stream.read(&mut reader_buf).await;

    // Send USER/PASS.
    stream.write_all(b"USER testuser\r\n").await.unwrap();
    let _ = stream.read(&mut reader_buf).await;
    stream.write_all(b"PASS testpass\r\n").await.unwrap();
    let _ = stream.read(&mut reader_buf).await;

    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "CredentialCapture"), "Expected CredentialCapture event");

    let cred_event = events.iter().find(|e| e.event_type.to_string() == "CredentialCapture").unwrap();
    assert!(cred_event.captured_data.as_ref().unwrap().contains("testuser"));
    assert!(cred_event.captured_data.as_ref().unwrap().contains("testpass"));
}

// ── 3. Telnet Honeypot ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_telnet_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(TelnetHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    let mut buf = vec![0u8; 1024];
    // Read "login: " prompt.
    let _ = stream.read(&mut buf).await;

    // Send username.
    stream.write_all(b"admin\r\n").await.unwrap();
    // Read "Password: " prompt.
    let _ = stream.read(&mut buf).await;

    // Send password.
    stream.write_all(b"hunter2\r\n").await.unwrap();
    // Read rejection.
    let _ = stream.read(&mut buf).await;

    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "CredentialCapture"), "Expected CredentialCapture event");

    let cred_event = events.iter().find(|e| e.event_type.to_string() == "CredentialCapture").unwrap();
    assert!(cred_event.captured_data.as_ref().unwrap().contains("admin"));
    assert!(cred_event.captured_data.as_ref().unwrap().contains("hunter2"));
}

// ── 4. SSH Honeypot ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ssh_honeypot() {
    let (port, mut rx, shutdown_tx) =
        setup_listener(Box::new(SshHoneypot::new(None, false))).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    let mut buf = vec![0u8; 4096];
    // Read server banner.
    let n = stream.read(&mut buf).await.unwrap();
    let server_banner = String::from_utf8_lossy(&buf[..n]);
    assert!(server_banner.contains("SSH-2.0-"), "Expected SSH banner");

    // Send client banner.
    stream
        .write_all(b"SSH-2.0-TestClient_1.0\r\n")
        .await
        .unwrap();

    // Give it a moment to process.
    tokio::time::sleep(Duration::from_millis(200)).await;

    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "ConnectionAttempt"), "Expected ConnectionAttempt event");
    assert!(has_event_type(&events, "BannerGrab"), "Expected BannerGrab event");

    let banner_event = events.iter().find(|e| e.event_type.to_string() == "BannerGrab").unwrap();
    assert!(banner_event
        .captured_data
        .as_ref()
        .unwrap()
        .contains("TestClient"));
}

// ── 5. SMTP Honeypot ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_smtp_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(SmtpHoneypot::new(None))).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read banner.
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("220"), "Expected SMTP 220 banner");

    // Send EHLO.
    writer.write_all(b"EHLO test.local\r\n").await.unwrap();
    line.clear();
    // Read multi-line response.
    loop {
        reader.read_line(&mut line).await.unwrap();
        if line.contains("250 ") {
            break;
        }
    }

    // Send MAIL FROM.
    writer
        .write_all(b"MAIL FROM:<attacker@evil.com>\r\n")
        .await
        .unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();

    // QUIT.
    writer.write_all(b"QUIT\r\n").await.unwrap();

    drop(writer);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "BannerGrab"), "Expected BannerGrab event (from EHLO)");
    assert!(has_event_type(&events, "EmailAttempt"), "Expected EmailAttempt event");
}

// ── 6. DNS Honeypot (UDP) ───────────────────────────────────────────────────

#[tokio::test]
async fn test_dns_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(DnsHoneypot::new())).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    // Build a minimal DNS A query for example.com.
    let query = build_dns_query("example.com", 1); // type A = 1
    client
        .send_to(&query, format!("127.0.0.1:{}", port))
        .await
        .expect("send");

    // Wait for response.
    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "DnsQuery"), "Expected DnsQuery event");

    let dns_event = events.iter().find(|e| e.event_type.to_string() == "DnsQuery").unwrap();
    assert!(dns_event.captured_data.as_ref().unwrap().contains("example.com"));
}

/// Build a minimal DNS query packet.
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Transaction ID.
    pkt.extend_from_slice(&[0xAB, 0xCD]);
    // Flags: standard query, recursion desired.
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1.
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0.
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Question section: encode domain name.
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // Root label.

    // QTYPE (A = 1, etc.)
    pkt.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS: IN (1).
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

// ── 7. MySQL Honeypot ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_mysql_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(MysqlHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    let mut buf = vec![0u8; 4096];
    // Read server greeting.
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0, "Expected MySQL greeting");

    // Build a minimal MySQL handshake response with username "testmysqluser".
    let auth_response = build_mysql_auth_response("testmysqluser");
    stream.write_all(&auth_response).await.unwrap();

    // Read error response.
    let _ = stream.read(&mut buf).await;
    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "CredentialCapture"), "Expected CredentialCapture event");

    let cred_event = events
        .iter()
        .find(|e| e.event_type.to_string() == "CredentialCapture")
        .unwrap();
    assert!(cred_event
        .captured_data
        .as_ref()
        .unwrap()
        .contains("testmysqluser"));
}

/// Build a minimal MySQL client handshake response packet.
fn build_mysql_auth_response(username: &str) -> Vec<u8> {
    let mut payload = Vec::new();

    // Capability flags (4 bytes): CLIENT_PROTOCOL_41 etc.
    payload.extend_from_slice(&[0x85, 0xa6, 0xff, 0x01]);
    // Max packet size (4 bytes).
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // Character set (1 byte): utf8.
    payload.push(33);
    // Reserved (23 bytes of zeros).
    payload.extend_from_slice(&[0u8; 23]);
    // Username (null-terminated).
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    // Auth response length + data.
    payload.push(0x00); // Empty auth response.

    // Wrap in MySQL packet: 3-byte length + 1-byte sequence number (1).
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(1); // Sequence number 1 (response to greeting).
    packet.extend_from_slice(&payload);

    packet
}

// ── 8. PostgreSQL Honeypot ──────────────────────────────────────────────────

#[tokio::test]
async fn test_postgres_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(PostgresHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    // Build PostgreSQL startup message.
    let startup = build_postgres_startup("testpguser", "testdb");
    stream.write_all(&startup).await.unwrap();

    // Read auth challenge + error.
    let mut buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "CredentialCapture"), "Expected CredentialCapture event");

    let cred_event = events
        .iter()
        .find(|e| e.event_type.to_string() == "CredentialCapture")
        .unwrap();
    assert!(cred_event
        .captured_data
        .as_ref()
        .unwrap()
        .contains("testpguser"));
}

/// Build a PostgreSQL startup message with user and database.
fn build_postgres_startup(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();

    // Protocol version 3.0.
    body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

    // Key-value pairs (null-terminated).
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0x00);

    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0x00);

    // Terminator.
    body.push(0x00);

    // Length includes itself (4 bytes).
    let total_len = (4 + body.len()) as u32;
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&body);

    msg
}

// ── 9. RDP Honeypot ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_rdp_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(RdpHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    // Build a minimal X.224 Connection Request with cookie.
    let cookie = b"Cookie: mstshash=testrdpuser\r\n";
    let mut pdu = Vec::new();
    // TPKT header.
    let total_len = (11 + cookie.len()) as u16;
    pdu.push(0x03); // Version 3
    pdu.push(0x00); // Reserved
    pdu.extend_from_slice(&total_len.to_be_bytes());
    // X.224 CR PDU.
    pdu.push((6 + cookie.len()) as u8); // Length indicator
    pdu.push(0xe0); // CR (Connection Request)
    pdu.extend_from_slice(&[0x00, 0x00]); // DST-REF
    pdu.extend_from_slice(&[0x00, 0x00]); // SRC-REF
    pdu.push(0x00); // Class 0
    pdu.extend_from_slice(cookie);

    stream.write_all(&pdu).await.unwrap();

    // Read response.
    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await;
    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "ConnectionAttempt"), "Expected ConnectionAttempt event");

    let rdp_event = events.iter().find(|e| {
        e.event_type.to_string() == "ConnectionAttempt"
            && e.details.contains_key("cookie")
    }).expect("Expected ConnectionAttempt with cookie detail");
    assert_eq!(rdp_event.details.get("cookie").unwrap(), "testrdpuser");
}

// ── 10. SMB Honeypot ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_smb_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(SmbHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    // Build a minimal SMB1 Negotiate Request.
    let mut smb_payload = Vec::new();
    // SMB1 header.
    smb_payload.extend_from_slice(&[0xFF, 0x53, 0x4D, 0x42]); // \xFFSMB
    smb_payload.push(0x72); // Negotiate command
    smb_payload.extend_from_slice(&[0x00; 27]); // Rest of header (zeros)
    // Negotiate body: WordCount = 0, ByteCount = 16.
    smb_payload.push(0x00); // Word count
    smb_payload.extend_from_slice(&[0x0e, 0x00]); // Byte count = 14
    // Dialect: "\x02NT LM 0.12\0"
    smb_payload.push(0x02);
    smb_payload.extend_from_slice(b"NT LM 0.12\0");

    // NetBIOS header.
    let payload_len = smb_payload.len();
    let mut pkt = Vec::new();
    pkt.push(0x00); // Session message
    pkt.push(0x00);
    pkt.push(((payload_len >> 8) & 0xFF) as u8);
    pkt.push((payload_len & 0xFF) as u8);
    pkt.extend_from_slice(&smb_payload);

    stream.write_all(&pkt).await.unwrap();

    // Read response.
    let mut buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "NegotiateAttempt"), "Expected NegotiateAttempt event");

    let smb_event = events.iter().find(|e| e.event_type.to_string() == "NegotiateAttempt").unwrap();
    assert_eq!(smb_event.details.get("smb_version").unwrap(), "SMB1");
}

// ── 11. TLS Honeypot ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tls_honeypot() {
    let (port, mut rx, shutdown_tx) = setup_listener(Box::new(TlsHoneypot::new())).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("connect");

    // Build a valid ClientHello with SNI "test.sentinel.io".
    let client_hello = build_tls_client_hello("test.sentinel.io");
    stream.write_all(&client_hello).await.unwrap();

    // Read TLS Alert response.
    let mut buf = vec![0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    drop(stream);

    let events = collect_events(&mut rx, Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);

    assert!(has_event_type(&events, "ConnectionAttempt"), "Expected ConnectionAttempt event");

    let tls_event = events
        .iter()
        .find(|e| e.event_type.to_string() == "ConnectionAttempt")
        .unwrap();

    assert_eq!(
        tls_event.details.get("sni").unwrap(),
        "test.sentinel.io",
        "Expected SNI in details"
    );
    assert!(
        tls_event.details.contains_key("ja3_string"),
        "Expected ja3_string in details"
    );
    assert!(
        tls_event.details.contains_key("tls_handshake_version"),
        "Expected TLS version in details"
    );
}

/// Build a minimal TLS ClientHello with the given SNI hostname.
fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
    let mut hello_body = Vec::new();

    // Client version: TLS 1.2 (0x0303).
    hello_body.extend_from_slice(&[0x03, 0x03]);

    // Random (32 bytes).
    hello_body.extend_from_slice(&[0x42u8; 32]);

    // Session ID length: 0.
    hello_body.push(0x00);

    // Cipher suites (2 suites).
    hello_body.extend_from_slice(&[0x00, 0x04]); // length = 4
    hello_body.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    hello_body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    // Compression methods.
    hello_body.push(0x01);
    hello_body.push(0x00);

    // Extensions.
    let mut extensions = Vec::new();

    // SNI extension.
    let name_bytes = hostname.as_bytes();
    let name_len = name_bytes.len() as u16;
    let list_len = name_len + 3;
    let ext_len = list_len + 2;

    extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
    extensions.extend_from_slice(&ext_len.to_be_bytes());
    extensions.extend_from_slice(&list_len.to_be_bytes());
    extensions.push(0x00); // host_name type
    extensions.extend_from_slice(&name_len.to_be_bytes());
    extensions.extend_from_slice(name_bytes);

    // Supported groups.
    extensions.extend_from_slice(&[0x00, 0x0a]); // type
    extensions.extend_from_slice(&[0x00, 0x04]); // length
    extensions.extend_from_slice(&[0x00, 0x02]); // list length
    extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1

    // EC point formats.
    extensions.extend_from_slice(&[0x00, 0x0b]); // type
    extensions.extend_from_slice(&[0x00, 0x02]); // length
    extensions.push(0x01); // formats length
    extensions.push(0x00); // uncompressed

    let ext_total_len = extensions.len() as u16;
    hello_body.extend_from_slice(&ext_total_len.to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    // Handshake header.
    let hs_len = hello_body.len();
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.push(((hs_len >> 16) & 0xFF) as u8);
    handshake.push(((hs_len >> 8) & 0xFF) as u8);
    handshake.push((hs_len & 0xFF) as u8);
    handshake.extend_from_slice(&hello_body);

    // Record header.
    let record_len = handshake.len();
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.push(((record_len >> 8) & 0xFF) as u8);
    record.push((record_len & 0xFF) as u8);
    record.extend_from_slice(&handshake);

    record
}
