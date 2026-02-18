use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use std::time::Duration;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_LENGTH: usize = 4096;

/// TLS Alert: handshake_failure (level=fatal, desc=handshake_failure).
const TLS_ALERT_HANDSHAKE_FAILURE: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

/// Information extracted from a TLS ClientHello message.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub record_version: u16,
    pub handshake_version: u16,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

pub struct TlsHoneypot;

impl TlsHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for TlsHoneypot {
    fn name(&self) -> &str {
        "tls-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        8443
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("TLS honeypot listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("TLS connection from {}", peer_addr);

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
                                        "TLS honeypot connection from {} ended: {}",
                                        peer_addr, e
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept TLS connection: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TLS honeypot shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single TLS honeypot connection inside the per-connection timeout.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        let mut buf = vec![0u8; MAX_REQUEST_LENGTH];
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            return Ok::<(), anyhow::Error>(());
        }

        let raw = &buf[..n];

        let mut event = WatchEvent::new(
            "tls-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ConnectionAttempt,
            Severity::Medium,
        );

        event
            .details
            .insert("bytes_received".to_string(), n.to_string());

        if let Some(info) = parse_client_hello(raw) {
            event.details.insert(
                "tls_record_version".to_string(),
                format!("0x{:04x}", info.record_version),
            );
            event.details.insert(
                "tls_handshake_version".to_string(),
                format!("0x{:04x}", info.handshake_version),
            );
            event.details.insert(
                "cipher_count".to_string(),
                info.cipher_suites.len().to_string(),
            );

            if let Some(ref sni) = info.sni {
                event.details.insert("sni".to_string(), sni.clone());
                event.captured_data = Some(format!("SNI: {}", sni));
            }

            let ja3 = build_ja3_string(&info);
            event.details.insert("ja3_string".to_string(), ja3);
        } else {
            event
                .details
                .insert("note".to_string(), "Non-TLS or truncated data".to_string());
        }

        let _ = events_tx.send(event);

        // Send TLS Alert handshake_failure and close.
        let _ = stream.write_all(TLS_ALERT_HANDSHAKE_FAILURE).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;

        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after {:?}", CONNECTION_TIMEOUT))??;

    Ok(())
}

/// Parse a TLS ClientHello message from raw bytes.
///
/// Expected layout:
///   - Record header: type(1) + version(2) + length(2)
///   - Handshake header: type(1) + length(3)
///   - ClientHello body: version(2) + random(32) + session_id(var) + cipher_suites(var) + ...
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    // Minimum: 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) = 43
    if data.len() < 43 {
        return None;
    }

    // Record header: content type must be 0x16 (Handshake).
    if data[0] != 0x16 {
        return None;
    }

    let record_version = u16::from_be_bytes([data[1], data[2]]);
    // record_length at [3..5], but we don't strictly need it for parsing.

    // Handshake header starts at offset 5.
    let handshake_type = data[5];
    if handshake_type != 0x01 {
        // 0x01 = ClientHello
        return None;
    }

    // Handshake length (3 bytes).
    let _hs_length = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | (data[8] as usize);

    // ClientHello body starts at offset 9.
    let mut pos = 9;

    // Client version (2 bytes).
    if pos + 2 > data.len() {
        return None;
    }
    let handshake_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes).
    if pos + 32 > data.len() {
        return None;
    }
    pos += 32;

    // Session ID (length-prefixed, 1 byte length).
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;
    if pos + session_id_len > data.len() {
        return None;
    }
    pos += session_id_len;

    // Cipher suites (2-byte length prefix, then N * 2 bytes).
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > data.len() {
        return None;
    }

    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    let cipher_end = pos + cipher_suites_len;
    while pos + 2 <= cipher_end {
        cipher_suites.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    pos = cipher_end;

    // Compression methods (1-byte length prefix).
    if pos >= data.len() {
        return Some(ClientHelloInfo {
            record_version,
            handshake_version,
            cipher_suites,
            sni: None,
            extensions: Vec::new(),
            elliptic_curves: Vec::new(),
            ec_point_formats: Vec::new(),
        });
    }
    let comp_len = data[pos] as usize;
    pos += 1;
    if pos + comp_len > data.len() {
        return Some(ClientHelloInfo {
            record_version,
            handshake_version,
            cipher_suites,
            sni: None,
            extensions: Vec::new(),
            elliptic_curves: Vec::new(),
            ec_point_formats: Vec::new(),
        });
    }
    pos += comp_len;

    // Extensions (2-byte total length prefix).
    let mut sni = None;
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    if pos + 2 <= data.len() {
        let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = std::cmp::min(pos + ext_total_len, data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            extensions.push(ext_type);

            if pos + ext_len > ext_end {
                break;
            }

            let ext_data = &data[pos..pos + ext_len];

            match ext_type {
                // SNI extension (0x0000).
                0x0000 => {
                    sni = parse_sni(ext_data);
                }
                // Supported groups / elliptic curves (0x000a).
                0x000a => {
                    if ext_data.len() >= 2 {
                        let list_len =
                            u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let mut i = 2;
                        while i + 2 <= std::cmp::min(2 + list_len, ext_data.len()) {
                            elliptic_curves.push(u16::from_be_bytes([
                                ext_data[i],
                                ext_data[i + 1],
                            ]));
                            i += 2;
                        }
                    }
                }
                // EC point formats (0x000b).
                0x000b => {
                    if !ext_data.is_empty() {
                        let fmt_len = ext_data[0] as usize;
                        let end = std::cmp::min(1 + fmt_len, ext_data.len());
                        for &b in &ext_data[1..end] {
                            ec_point_formats.push(b);
                        }
                    }
                }
                _ => {}
            }

            pos += ext_len;
        }
    }

    Some(ClientHelloInfo {
        record_version,
        handshake_version,
        cipher_suites,
        sni,
        extensions,
        elliptic_curves,
        ec_point_formats,
    })
}

/// Extract the SNI hostname from an SNI extension payload.
fn parse_sni(data: &[u8]) -> Option<String> {
    // SNI extension: list_length(2) + type(1) + name_length(2) + name
    if data.len() < 5 {
        return None;
    }

    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];
    if name_type != 0x00 {
        // 0x00 = host_name
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }

    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

/// Build a JA3-style fingerprint string (without MD5 hashing since md-5 crate
/// is not available).
///
/// Format: `"version,ciphers,extensions,curves,formats"`
/// where each list is comma-separated decimal values joined by `-`.
pub fn build_ja3_string(info: &ClientHelloInfo) -> String {
    let version = info.handshake_version.to_string();

    let ciphers: String = info
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions: String = info
        .extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let curves: String = info
        .elliptic_curves
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let formats: String = info
        .ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");

    format!("{},{},{},{},{}", version, ciphers, extensions, curves, formats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trait_methods() {
        let hp = TlsHoneypot::new();
        assert_eq!(hp.name(), "tls-honeypot");
        assert_eq!(hp.protocol(), "tcp");
        assert_eq!(hp.default_port(), 8443);
    }

    /// Build a minimal valid ClientHello for testing.
    fn build_test_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut hello_body = Vec::new();

        // Client version: TLS 1.2 (0x0303)
        hello_body.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes of zeros)
        hello_body.extend_from_slice(&[0u8; 32]);

        // Session ID length: 0
        hello_body.push(0x00);

        // Cipher suites: 2 suites (4 bytes total, prefixed by length)
        hello_body.extend_from_slice(&[0x00, 0x04]); // length = 4
        hello_body.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        hello_body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression methods: 1 method (null)
        hello_body.push(0x01);
        hello_body.push(0x00);

        // Extensions
        let mut extensions = Vec::new();

        // SNI extension
        if let Some(hostname) = sni {
            let name_bytes = hostname.as_bytes();
            let name_len = name_bytes.len() as u16;
            let list_len = name_len + 3; // type(1) + length(2)
            let ext_len = list_len + 2; // list_length(2)

            extensions.extend_from_slice(&[0x00, 0x00]); // extension type: SNI
            extensions.extend_from_slice(&ext_len.to_be_bytes()); // extension length
            extensions.extend_from_slice(&list_len.to_be_bytes()); // list length
            extensions.push(0x00); // name type: host_name
            extensions.extend_from_slice(&name_len.to_be_bytes()); // name length
            extensions.extend_from_slice(name_bytes);
        }

        // Supported groups extension (0x000a): x25519(29), secp256r1(23)
        extensions.extend_from_slice(&[0x00, 0x0a]); // extension type
        extensions.extend_from_slice(&[0x00, 0x06]); // extension length = 6
        extensions.extend_from_slice(&[0x00, 0x04]); // list length = 4
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
        extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1

        // EC point formats extension (0x000b)
        extensions.extend_from_slice(&[0x00, 0x0b]); // extension type
        extensions.extend_from_slice(&[0x00, 0x02]); // extension length = 2
        extensions.push(0x01); // formats length = 1
        extensions.push(0x00); // uncompressed

        // Extensions total length
        let ext_total_len = extensions.len() as u16;
        hello_body.extend_from_slice(&ext_total_len.to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // Build handshake header
        let hs_len = hello_body.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&hello_body);

        // Build record header
        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.push(((record_len >> 8) & 0xFF) as u8);
        record.push((record_len & 0xFF) as u8);
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_parse_valid_client_hello() {
        let data = build_test_client_hello(Some("example.com"));
        let info = parse_client_hello(&data).expect("should parse");
        assert_eq!(info.record_version, 0x0301);
        assert_eq!(info.handshake_version, 0x0303);
        assert_eq!(info.cipher_suites.len(), 2);
        assert_eq!(info.cipher_suites[0], 0xc02b);
        assert_eq!(info.cipher_suites[1], 0xc02f);
        assert_eq!(info.sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_client_hello_no_sni() {
        let data = build_test_client_hello(None);
        let info = parse_client_hello(&data).expect("should parse");
        assert_eq!(info.sni, None);
        assert_eq!(info.cipher_suites.len(), 2);
    }

    #[test]
    fn test_parse_truncated_data() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        assert!(parse_client_hello(&data).is_none());
    }

    #[test]
    fn test_parse_non_handshake() {
        // Application data (0x17) instead of handshake (0x16).
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(parse_client_hello(&data).is_none());
    }

    #[test]
    fn test_parse_non_client_hello() {
        // Handshake type 0x02 = ServerHello (not ClientHello).
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x30];
        data.push(0x02); // ServerHello
        data.extend_from_slice(&[0x00, 0x00, 0x2c]);
        data.extend_from_slice(&[0x03, 0x03]); // version
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0x00); // session ID len
        data.extend_from_slice(&[0x00, 0x00]); // cipher suite
        data.push(0x00); // compression
        assert!(parse_client_hello(&data).is_none());
    }

    #[test]
    fn test_sni_extraction() {
        let data = build_test_client_hello(Some("secure.test.org"));
        let info = parse_client_hello(&data).expect("should parse");
        assert_eq!(info.sni, Some("secure.test.org".to_string()));
    }

    #[test]
    fn test_elliptic_curves_extraction() {
        let data = build_test_client_hello(Some("test.com"));
        let info = parse_client_hello(&data).expect("should parse");
        assert_eq!(info.elliptic_curves, vec![29, 23]); // x25519, secp256r1
    }

    #[test]
    fn test_ec_point_formats_extraction() {
        let data = build_test_client_hello(Some("test.com"));
        let info = parse_client_hello(&data).expect("should parse");
        assert_eq!(info.ec_point_formats, vec![0]); // uncompressed
    }

    #[test]
    fn test_ja3_string_format() {
        let data = build_test_client_hello(Some("example.com"));
        let info = parse_client_hello(&data).expect("should parse");
        let ja3 = build_ja3_string(&info);

        // Expected: "771,49195-49199,0-10-11,29-23,0"
        // version = 771 (0x0303)
        // ciphers = 49195 (0xc02b) - 49199 (0xc02f)
        // extensions = 0 (SNI) - 10 (supported_groups) - 11 (ec_point_formats)
        // curves = 29 (x25519) - 23 (secp256r1)
        // formats = 0 (uncompressed)
        assert_eq!(ja3, "771,49195-49199,0-10-11,29-23,0");
    }

    #[test]
    fn test_ja3_string_empty_fields() {
        let info = ClientHelloInfo {
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![],
            sni: None,
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
        };
        let ja3 = build_ja3_string(&info);
        assert_eq!(ja3, "771,,,,");
    }

    #[test]
    fn test_alert_length() {
        assert_eq!(TLS_ALERT_HANDSHAKE_FAILURE.len(), 7);
        // ContentType: Alert (0x15)
        assert_eq!(TLS_ALERT_HANDSHAKE_FAILURE[0], 0x15);
        // Level: fatal (0x02)
        assert_eq!(TLS_ALERT_HANDSHAKE_FAILURE[5], 0x02);
        // Description: handshake_failure (0x28 = 40)
        assert_eq!(TLS_ALERT_HANDSHAKE_FAILURE[6], 0x28);
    }
}
