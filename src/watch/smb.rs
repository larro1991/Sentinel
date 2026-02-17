use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fake SMB honeypot that captures negotiate requests from scanners and
/// malware probing for SMB services.
pub struct SmbHoneypot;

impl SmbHoneypot {
    pub fn new() -> Self {
        Self
    }
}

// ─── SMB magic bytes ─────────────────────────────────────────────────────────
//
// After the 4-byte NetBIOS Session Service header the SMB protocol magic is:
//   SMB1:  \xFF S M B   (0xFF 0x53 0x4D 0x42)
//   SMB2+: \xFE S M B   (0xFE 0x53 0x4D 0x42)
const SMB1_MAGIC: [u8; 4] = [0xFF, 0x53, 0x4D, 0x42];
const SMB2_MAGIC: [u8; 4] = [0xFE, 0x53, 0x4D, 0x42];

// ─── Minimal SMB1 Negotiate Response ─────────────────────────────────────────
//
// This is a deliberately minimal (but structurally valid) SMB1 Negotiate
// Response that selects dialect index 0 and advertises signing as required.
// It is enough to keep basic scanners happy while logging the event.
//
// Layout:
//   NetBIOS header (4 bytes)
//   SMB1 header    (32 bytes)
//   Word count     (1 byte)  — 0x11 = 17 words for NT LM 0.12
//   Words          (34 bytes)
//   Byte count     (2 bytes) — 0x00 0x00
// Total: 73 bytes
const SMB1_NEGOTIATE_RESPONSE: [u8; 73] = [
    // --- NetBIOS Session Service header ---
    0x00,                            // Type: Session Message
    0x00, 0x00, 0x45,                // Length: 69 bytes payload
    // --- SMB Header (32 bytes) ---
    0xFF, 0x53, 0x4D, 0x42,         // Protocol: \xFFSMB
    0x72,                            // Command: Negotiate (0x72)
    0x00, 0x00, 0x00, 0x00,         // Status: SUCCESS
    0x98,                            // Flags: Reply + Canonicalized
    0x53, 0xC8,                      // Flags2: Unicode | NT Status | Extended Security
    0x00, 0x00,                      // PID High
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,         // Signature
    0x00, 0x00,                      // Reserved
    0x00, 0x00,                      // Tree ID
    0xFF, 0xFE,                      // Process ID
    0x00, 0x00,                      // User ID
    0x00, 0x00,                      // Multiplex ID
    // --- Negotiate Response body ---
    0x11,                            // Word Count: 17
    0x00, 0x00,                      // Dialect Index: 0
    0x0F,                            // Security Mode: User | Encrypt | Signing Enabled | Signing Required
    0x01, 0x00,                      // Max MPX Count: 1
    0x01, 0x00,                      // Max Number VCs: 1
    0x00, 0x04, 0x00, 0x00,         // Max Buffer Size: 1024
    0x00, 0x00, 0x01, 0x00,         // Max Raw Size: 65536
    0x00, 0x00, 0x00, 0x00,         // Session Key: 0
    0xFD, 0xF3, 0x00, 0x00,         // Capabilities: Unicode | NT SMBs | RPC Remote APIs | NT Status | Level II Oplocks | Lock&Read | NT Find | Extended Security
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,         // System Time: 0
    0x00, 0x00,                      // Server Time Zone: 0
    0x00,                            // Encryption Key Length: 0
    0x00, 0x00,                      // Byte Count: 0
];

/// Hex-encode a byte slice for human-readable display.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// Attempt to extract dialect strings from an SMB1 Negotiate Request body.
///
/// Dialect entries start after the SMB header (32 bytes) + WordCount (1 byte)
/// + ByteCount (2 bytes), i.e. at offset 39 from the start of the SMB payload
/// (offset 43 from the TCP payload including the 4-byte NetBIOS header).
///
/// Each dialect entry is: 0x02 <null-terminated ASCII string>.
fn extract_smb1_dialects(payload: &[u8]) -> Vec<String> {
    let mut dialects = Vec::new();

    // Minimum valid offset: 4 (NetBIOS) + 32 (SMB header) + 1 (WordCount) + 2 (ByteCount) = 39
    if payload.len() < 39 {
        return dialects;
    }

    let word_count = payload[36] as usize;
    // Skip past the words: parameter words start at offset 37, each word is 2 bytes.
    let byte_count_offset = 37 + word_count * 2;
    if payload.len() < byte_count_offset + 2 {
        return dialects;
    }

    let byte_count = u16::from_le_bytes([
        payload[byte_count_offset],
        payload[byte_count_offset + 1],
    ]) as usize;

    let data_start = byte_count_offset + 2;
    let data_end = std::cmp::min(data_start + byte_count, payload.len());
    if data_start >= payload.len() {
        return dialects;
    }

    let data = &payload[data_start..data_end];
    let mut i = 0;
    while i < data.len() {
        // Each dialect begins with 0x02
        if data[i] != 0x02 {
            i += 1;
            continue;
        }
        i += 1;
        // Find the null terminator.
        if let Some(end) = data[i..].iter().position(|&b| b == 0x00) {
            if let Ok(s) = std::str::from_utf8(&data[i..i + end]) {
                dialects.push(s.to_string());
            }
            i += end + 1;
        } else {
            break;
        }
    }

    dialects
}

/// Attempt to extract the Client GUID from an SMB2 Negotiate Request.
///
/// SMB2 Negotiate layout (after the 4-byte NetBIOS header):
///   Offset  0: Protocol ID  (4 bytes) — 0xFE 'SMB'
///   Offset  4: Header Length (2 bytes) — 64
///   ...
///   Offset 64: Structure Size (2 bytes) — 36
///   Offset 66: Dialect Count  (2 bytes)
///   Offset 68: Security Mode  (2 bytes)
///   Offset 70: Reserved       (2 bytes)
///   Offset 72: Capabilities   (4 bytes)
///   Offset 76: Client GUID    (16 bytes)
///
/// All offsets above are relative to the SMB2 header start (i.e. after the
/// 4-byte NetBIOS header).
fn extract_smb2_client_guid(payload: &[u8]) -> Option<String> {
    // We need at least 4 (NetBIOS) + 64 (SMB2 header) + 36 (negotiate body up through GUID)
    // = 4 + 76 + 16 = 96 bytes
    if payload.len() < 96 {
        return None;
    }

    // Client GUID is at SMB2 header offset 76, which is TCP payload offset 80
    // (4 NetBIOS + 76).
    let guid_offset = 4 + 76;
    let guid_bytes = &payload[guid_offset..guid_offset + 16];

    // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // (first three groups are little-endian, last two are big-endian)
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
    let d4 = &guid_bytes[8..16];

    let guid = format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
    );

    // Skip all-zero GUIDs (common in scanners).
    if guid_bytes.iter().all(|&b| b == 0) {
        return None;
    }

    Some(guid)
}

/// Extract the dialect count and individual dialect values from an SMB2
/// Negotiate Request.
fn extract_smb2_dialects(payload: &[u8]) -> Vec<String> {
    let mut dialects = Vec::new();

    // Dialect count at TCP payload offset 70 (4 NetBIOS + 64 header + 2 StructureSize).
    if payload.len() < 72 {
        return dialects;
    }

    let dialect_count = u16::from_le_bytes([payload[70], payload[71]]) as usize;
    // Dialects start at TCP offset 100 (4 NetBIOS + 64 header + 32 negotiate fixed fields).
    // But the SMB2 negotiate structure size before the dialect list is 36 bytes:
    //   offset 68: StructureSize(2) + DialectCount(2) + SecurityMode(2) + Reserved(2)
    //            + Capabilities(4) + ClientGUID(16) + NegotiateContextOffset/Count/Reserved2(8)
    //   = 36 bytes, starting at SMB2 header offset 64 => TCP offset 68 + 36 = 100
    // But actually: 4(NetBIOS) + 64(header) = 68, then negotiate body starts there.
    // StructureSize(2) + DialectCount(2) + SecurityMode(2) + Reserved(2) + Capabilities(4)
    // + ClientGUID(16) + NegContextOffset(4) + NegContextCount(2) + Reserved2(2) = 36 bytes
    // Dialect list starts at offset 68 + 36 = 104.
    //
    // Actually the simpler calculation: dialects begin right after the fixed 36-byte
    // negotiate body, which starts at TCP offset 68 (4 + 64).  So dialect list at 68+36=104.
    let dialect_start = 4 + 64 + 36;
    let dialect_end = dialect_start + dialect_count * 2;

    if payload.len() < dialect_end {
        return dialects;
    }

    for i in 0..dialect_count {
        let offset = dialect_start + i * 2;
        let dialect = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
        let label = match dialect {
            0x0202 => "SMB 2.0.2".to_string(),
            0x0210 => "SMB 2.1".to_string(),
            0x0300 => "SMB 3.0".to_string(),
            0x0302 => "SMB 3.0.2".to_string(),
            0x0311 => "SMB 3.1.1".to_string(),
            other => format!("0x{:04x}", other),
        };
        dialects.push(label);
    }

    dialects
}

#[async_trait]
impl WatchListener for SmbHoneypot {
    fn name(&self) -> &str {
        "smb-honeypot"
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    fn default_port(&self) -> u16 {
        4445
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        tracing::info!("[smb-honeypot] Listening on {}", bind_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("[smb-honeypot] Accept error: {}", e);
                            continue;
                        }
                    };

                    let tx = events_tx.clone();
                    let dest_port = bind_addr.port();

                    tokio::spawn(async move {
                        if let Err(e) = handle_smb_connection(stream, peer_addr, dest_port, tx).await {
                            tracing::debug!("[smb-honeypot] Connection handler error from {}: {}", peer_addr, e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    tracing::info!("[smb-honeypot] Shutdown signal received, stopping listener");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle a single inbound SMB connection.
async fn handle_smb_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    // Apply a 30-second overall timeout for the entire interaction.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        handle_smb_inner(&mut stream, peer_addr, dest_port, &events_tx),
    )
    .await
    .unwrap_or_else(|_| {
        tracing::debug!("[smb-honeypot] Connection from {} timed out", peer_addr);
        Ok(())
    })
}

async fn handle_smb_inner(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dest_port: u16,
    events_tx: &mpsc::UnboundedSender<WatchEvent>,
) -> anyhow::Result<()> {
    // Read initial data — most SMB clients will send a negotiate request
    // immediately after the TCP handshake completes.
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => {
            // Zero-length read: connection closed without sending data.
            let mut event = WatchEvent::new(
                "smb-honeypot",
                "tcp",
                peer_addr,
                dest_port,
                WatchEventType::ConnectionAttempt,
                Severity::Low,
            );
            event.details.insert("note".to_string(), "Connection closed without data".to_string());
            let _ = events_tx.send(event);
            return Ok(());
        }
        Ok(Err(e)) => {
            tracing::debug!("[smb-honeypot] Read error from {}: {}", peer_addr, e);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("[smb-honeypot] Read timed out from {}", peer_addr);
            return Ok(());
        }
    };

    let payload = &buf[..n];

    // ── Detect SMB protocol ─────────────────────────────────────────────
    //
    // The SMB magic lives right after the 4-byte NetBIOS Session Service
    // header, i.e. at bytes 4..8 of the TCP payload.
    let (smb_version, is_smb) = if payload.len() >= 8 {
        if payload[4..8] == SMB1_MAGIC {
            ("SMB1", true)
        } else if payload[4..8] == SMB2_MAGIC {
            ("SMB2+", true)
        } else {
            ("unknown", false)
        }
    } else {
        ("unknown", false)
    };

    if !is_smb {
        // Not an SMB negotiate — could be a generic port scanner.  Log it as
        // a protocol probe and move on.
        let mut event = WatchEvent::new(
            "smb-honeypot",
            "tcp",
            peer_addr,
            dest_port,
            WatchEventType::ProtocolProbe,
            Severity::Low,
        );
        let hex_preview_len = std::cmp::min(64, payload.len());
        event.captured_data = Some(hex_encode(&payload[..hex_preview_len]));
        event.details.insert("bytes_received".to_string(), n.to_string());
        event.details.insert("note".to_string(), "Non-SMB data received on SMB honeypot port".to_string());
        let _ = events_tx.send(event);
        return Ok(());
    }

    // ── SMB Negotiate detected ──────────────────────────────────────────
    let mut event = WatchEvent::new(
        "smb-honeypot",
        "tcp",
        peer_addr,
        dest_port,
        WatchEventType::NegotiateAttempt,
        Severity::Medium,
    );

    event.details.insert("smb_version".to_string(), smb_version.to_string());
    event.details.insert("bytes_received".to_string(), n.to_string());

    // Capture a hex preview of the raw negotiate request.
    let hex_preview_len = std::cmp::min(128, payload.len());
    event.captured_data = Some(hex_encode(&payload[..hex_preview_len]));

    // Extract protocol-specific details.
    match smb_version {
        "SMB1" => {
            let dialects = extract_smb1_dialects(payload);
            if !dialects.is_empty() {
                event.details.insert("dialects".to_string(), dialects.join(", "));
            }

            // Check if the command byte is Negotiate (0x72).
            if payload.len() > 8 && payload[8] == 0x72 {
                event.details.insert("smb_command".to_string(), "Negotiate (0x72)".to_string());
            } else if payload.len() > 8 {
                event.details.insert(
                    "smb_command".to_string(),
                    format!("0x{:02x}", payload[8]),
                );
            }
        }
        "SMB2+" => {
            let dialects = extract_smb2_dialects(payload);
            if !dialects.is_empty() {
                event.details.insert("dialects".to_string(), dialects.join(", "));
            }

            if let Some(guid) = extract_smb2_client_guid(payload) {
                event.details.insert("client_guid".to_string(), guid);
            }

            // SMB2 command is a 2-byte LE value at offset 16 from the SMB2 header
            // start (TCP offset 16).  Negotiate = 0x0000.
            if payload.len() >= 16 {
                let command = u16::from_le_bytes([payload[16], payload[17]]);
                let cmd_label = match command {
                    0x0000 => "Negotiate (0x0000)".to_string(),
                    other => format!("0x{:04x}", other),
                };
                event.details.insert("smb2_command".to_string(), cmd_label);
            }
        }
        _ => {}
    }

    let _ = events_tx.send(event);

    // ── Send a minimal response ─────────────────────────────────────────
    //
    // For SMB1 negotiates we send a canned response that looks like a real
    // server with signing required.  For SMB2+ we just close the connection
    // since crafting a valid SMB2 negotiate response is more involved and
    // we have already captured everything we need.
    if smb_version == "SMB1" {
        let _ = stream.write_all(&SMB1_NEGOTIATE_RESPONSE).await;
        let _ = stream.flush().await;

        // Some clients will follow up with a Session Setup.  Try to read it
        // to capture any additional data (e.g. NTLMSSP token).
        let mut follow_up = vec![0u8; 4096];
        if let Ok(Ok(m)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut follow_up),
        )
        .await
        {
            if m > 0 {
                let mut login_event = WatchEvent::new(
                    "smb-honeypot",
                    "tcp",
                    peer_addr,
                    dest_port,
                    WatchEventType::LoginAttempt,
                    Severity::High,
                );

                let preview_len = std::cmp::min(128, m);
                login_event.captured_data = Some(hex_encode(&follow_up[..preview_len]));
                login_event.details.insert("bytes_received".to_string(), m.to_string());
                login_event.details.insert("smb_version".to_string(), "SMB1".to_string());
                login_event.details.insert("stage".to_string(), "Session Setup".to_string());

                // Look for NTLMSSP signature in the follow-up data.
                if let Some(pos) = follow_up[..m]
                    .windows(7)
                    .position(|w| w == b"NTLMSSP")
                {
                    login_event.details.insert("auth_protocol".to_string(), "NTLMSSP".to_string());

                    // NTLMSSP message type is at offset +8 from the signature.
                    if pos + 12 <= m {
                        let msg_type = u32::from_le_bytes([
                            follow_up[pos + 8],
                            follow_up[pos + 9],
                            follow_up[pos + 10],
                            follow_up[pos + 11],
                        ]);
                        let msg_label = match msg_type {
                            1 => "NEGOTIATE_MESSAGE",
                            2 => "CHALLENGE_MESSAGE",
                            3 => "AUTHENTICATE_MESSAGE",
                            _ => "UNKNOWN",
                        };
                        login_event.details.insert(
                            "ntlmssp_message_type".to_string(),
                            format!("{} ({})", msg_label, msg_type),
                        );
                    }
                }

                let _ = events_tx.send(login_event);
            }
        }
    }

    // Gracefully shut down the write half so the client gets a clean close.
    let _ = stream.shutdown().await;

    Ok(())
}
