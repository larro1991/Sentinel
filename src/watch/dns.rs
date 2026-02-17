use super::*;
use crate::finding::Severity;

use async_trait::async_trait;
use tokio::net::UdpSocket;

/// DNS honeypot — listens on UDP, parses DNS queries, responds with NXDOMAIN.
pub struct DnsHoneypot;

impl DnsHoneypot {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl WatchListener for DnsHoneypot {
    fn name(&self) -> &str {
        "dns-honeypot"
    }

    fn protocol(&self) -> &str {
        "udp"
    }

    fn default_port(&self) -> u16 {
        5353
    }

    async fn listen(
        &self,
        bind_addr: SocketAddr,
        events_tx: mpsc::UnboundedSender<WatchEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        tracing::info!("[dns-honeypot] Listening on {} (UDP)", bind_addr);

        let mut buf = [0u8; 512];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            let data = &buf[..len];
                            handle_query(
                                &socket,
                                peer_addr,
                                bind_addr.port(),
                                data,
                                &events_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("[dns-honeypot] Recv error: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("[dns-honeypot] Shutdown signal received");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_query(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    dest_port: u16,
    data: &[u8],
    events_tx: &mpsc::UnboundedSender<WatchEvent>,
) {
    // DNS header is 12 bytes minimum.
    if data.len() < 12 {
        let mut event = WatchEvent::new(
            "dns-honeypot",
            "udp",
            peer_addr,
            dest_port,
            WatchEventType::ProtocolProbe,
            Severity::Low,
        );
        event.captured_data = Some(format!("Short DNS packet: {} bytes", data.len()));
        let _ = events_tx.send(event);
        return;
    }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    let qd_count = u16::from_be_bytes([data[4], data[5]]);

    // Parse the first question section to extract the queried domain name.
    let domain = if qd_count > 0 {
        parse_domain_name(data, 12)
    } else {
        None
    };

    let query_type = if let Some((_, end)) = parse_domain_name_with_end(data, 12) {
        if end + 2 <= data.len() {
            Some(u16::from_be_bytes([data[end], data[end + 1]]))
        } else {
            None
        }
    } else {
        None
    };

    let type_str = match query_type {
        Some(1) => "A",
        Some(2) => "NS",
        Some(5) => "CNAME",
        Some(6) => "SOA",
        Some(15) => "MX",
        Some(16) => "TXT",
        Some(28) => "AAAA",
        Some(33) => "SRV",
        Some(255) => "ANY",
        Some(n) => {
            // Use a leaked string to get a &str; fine for a handful of unknown types.
            // In practice, just log the number.
            let _ = n;
            "OTHER"
        }
        None => "UNKNOWN",
    };

    let domain_str = domain.as_deref().unwrap_or("<unparseable>");

    let mut event = WatchEvent::new(
        "dns-honeypot",
        "udp",
        peer_addr,
        dest_port,
        WatchEventType::DnsQuery,
        Severity::Medium,
    );
    event.captured_data = Some(format!("{} {}", type_str, domain_str));
    event.details.insert("query_domain".to_string(), domain_str.to_string());
    event.details.insert("query_type".to_string(), type_str.to_string());
    event.details.insert("tx_id".to_string(), tx_id.to_string());
    let _ = events_tx.send(event);

    // Build NXDOMAIN response.
    let response = build_nxdomain_response(data, tx_id);
    if let Err(e) = socket.send_to(&response, peer_addr).await {
        tracing::debug!("[dns-honeypot] Failed to send NXDOMAIN to {}: {}", peer_addr, e);
    }
}

/// Parse a DNS domain name starting at `offset` in the packet. Returns the
/// dotted name string.
fn parse_domain_name(data: &[u8], offset: usize) -> Option<String> {
    parse_domain_name_with_end(data, offset).map(|(name, _)| name)
}

/// Parse a DNS domain name, returning both the name and the byte offset
/// immediately after the name field (past the terminating zero or pointer).
fn parse_domain_name_with_end(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut end_pos = None;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }

        // Compression pointer (top 2 bits set).
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            // Follow the pointer (only once to avoid loops).
            pos = ptr;
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        labels.push(label);
        pos += len;
    }

    let name = labels.join(".");
    Some((name, end_pos.unwrap_or(pos)))
}

/// Build a minimal DNS NXDOMAIN response for the given query packet.
fn build_nxdomain_response(query: &[u8], tx_id: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len());

    // Header: copy transaction ID, set response flags.
    resp.push((tx_id >> 8) as u8);
    resp.push(tx_id as u8);

    // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    resp.push(0x85); // 1 0000 1 0 1
    resp.push(0x83); // 1 000 0011

    // QDCOUNT: copy from query.
    if query.len() >= 6 {
        resp.push(query[4]);
        resp.push(query[5]);
    } else {
        resp.push(0);
        resp.push(0);
    }

    // ANCOUNT, NSCOUNT, ARCOUNT: all zero.
    resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    // Copy the question section from the original query (after the 12-byte header).
    if query.len() > 12 {
        resp.extend_from_slice(&query[12..]);
    }

    resp
}
