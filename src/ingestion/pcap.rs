use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct PcapIngestor { path: PathBuf }

impl PcapIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self { path: path.into() } }
}

#[async_trait]
impl Ingestor for PcapIngestor {
    fn name(&self) -> &str { "pcap" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "PCAP ingestion starting");

        let path   = self.path.clone();
        let source = EventSource::Pcap {
            interface: path.to_string_lossy().into_owned(),
        };

        // pcap-file reads synchronously; keep it off the async executor.
        let events: Vec<serde_json::Value> = tokio::task::spawn_blocking(move || {
            use pcap_file::pcap::PcapReader;
            let file   = std::fs::File::open(&path)
                .with_context(|| format!("Cannot open PCAP: {}", path.display()))?;
            let mut reader = PcapReader::new(file)
                .context("Invalid PCAP file")?;
            let mut out = Vec::new();
            while let Some(pkt) = reader.next_packet() {
                match pkt {
                    Ok(p)  => out.push(packet_to_json(&p.data)),
                    Err(e) => warn!(error = %e, "PCAP: packet error"),
                }
            }
            Ok::<_, anyhow::Error>(out)
        }).await??;

        let count = events.len();
        for ev in events {
            if tx.send(RawEvent::new(source.clone(), ev)).await.is_err() {
                debug!("PCAP downstream closed");
                break;
            }
        }

        info!(count, "PCAP ingestion complete");
        Ok(())
    }
}

pub(crate) fn packet_to_json(data: &[u8]) -> serde_json::Value {
    use etherparse::SlicedPacket;

    let Ok(sliced) = SlicedPacket::from_ethernet(data) else {
        return serde_json::json!({ "event_type": "network_connection", "protocol": "raw" });
    };

    let (src_ip, dst_ip, proto) = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(v4)) => (
            format_ipv4(v4.header().source()),
            format_ipv4(v4.header().destination()),
            "ipv4",
        ),
        Some(etherparse::NetSlice::Ipv6(v6)) => (
            format_ipv6(v6.header().source()),
            format_ipv6(v6.header().destination()),
            "ipv6",
        ),
        _ => return serde_json::json!({ "event_type": "network_connection", "protocol": "unknown" }),
    };

    let (transport, src_port, dst_port, pkt_payload): (&str, u16, u16, &[u8]) = match &sliced.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (
            "tcp", tcp.source_port(), tcp.destination_port(), tcp.payload(),
        ),
        Some(etherparse::TransportSlice::Udp(udp)) => (
            "udp", udp.source_port(), udp.destination_port(), udp.payload(),
        ),
        _ => return serde_json::json!({
            "event_type": "network_connection",
            "src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto,
        }),
    };

    if src_port == 53 || dst_port == 53 {
        let query = parse_dns_name(pkt_payload).unwrap_or_default();
        return serde_json::json!({
            "event_type": "dns_query",
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   src_port.to_string(),
            "dst_port":   dst_port.to_string(),
            "query":      query,
            "protocol":   transport,
        });
    }

    serde_json::json!({
        "event_type": "network_connection",
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "src_port":   src_port.to_string(),
        "dst_port":   dst_port.to_string(),
        "protocol":   transport,
    })
}

fn format_ipv4(addr: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

fn format_ipv6(addr: [u8; 16]) -> String {
    let groups: Vec<String> = addr.chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    groups.join(":")
}

// Minimal DNS name decoder — reads the Question section of a DNS message.
fn parse_dns_name(data: &[u8]) -> Option<String> {
    if data.len() < 13 { return None; }
    let mut pos    = 12; // skip the 12-byte DNS header
    let mut labels = Vec::new();
    loop {
        let len = *data.get(pos)? as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { break; } // compression pointer — stop
        pos += 1;
        let end = pos + len;
        if end > data.len() { return None; }
        labels.push(std::str::from_utf8(&data[pos..end]).ok()?.to_owned());
        pos = end;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}
