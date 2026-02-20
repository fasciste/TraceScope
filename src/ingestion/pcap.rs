/// PCAP ingestor.
///
/// Production path: call `pcap::Capture::from_file` inside
/// `tokio::task::spawn_blocking` (libpcap is synchronous) and stream
/// synthesised JSON network-event records.
///
/// Current implementation: reads a **JSON-lines PCAP export** (e.g. output of
/// `tshark -T json` piped through `jq -c .[]`).  Provides identical async
/// streaming semantics.
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct PcapIngestor {
    path:      PathBuf,
    interface: String,
}

impl PcapIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path:      path.into(),
            interface: "file".into(),
        }
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = iface.into();
        self
    }
}

#[async_trait]
impl Ingestor for PcapIngestor {
    fn name(&self) -> &str { "pcap" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "Starting PCAP ingestion");

        let file = tokio::fs::File::open(&self.path)
            .await
            .with_context(|| format!("Cannot open PCAP file: {}", self.path.display()))?;

        let source = EventSource::Pcap { interface: self.interface.clone() };

        let mut lines = BufReader::new(file).lines();
        let mut count = 0u64;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_owned();
            if line.is_empty() { continue; }

            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(mut raw_data) => {
                    // Ensure event_type is set for the normalizer.
                    if raw_data.get("event_type").is_none() {
                        raw_data["event_type"] = serde_json::json!("network_connection");
                    }
                    count += 1;
                    let event = RawEvent::new(source.clone(), raw_data);
                    if tx.send(event).await.is_err() {
                        debug!("PCAP downstream closed — stopping");
                        break;
                    }
                }
                Err(e) => warn!(error = %e, "PCAP: skipping unparseable line"),
            }
        }

        info!(count, "PCAP ingestion complete");
        Ok(())
    }
}
