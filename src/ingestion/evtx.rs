/// EVTX ingestor.
///
/// Production path: wrap `evtx::EvtxParser` in `tokio::task::spawn_blocking`
/// (it is a sync, CPU-bound parser) and stream records through this channel.
///
/// Current implementation reads a **JSON-lines file** where each line is a
/// JSON object representing one Windows event (e.g. exported via `python-evtx`
/// or `evtx_dump --format json-lines`).  This keeps the binary free of the
/// optional `evtx` C dependency while preserving the real async streaming
/// semantics.
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct EvtxIngestor {
    path: PathBuf,
}

impl EvtxIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl Ingestor for EvtxIngestor {
    fn name(&self) -> &str { "evtx" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "Starting EVTX ingestion");

        let file = tokio::fs::File::open(&self.path)
            .await
            .with_context(|| format!("Cannot open EVTX file: {}", self.path.display()))?;

        let source = EventSource::Evtx {
            file:    self.path.to_string_lossy().into_owned(),
            channel: "Security".into(),
        };

        let mut lines  = BufReader::new(file).lines();
        let mut count  = 0u64;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_owned();
            if line.is_empty() { continue; }

            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(raw_data) => {
                    count += 1;
                    let event = RawEvent::new(source.clone(), raw_data);
                    if tx.send(event).await.is_err() {
                        debug!("EVTX downstream closed — stopping");
                        break;
                    }
                }
                Err(e) => warn!(error = %e, "EVTX: skipping unparseable line"),
            }
        }

        info!(count, "EVTX ingestion complete");
        Ok(())
    }
}
