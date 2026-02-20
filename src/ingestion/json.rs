/// Generic JSON-lines ingestor.
///
/// Reads a file where every non-empty line is a JSON object.  This is the
/// most portable format: any tool can export to JSON-lines, and TraceScope
/// consumes it directly.
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct JsonIngestor {
    path: PathBuf,
}

impl JsonIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl Ingestor for JsonIngestor {
    fn name(&self) -> &str { "json" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "Starting JSON ingestion");

        let file = tokio::fs::File::open(&self.path)
            .await
            .with_context(|| format!("Cannot open JSON file: {}", self.path.display()))?;

        let source = EventSource::Json {
            file: self.path.to_string_lossy().into_owned(),
        };

        let mut lines = BufReader::new(file).lines();
        let mut count = 0u64;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_owned();
            if line.is_empty() || line.starts_with("//") { continue; }

            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(raw_data) => {
                    count += 1;
                    let event = RawEvent::new(source.clone(), raw_data);
                    if tx.send(event).await.is_err() {
                        debug!("JSON downstream closed — stopping");
                        break;
                    }
                }
                Err(e) => warn!(line_nr = count + 1, error = %e, "JSON: skipping invalid line"),
            }
        }

        info!(count, "JSON ingestion complete");
        Ok(())
    }
}
