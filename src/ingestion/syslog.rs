/// Syslog ingestor.
///
/// Reads a syslog file line-by-line.  Each line is either:
///   • a raw RFC-3164/RFC-5424 syslog line → wrapped in a JSON object
///     `{ "raw": "<line>", "source": "<host>" }`
///   • a pre-serialised JSON object (structured syslog)
///
/// Production extension: bind a UDP/TCP socket and tail -f for live ingestion.
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct SyslogIngestor {
    path: PathBuf,
    /// Logical host name embedded in metadata when the file itself does not
    /// include a hostname field.
    default_host: String,
}

impl SyslogIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path:         path.into(),
            default_host: "localhost".into(),
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.default_host = host.into();
        self
    }
}

#[async_trait]
impl Ingestor for SyslogIngestor {
    fn name(&self) -> &str { "syslog" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "Starting syslog ingestion");

        let file = tokio::fs::File::open(&self.path)
            .await
            .with_context(|| format!("Cannot open syslog file: {}", self.path.display()))?;

        let source = EventSource::Syslog {
            host:     self.default_host.clone(),
            facility: 1,
        };

        let mut lines = BufReader::new(file).lines();
        let mut count = 0u64;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_owned();
            if line.is_empty() { continue; }

            // Try to parse as JSON first; otherwise wrap the raw string.
            let raw_data = serde_json::from_str::<serde_json::Value>(&line)
                .unwrap_or_else(|_| {
                    serde_json::json!({
                        "event_type": "syslog",
                        "raw":        line,
                        "host":       self.default_host,
                    })
                });

            count += 1;
            let event = RawEvent::new(source.clone(), raw_data);
            if tx.send(event).await.is_err() {
                debug!("Syslog downstream closed — stopping");
                break;
            }
        }

        info!(count, "Syslog ingestion complete");
        Ok(())
    }
}
