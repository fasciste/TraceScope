use async_trait::async_trait;
use anyhow::Result;
use tokio::sync::mpsc;

use crate::domain::event::RawEvent;

pub mod evtx;
pub mod json;
pub mod pcap;
pub mod syslog;

// ─── Ingestor trait ───────────────────────────────────────────────────────────

/// An async ingestion source.
///
/// Each ingestor runs as an independent `tokio::spawn` task and forwards
/// `RawEvent`s through a bounded channel (backpressure built-in).
/// When ingestion is complete the task drops its `Sender` half, signalling
/// EOF to downstream consumers.
#[async_trait]
pub trait Ingestor: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// Stream events into `tx` until EOF or channel closure.
    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()>;
}
