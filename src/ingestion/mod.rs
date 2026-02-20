use async_trait::async_trait;
use anyhow::Result;
use tokio::sync::mpsc;

use crate::domain::event::RawEvent;

pub mod evtx;
pub mod json;
pub mod pcap;
pub mod syslog;

#[async_trait]
pub trait Ingestor: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()>;
}
