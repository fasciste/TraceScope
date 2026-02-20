use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::domain::event::{EventSource, RawEvent};
use super::Ingestor;

pub struct EvtxIngestor { path: PathBuf }

impl EvtxIngestor {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self { path: path.into() } }
}

#[async_trait]
impl Ingestor for EvtxIngestor {
    fn name(&self) -> &str { "evtx" }

    async fn ingest(&self, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(path = %self.path.display(), "EVTX ingestion starting");

        let path   = self.path.clone();
        let source = EventSource::Evtx {
            file:    path.to_string_lossy().into_owned(),
            channel: String::new(),
        };

        // evtx parsing is synchronous and CPU-bound — keep it off the async executor.
        let records: Vec<serde_json::Value> = tokio::task::spawn_blocking(move || {
            let mut parser = evtx::EvtxParser::from_path(&path)
                .with_context(|| format!("Cannot open EVTX: {}", path.display()))?;
            let mut out = Vec::new();
            for record in parser.records_json() {
                match record {
                    Ok(r) => match serde_json::from_str::<serde_json::Value>(&r.data) {
                        Ok(v)  => out.push(flatten_evtx(v)),
                        Err(e) => warn!(error = %e, "EVTX: JSON parse failed"),
                    },
                    Err(e) => warn!(error = %e, "EVTX: record error"),
                }
            }
            Ok::<_, anyhow::Error>(out)
        }).await??;

        let count = records.len();
        for rec in records {
            if tx.send(RawEvent::new(source.clone(), rec)).await.is_err() {
                debug!("EVTX downstream closed");
                break;
            }
        }

        info!(count, "EVTX ingestion complete");
        Ok(())
    }
}

// Convert the deeply-nested XML-as-JSON that evtx outputs into a flat object
// matching the normalizer's expected schema (EventID, host, timestamp, cmd, …).
fn flatten_evtx(value: serde_json::Value) -> serde_json::Value {
    let event = match value.get("Event") {
        Some(e) => e,
        None    => return value,
    };

    let mut flat = serde_json::Map::new();

    if let Some(sys) = event.get("System") {
        if let Some(s) = sys.get("EventID").and_then(evtx_str) {
            if let Ok(n) = s.parse::<u64>() {
                flat.insert("EventID".into(), serde_json::json!(n));
            }
        }
        if let Some(s) = sys.get("Channel").and_then(evtx_str) {
            flat.insert("channel".into(), s.into());
        }
        if let Some(s) = sys.get("Computer").and_then(evtx_str) {
            flat.insert("host".into(), s.into());
        }
        if let Some(s) = sys.get("TimeCreated")
            .and_then(|v| v.get("#attributes"))
            .and_then(|a| a.get("SystemTime"))
            .and_then(|v| v.as_str())
        {
            flat.insert("timestamp".into(), s.into());
        }
        if let Some(s) = sys.get("Level").and_then(evtx_str) {
            flat.insert("Level".into(), s.into());
        }
    }

    if let Some(ed) = event.get("EventData") {
        flatten_event_data(ed, &mut flat);
    }

    serde_json::Value::Object(flat)
}

fn flatten_event_data(ed: &serde_json::Value, out: &mut serde_json::Map<String, serde_json::Value>) {
    match ed.get("Data") {
        Some(serde_json::Value::Array(arr)) => {
            for item in arr {
                let name = item.get("#attributes")
                    .and_then(|a| a.get("Name"))
                    .and_then(|v| v.as_str());
                let text = item.get("#text").and_then(|v| v.as_str())
                    .or_else(|| item.as_str());
                if let (Some(n), Some(t)) = (name, text) {
                    out.entry(win_field(n)).or_insert(t.into());
                }
            }
        }
        Some(serde_json::Value::Object(obj)) => {
            for (k, v) in obj {
                if let Some(s) = evtx_str(v) {
                    out.entry(win_field(k)).or_insert(s.into());
                }
            }
        }
        _ => {
            if let Some(obj) = ed.as_object() {
                for (k, v) in obj.iter().filter(|(k, _)| *k != "Data") {
                    if let Some(s) = evtx_str(v) {
                        out.entry(win_field(k)).or_insert(s.into());
                    }
                }
            }
        }
    }
}

fn evtx_str(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Object(o) => o.get("#text")
            .and_then(|t| t.as_str())
            .map(String::from),
        _ => None,
    }
}

fn win_field(name: &str) -> String {
    match name {
        "CommandLine"                  => "cmd",
        "Image"                        => "image",
        "ParentImage"                  => "parent_image",
        "User" | "SubjectUserName"     => "user",
        "TargetUserName"               => "target_user",
        "IpAddress" | "SourceAddress" => "source_ip",
        "ProcessId" | "NewProcessId"
        | "ProcessID"                  => "pid",
        "ServiceName"                  => "service_name",
        "ImagePath"                    => "image_path",
        "TargetObject"                 => "registry_key",
        "Details"                      => "registry_value",
        "DestAddress"                  => "dst_ip",
        "DestPort"                     => "dst_port",
        "SourcePort"                   => "src_port",
        "QueryName"                    => "query",
        other                          => return other.to_lowercase(),
    }.to_string()
}
