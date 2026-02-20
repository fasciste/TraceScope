use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::domain::event::{Event, EventType, RawEvent, Severity};

pub struct Normalizer;

impl Normalizer {
    pub fn new() -> Self { Self }

    pub async fn run(
        &self,
        mut raw_rx: mpsc::Receiver<RawEvent>,
        norm_tx:    mpsc::Sender<Event>,
        counter:    Arc<AtomicU64>,
    ) {
        while let Some(raw) = raw_rx.recv().await {
            match self.normalize(raw) {
                Ok(event) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    if norm_tx.send(event).await.is_err() {
                        debug!("Normalizer: downstream closed");
                        break;
                    }
                }
                Err(e) => warn!(error = %e, "Normalisation failed — dropping event"),
            }
        }
        debug!("Normalizer task finished");
    }

    fn normalize(&self, raw: RawEvent) -> Result<Event> {
        let data       = &raw.raw_data;
        let event_type = self.detect_event_type(data);
        let severity   = self.detect_severity(data);
        let metadata   = self.flatten_metadata(data);
        let timestamp  = self.extract_timestamp(data);

        let mut event = Event::new(raw.source, event_type, severity, metadata);
        if let Some(ts) = timestamp {
            event = event.with_timestamp(ts);
        }
        Ok(event)
    }

    fn detect_event_type(&self, data: &serde_json::Value) -> EventType {
        if let Some(et) = data.get("event_type").and_then(|v| v.as_str()) {
            return match et {
                "process_creation"     => EventType::ProcessCreation,
                "network_connection"   => EventType::NetworkConnection,
                "file_creation"        => EventType::FileCreation,
                "service_installation" => EventType::ServiceInstallation,
                "registry_modification"=> EventType::RegistryModification,
                "login_attempt"        => EventType::LoginAttempt,
                "login_success"        => EventType::LoginSuccess,
                "login_failure"        => EventType::LoginFailure,
                "privilege_escalation" => EventType::PrivilegeEscalation,
                "command_execution"    => EventType::CommandExecution,
                "dns_query"            => EventType::DnsQuery,
                other                  => EventType::Unknown(other.to_owned()),
            };
        }

        // Windows EventID → normalized type
        if let Some(id) = data.get("EventID").and_then(|v| v.as_u64()) {
            return match id {
                4688     => EventType::ProcessCreation,
                3 | 5156 => EventType::NetworkConnection,
                11       => EventType::FileCreation,
                7045     => EventType::ServiceInstallation,
                4657     => EventType::RegistryModification,
                4648     => EventType::LoginAttempt,
                4624     => EventType::LoginSuccess,
                4625     => EventType::LoginFailure,
                4672     => EventType::PrivilegeEscalation,
                1        => EventType::ProcessCreation,
                _        => EventType::Unknown(format!("EventID:{id}")),
            };
        }

        EventType::Unknown("unclassified".into())
    }

    fn detect_severity(&self, data: &serde_json::Value) -> Severity {
        if let Some(s) = data.get("severity").and_then(|v| v.as_str()) {
            return match s.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high"     => Severity::High,
                "medium"   => Severity::Medium,
                "low"      => Severity::Low,
                _          => Severity::Info,
            };
        }
        // Windows event level: 1=Critical 2=Error 3=Warning 4=Info
        if let Some(level) = data.get("Level").and_then(|v| v.as_u64()) {
            return match level {
                1    => Severity::Critical,
                2    => Severity::High,
                3    => Severity::Medium,
                4..=5=> Severity::Low,
                _    => Severity::Info,
            };
        }
        Severity::Info
    }

    fn flatten_metadata(&self, data: &serde_json::Value) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(obj) = data.as_object() {
            for (k, v) in obj {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other                        => other.to_string(),
                };
                map.insert(k.clone(), s);
            }
        }
        map
    }

    fn extract_timestamp(&self, data: &serde_json::Value) -> Option<DateTime<Utc>> {
        for key in &["timestamp", "@timestamp", "TimeCreated", "time"] {
            if let Some(ts_str) = data.get(*key).and_then(|v| v.as_str()) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
        None
    }
}

impl Default for Normalizer {
    fn default() -> Self { Self::new() }
}
