use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::domain::event::{Event, EventType, RawEvent, Severity};

pub struct Normalizer {
    filter_hosts: Vec<String>,
}

impl Normalizer {
    pub fn new() -> Self { Self { filter_hosts: vec![] } }

    pub fn with_filter_hosts(mut self, hosts: Vec<String>) -> Self {
        self.filter_hosts = hosts.into_iter().map(|h| h.to_lowercase()).collect();
        self
    }

    pub async fn run(
        &self,
        mut raw_rx: mpsc::Receiver<RawEvent>,
        norm_tx:    mpsc::Sender<Event>,
        counter:    Arc<AtomicU64>,
    ) {
        while let Some(raw) = raw_rx.recv().await {
            match self.normalize(raw) {
                Ok(Some(event)) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    if norm_tx.send(event).await.is_err() {
                        debug!("Normalizer: downstream closed");
                        break;
                    }
                }
                Ok(None) => {} // filtered out
                Err(e) => warn!(error = %e, "Normalisation failed — dropping event"),
            }
        }
        debug!("Normalizer task finished");
    }

    fn normalize(&self, raw: RawEvent) -> Result<Option<Event>> {
        let data       = &raw.raw_data;
        let event_type = self.detect_event_type(data);
        let severity   = self.detect_severity(data);
        let metadata   = self.flatten_metadata(data);
        let timestamp  = self.extract_timestamp(data);

        // Drop event if host filter is active and event doesn't match.
        if !self.filter_hosts.is_empty() {
            let host = metadata.get("host").map(String::as_str).unwrap_or("").to_lowercase();
            if !self.filter_hosts.iter().any(|f| f == &host) {
                return Ok(None);
            }
        }

        let mut event = Event::new(raw.source, event_type, severity, metadata);
        if let Some(ts) = timestamp {
            event = event.with_timestamp(ts);
        }
        Ok(Some(event))
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
                // Process
                1 | 4688          => EventType::ProcessCreation,
                // Network
                3 | 5156          => EventType::NetworkConnection,
                // File
                11                => EventType::FileCreation,
                // Service
                7045              => EventType::ServiceInstallation,
                // Registry
                4657 | 13         => EventType::RegistryModification,
                // Auth
                4648              => EventType::LoginAttempt,
                4624              => EventType::LoginSuccess,
                4625 | 4771       => EventType::LoginFailure,
                // Privilege escalation
                4672              => EventType::PrivilegeEscalation,
                // Sysmon command / script execution
                4103 | 4104 | 800 => EventType::CommandExecution,
                // DNS (Sysmon)
                22                => EventType::DnsQuery,
                _                 => EventType::Unknown(format!("EventID:{id}")),
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

    // Recursively flattens nested JSON objects into a flat key→string map.
    // Nested keys get dot-notation: {"metadata": {"cmd": "x"}} → "metadata.cmd" = "x".
    // If a nested key doesn't exist at the top level, it's also inserted without prefix
    // (e.g. "cmd" = "x") — so rules using top-level field names still work regardless
    // of whether the user nested their data inside a sub-object.
    fn flatten_metadata(&self, data: &serde_json::Value) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(obj) = data.as_object() {
            for (k, v) in obj {
                self.flatten_value(k, v, &mut map);
            }
        }
        // Field aliases: map common alternative names to canonical keys used by rules.
        // Only applied when the canonical key is absent. Order matters — first match wins.
        for (alias, canonical) in &[
            // Process
            ("command_line",        "cmd"),
            ("CommandLine",         "cmd"),
            ("ProcessCommandLine",  "cmd"),
            ("Image",               "exe"),
            ("ParentImage",         "parent_image"),
            ("ParentProcessName",   "parent_image"),
            // Host
            ("hostname",            "host"),
            ("Hostname",            "host"),
            ("computer",            "host"),
            ("Computer",            "host"),
            ("ComputerName",        "host"),
            ("WorkstationName",     "host"),
            // User
            ("username",            "user"),
            ("Username",            "user"),
            ("UserName",            "user"),
            ("User",                "user"),
            ("SubjectUserName",     "user"),
            ("TargetUserName",      "user"),
            ("AccountName",         "user"),
            // Network
            ("src_ip",              "source_ip"),
            ("SourceIp",            "source_ip"),
            ("SourceAddress",       "source_ip"),
            ("SourcePort",          "src_port"),
            ("dest_ip",             "dst_ip"),
            ("DestinationIp",       "dst_ip"),
            ("DestinationAddress",  "dst_ip"),
            ("dest_port",           "dst_port"),
            ("DestinationPort",     "dst_port"),
            ("bytes_sent",          "bytes_out"),
            ("BytesSent",           "bytes_out"),
            ("BytesOut",            "bytes_out"),
            // File
            ("file_name",           "file_path"),
            ("FileName",            "file_path"),
            ("TargetFilename",      "file_path"),
            ("FilePath",            "file_path"),
            // Registry
            ("TargetObject",        "registry_key"),
            ("RegistryKey",         "registry_key"),
            ("Details",             "registry_value"),
            // DNS
            ("QueryName",           "query"),
            ("dns_name",            "query"),
            // Service
            ("ServiceName",         "service_name"),
            ("ImagePath",           "image_path"),
        ] {
            if !map.contains_key(*canonical) {
                if let Some(val) = map.get(*alias).cloned() {
                    map.insert((*canonical).to_owned(), val);
                }
            }
        }
        map
    }

    fn flatten_value(&self, prefix: &str, value: &serde_json::Value, map: &mut HashMap<String, String>) {
        match value {
            serde_json::Value::Object(obj) => {
                for (k, v) in obj {
                    let child_key = format!("{prefix}.{k}");
                    self.flatten_value(&child_key, v, map);
                    // Also insert without prefix if top-level key is absent.
                    if !map.contains_key(k.as_str()) {
                        if let Some(s) = scalar_to_string(v) {
                            map.insert(k.clone(), s);
                        }
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                // Join scalar array elements as comma-separated string.
                let joined: String = arr.iter()
                    .filter_map(scalar_to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                if !joined.is_empty() {
                    map.insert(prefix.to_owned(), joined);
                }
            }
            _ => {
                if let Some(s) = scalar_to_string(value) {
                    map.insert(prefix.to_owned(), s);
                }
            }
        }
    }

    fn extract_timestamp(&self, data: &serde_json::Value) -> Option<DateTime<Utc>> {
        for key in &["timestamp", "@timestamp", "TimeCreated", "time", "event_time", "datetime"] {
            if let Some(ts_str) = data.get(*key).and_then(|v| v.as_str()) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
        None
    }
}

fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b)   => Some(b.to_string()),
        serde_json::Value::Null      => None,
        _                            => None,
    }
}

impl Default for Normalizer {
    fn default() -> Self { Self::new() }
}
