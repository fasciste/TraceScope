use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind")]
pub enum EventSource {
    Evtx    { file: String, channel: String },
    Syslog  { host: String, facility: u8    },
    Pcap    { interface: String             },
    Json    { file: String                  },
    Mock,
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evtx   { file, .. }  => write!(f, "evtx:{file}"),
            Self::Syslog { host, .. }  => write!(f, "syslog:{host}"),
            Self::Pcap   { interface } => write!(f, "pcap:{interface}"),
            Self::Json   { file }      => write!(f, "json:{file}"),
            Self::Mock                 => write!(f, "mock"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessCreation,
    NetworkConnection,
    FileCreation,
    ServiceInstallation,
    RegistryModification,
    LoginAttempt,
    LoginSuccess,
    LoginFailure,
    PrivilegeEscalation,
    CommandExecution,
    DnsQuery,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Self::Info     => 1,
            Self::Low      => 5,
            Self::Medium   => 15,
            Self::High     => 30,
            Self::Critical => 50,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info     => "INFO",
            Self::Low      => "LOW",
            Self::Medium   => "MEDIUM",
            Self::High     => "HIGH",
            Self::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

/// Immutable normalized forensic event. `metadata` is Arc-wrapped so
/// cloning is O(1) across broadcast fan-out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id:         Uuid,
    pub timestamp:  DateTime<Utc>,
    pub source:     EventSource,
    pub event_type: EventType,
    pub severity:   Severity,
    pub metadata:   Arc<HashMap<String, String>>,
}

impl Event {
    pub fn new(
        source:     EventSource,
        event_type: EventType,
        severity:   Severity,
        metadata:   HashMap<String, String>,
    ) -> Self {
        Self {
            id:         Uuid::new_v4(),
            timestamp:  Utc::now(),
            source,
            event_type,
            severity,
            metadata:   Arc::new(metadata),
        }
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }

    #[inline]
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub source:      EventSource,
    pub raw_data:    serde_json::Value,
    pub received_at: DateTime<Utc>,
}

impl RawEvent {
    pub fn new(source: EventSource, raw_data: serde_json::Value) -> Self {
        Self { source, raw_data, received_at: Utc::now() }
    }
}
