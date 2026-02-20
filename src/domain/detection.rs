use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::event::{Event, Severity};

/// A confirmed or suspected threat detection produced by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Unique detection ID.
    pub id: Uuid,
    /// Rule that produced this detection.
    pub rule_id:   String,
    pub rule_name: String,
    /// Human-readable description of what was detected.
    pub description: String,
    pub severity:    Severity,
    /// IDs of the events that contributed to this detection.
    pub events: Vec<Uuid>,
    pub detected_at: DateTime<Utc>,
    /// Score contribution added to the global threat score.
    pub score_contribution: u32,
    /// MITRE ATT&CK / custom tags.
    pub tags: Vec<String>,
    /// Forensic evidence strings (human-readable).
    pub evidence: Vec<String>,
}

impl Detection {
    pub fn new(
        rule_id:            impl Into<String>,
        rule_name:          impl Into<String>,
        description:        impl Into<String>,
        severity:           Severity,
        trigger_events:     &[&Event],
        score_contribution: u32,
        tags:               Vec<String>,
        evidence:           Vec<String>,
    ) -> Self {
        Self {
            id:                 Uuid::new_v4(),
            rule_id:            rule_id.into(),
            rule_name:          rule_name.into(),
            description:        description.into(),
            severity,
            events:             trigger_events.iter().map(|e| e.id).collect(),
            detected_at:        Utc::now(),
            score_contribution,
            tags,
            evidence,
        }
    }
}
