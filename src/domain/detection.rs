use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::event::{Event, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id:                 Uuid,
    pub rule_id:            String,
    pub rule_name:          String,
    pub description:        String,
    pub severity:           Severity,
    pub events:             Vec<Uuid>,
    pub detected_at:        DateTime<Utc>,
    pub score_contribution: u32,
    pub tags:               Vec<String>,
    pub evidence:           Vec<String>,
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
