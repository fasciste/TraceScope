pub mod cli;
pub mod json;
pub mod web;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::domain::detection::Detection;
use crate::domain::event::Severity;
use crate::domain::score::ScoreSnapshot;

// ─── DetectionSummary ─────────────────────────────────────────────────────────

/// Severity-bucketed summary of all detections in a report.
#[derive(Debug, Serialize)]
pub struct DetectionSummary {
    pub total:    usize,
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
    pub info:     usize,
}

impl DetectionSummary {
    pub fn from_detections(detections: &[Detection]) -> Self {
        let mut s = Self {
            total: detections.len(),
            critical: 0, high: 0, medium: 0, low: 0, info: 0,
        };
        for d in detections {
            match d.severity {
                Severity::Critical => s.critical += 1,
                Severity::High     => s.high     += 1,
                Severity::Medium   => s.medium   += 1,
                Severity::Low      => s.low      += 1,
                Severity::Info     => s.info     += 1,
            }
        }
        s
    }
}

// ─── ForensicReport ───────────────────────────────────────────────────────────

/// Final forensic report returned by the pipeline.
#[derive(Debug, Serialize)]
pub struct ForensicReport {
    pub generated_at:     DateTime<Utc>,
    pub duration_secs:    f64,
    pub events_processed: u64,
    pub score:            ScoreSnapshot,
    pub summary:          DetectionSummary,
    pub detections:       Vec<Detection>,
}
