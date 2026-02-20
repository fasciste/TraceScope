use async_trait::async_trait;
use anyhow::Result;
use chrono::{DateTime, Utc};

use super::detection::Detection;
use super::event::{Event, EventType};

// ─── Rule trait ───────────────────────────────────────────────────────────────

/// An async, concurrent-safe detection rule.
///
/// Each rule receives the triggering event and a sliding-window context of
/// recent events. Implementations should be stateless; all temporal state
/// lives in the `Correlator`.
#[async_trait]
pub trait Rule: Send + Sync + 'static {
    fn id(&self)          -> &str;
    fn name(&self)        -> &str;
    fn description(&self) -> &str;
    fn tags(&self)        -> &[&'static str] { &[] }

    async fn evaluate(
        &self,
        event:   &Event,
        context: &RuleContext,
    ) -> Result<Option<Detection>>;
}

// ─── RuleContext ──────────────────────────────────────────────────────────────

/// Sliding-window snapshot delivered to each rule during evaluation.
///
/// Built from the `Correlator` at evaluation time; cloning is O(n events)
/// but events themselves are cheap to clone (Arc metadata).
#[derive(Clone)]
pub struct RuleContext {
    /// All events currently in the correlation window.
    pub recent_events: Vec<Event>,
    /// Duration of the window (seconds).
    pub window_secs: i64,
}

impl RuleContext {
    pub fn new(recent_events: Vec<Event>, window_secs: i64) -> Self {
        Self { recent_events, window_secs }
    }

    /// `true` if any event in the window matches `event_type`.
    pub fn has_event_type(&self, event_type: &EventType) -> bool {
        self.recent_events.iter().any(|e| &e.event_type == event_type)
    }

    /// Iterator over events matching `event_type`.
    pub fn events_of_type<'a>(
        &'a self,
        event_type: &'a EventType,
    ) -> impl Iterator<Item = &'a Event> {
        self.recent_events.iter().filter(move |e| &e.event_type == event_type)
    }

    /// Count events of a given type where `metadata[key] == value`.
    pub fn count_where(
        &self,
        event_type: &EventType,
        key:        &str,
        value:      &str,
    ) -> usize {
        self.recent_events.iter().filter(|e| {
            e.event_type == *event_type
                && e.get_meta(key).unwrap_or("") == value
        }).count()
    }

    /// Point-in-time count: like `count_where` but only considers events
    /// whose timestamp is ≤ `before`.
    ///
    /// This prevents false positives caused by the dispatcher racing ahead of
    /// the rule engine and filling the correlator with future events.
    pub fn count_where_before(
        &self,
        event_type: &EventType,
        key:        &str,
        value:      &str,
        before:     &DateTime<Utc>,
    ) -> usize {
        self.recent_events.iter().filter(|e| {
            e.event_type == *event_type
                && e.get_meta(key).unwrap_or("") == value
                && &e.timestamp <= before
        }).count()
    }

    /// Point-in-time presence check: does any event of `event_type` exist
    /// with timestamp ≤ `before`?
    pub fn has_event_type_before(
        &self,
        event_type: &EventType,
        before:     &DateTime<Utc>,
    ) -> bool {
        self.recent_events.iter().any(|e| {
            &e.event_type == event_type && &e.timestamp <= before
        })
    }
}
