use async_trait::async_trait;
use anyhow::Result;
use chrono::{DateTime, Utc};

use super::detection::Detection;
use super::event::{Event, EventType};

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

// Snapshot of the sliding window delivered to each rule at evaluation time.
#[derive(Clone)]
pub struct RuleContext {
    pub recent_events: Vec<Event>,
    pub window_secs:   i64,
}

impl RuleContext {
    pub fn new(recent_events: Vec<Event>, window_secs: i64) -> Self {
        Self { recent_events, window_secs }
    }

    pub fn has_event_type(&self, event_type: &EventType) -> bool {
        self.recent_events.iter().any(|e| &e.event_type == event_type)
    }

    pub fn events_of_type<'a>(
        &'a self,
        event_type: &'a EventType,
    ) -> impl Iterator<Item = &'a Event> {
        self.recent_events.iter().filter(move |e| &e.event_type == event_type)
    }

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

    // Point-in-time variant: only counts events with timestamp <= `before`.
    // Used to avoid false positives when the dispatcher races ahead of the rule engine.
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
