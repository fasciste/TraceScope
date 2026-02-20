// Replay-safe: "now" is derived from the latest event timestamp seen,
// not wall clock — so forensic replays of historical data work correctly.
use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::trace;

use crate::domain::event::Event;

struct State {
    events:    VecDeque<Event>,
    // Running maximum of seen timestamps; None until the first event arrives.
    latest_ts: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct Correlator {
    inner:       Arc<RwLock<State>>,
    window_secs: i64,
}

impl Correlator {
    pub fn new(window_secs: i64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State {
                events:    VecDeque::new(),
                latest_ts: None,
            })),
            window_secs,
        }
    }

    pub async fn add(&self, event: Event) {
        let mut state = self.inner.write().await;

        // O(1) max update — avoids scanning the deque on every insert.
        state.latest_ts = Some(match state.latest_ts {
            Some(prev) => prev.max(event.timestamp),
            None       => event.timestamp,
        });

        state.events.push_back(event);
        self.evict_locked(&mut state);

        trace!(window_len = state.events.len(), "Correlator updated");
    }

    pub async fn get_context(&self, window_secs: i64) -> Vec<Event> {
        let state  = self.inner.read().await;
        let now    = state.latest_ts.unwrap_or_else(Utc::now);
        let cutoff = now - chrono::Duration::seconds(window_secs);
        state.events.iter()
            .filter(|e| e.timestamp >= cutoff)
            .cloned()
            .collect()
    }

    fn evict_locked(&self, state: &mut State) {
        let now    = state.latest_ts.unwrap_or_else(Utc::now);
        let cutoff = now - chrono::Duration::seconds(self.window_secs);
        while state.events.front().map(|e| e.timestamp < cutoff).unwrap_or(false) {
            state.events.pop_front();
        }
    }

    pub fn window_secs(&self) -> i64 { self.window_secs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::domain::event::{EventSource, EventType, Severity};

    fn make_event(offset_secs: i64) -> Event {
        let mut e = Event::new(
            EventSource::Mock,
            EventType::LoginFailure,
            Severity::Low,
            HashMap::new(),
        );
        e.timestamp = Utc::now() - chrono::Duration::seconds(offset_secs);
        e
    }

    #[tokio::test]
    async fn sliding_window_eviction() {
        let corr = Correlator::new(60);
        corr.add(make_event(120)).await;
        corr.add(make_event(10)).await;
        let ctx = corr.get_context(60).await;
        assert_eq!(ctx.len(), 1, "only the recent event should remain");
    }

    #[tokio::test]
    async fn all_events_in_window() {
        let corr = Correlator::new(300);
        for i in 0..5 {
            corr.add(make_event(i * 10)).await;
        }
        let ctx = corr.get_context(300).await;
        assert_eq!(ctx.len(), 5);
    }

    #[tokio::test]
    async fn latest_ts_cached_correctly() {
        let corr = Correlator::new(300);
        corr.add(make_event(50)).await;
        corr.add(make_event(10)).await;
        let ctx = corr.get_context(300).await;
        assert_eq!(ctx.len(), 2, "both events should be in window");
    }
}
