/// Sliding-window event correlator.
///
/// Stores a bounded, time-ordered deque of recent `Event`s protected by a
/// `tokio::sync::RwLock`.  Multiple readers (rule engines) can hold read
/// locks concurrently; a single writer (dispatcher) appends and evicts.
///
/// **Replay-safe**: the "now" reference is derived from the *most recent event
/// timestamp* seen so far (cached in `State.latest_ts`), not from `Utc::now()`.
/// This means the correlator works correctly for both live ingestion AND
/// forensic replay of historical data (e.g. EVTX files from 2024 ingested
/// in 2026).
///
/// **Optimized**: `latest_ts` is cached as a running maximum and updated in
/// O(1) per insertion, replacing the previous O(n) full-scan approach.
use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::trace;

use crate::domain::event::Event;

// ─── Internal state ───────────────────────────────────────────────────────────

/// All mutable state held inside a single `RwLock`, allowing the cached
/// `latest_ts` to be updated atomically with the event deque.
struct State {
    events:    VecDeque<Event>,
    /// Running maximum of all event timestamps seen so far.
    /// `None` until the first event arrives.
    latest_ts: Option<DateTime<Utc>>,
}

// ─── Correlator ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Correlator {
    inner:       Arc<RwLock<State>>,
    window_secs: i64,
}

impl Correlator {
    /// Create a correlator with a `window_secs` retention window.
    pub fn new(window_secs: i64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State {
                events:    VecDeque::new(),
                latest_ts: None,
            })),
            window_secs,
        }
    }

    /// Append an event and evict any events older than the window.
    ///
    /// `latest_ts` is updated in O(1) as a running maximum — no full-deque
    /// scan required.  Called by the `Dispatcher` before broadcasting.
    pub async fn add(&self, event: Event) {
        let mut state = self.inner.write().await;

        // O(1) update: compare against cached maximum.
        state.latest_ts = Some(match state.latest_ts {
            Some(prev) => prev.max(event.timestamp),
            None       => event.timestamp,
        });

        state.events.push_back(event);
        self.evict_locked(&mut state);

        trace!(window_len = state.events.len(), "Correlator updated");
    }

    /// Return all events within the last `window_secs` seconds.
    ///
    /// Uses the cached `latest_ts` (O(1)) as the reference "now".
    /// Falls back to `Utc::now()` when the deque is empty (no events yet).
    pub async fn get_context(&self, window_secs: i64) -> Vec<Event> {
        let state  = self.inner.read().await;
        let now    = state.latest_ts.unwrap_or_else(Utc::now);
        let cutoff = now - chrono::Duration::seconds(window_secs);
        state.events.iter()
            .filter(|e| e.timestamp >= cutoff)
            .cloned()
            .collect()
    }

    /// Evict events that have fallen outside the window.
    /// Must be called while holding the write lock.
    fn evict_locked(&self, state: &mut State) {
        let now    = state.latest_ts.unwrap_or_else(Utc::now);
        let cutoff = now - chrono::Duration::seconds(self.window_secs);
        while state.events.front().map(|e| e.timestamp < cutoff).unwrap_or(false) {
            state.events.pop_front();
        }
    }

    pub fn window_secs(&self) -> i64 { self.window_secs }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

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

        // Add an event from 120 seconds ago — should be evicted.
        corr.add(make_event(120)).await;
        // Add a recent event — should be retained.
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

        // Insert in reverse chronological order.
        corr.add(make_event(50)).await;  // older
        corr.add(make_event(10)).await;  // newer

        // Both should be retained (both within 300s window).
        let ctx = corr.get_context(300).await;
        assert_eq!(ctx.len(), 2, "both events should be in window");
    }
}
