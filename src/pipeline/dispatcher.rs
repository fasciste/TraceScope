/// Dispatcher: fan-out hub between normaliser and rule engines.
///
/// For each normalised event it:
///   1. Appends to the `Correlator` sliding window (shared, Arc).
///   2. Broadcasts to all rule-engine subscribers via `broadcast::Sender`.
///
/// The broadcast channel is bounded (capacity = 1024).  If a rule engine falls
/// behind, `RecvError::Lagged` is returned to it — the engine logs a warning
/// and continues, favouring throughput over guaranteed delivery of every event
/// to slow consumers.
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tracing::{debug, trace, warn};

use crate::domain::event::Event;
use super::correlator::Correlator;

pub struct Dispatcher {
    correlator: Arc<Correlator>,
    event_tx:   broadcast::Sender<Event>,
}

impl Dispatcher {
    pub fn new(correlator: Arc<Correlator>, event_tx: broadcast::Sender<Event>) -> Self {
        Self { correlator, event_tx }
    }

    /// Consume events from `norm_rx` until the channel closes.
    ///
    /// When this future completes, `event_tx` is dropped, which sends a
    /// `RecvError::Closed` to all rule-engine receivers — triggering their
    /// graceful shutdown.
    pub async fn run(&self, mut norm_rx: mpsc::Receiver<Event>) {
        let mut dispatched = 0u64;

        while let Some(event) = norm_rx.recv().await {
            trace!(event_id = %event.id, event_type = ?event.event_type, "Dispatching");

            // 1. Update sliding window (write lock, brief).
            self.correlator.add(event.clone()).await;

            // 2. Broadcast — ignore error if no subscribers yet.
            if let Err(e) = self.event_tx.send(event) {
                warn!(error = %e, "Broadcast send failed (no subscribers?)");
            }

            dispatched += 1;
        }

        debug!(dispatched, "Dispatcher finished — closing broadcast channel");
        // `event_tx` is dropped here → rule engines see RecvError::Closed.
    }
}
