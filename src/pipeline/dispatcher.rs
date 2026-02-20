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

    // When this future returns, event_tx is dropped → broadcast closes →
    // rule engines receive RecvError::Closed and shut down gracefully.
    pub async fn run(&self, mut norm_rx: mpsc::Receiver<Event>) {
        let mut dispatched = 0u64;

        while let Some(event) = norm_rx.recv().await {
            trace!(event_id = %event.id, event_type = ?event.event_type, "Dispatching");

            self.correlator.add(event.clone()).await;

            if let Err(e) = self.event_tx.send(event) {
                warn!(error = %e, "Broadcast send failed (no subscribers?)");
            }

            dispatched += 1;
        }

        debug!(dispatched, "Dispatcher finished — closing broadcast channel");
    }
}
