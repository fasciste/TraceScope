/// Async, concurrent rule evaluation engine.
///
/// Subscribes to the `broadcast::Receiver<Event>` emitted by the Dispatcher.
/// For each received event it spawns one `tokio` task per rule (via
/// `JoinSet`), evaluates them concurrently, and forwards any resulting
/// `Detection`s to the output channel.
///
/// Backpressure: detection channel is bounded (256).  If the output sink is
/// saturated, rule tasks are naturally slowed down through `send().await`.
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::domain::detection::Detection;
use crate::domain::rule::{Rule, RuleContext};
use crate::pipeline::correlator::Correlator;

pub struct RuleEngine {
    rules:        Vec<Arc<dyn Rule>>,
    correlator:   Arc<Correlator>,
    event_rx:     broadcast::Receiver<crate::domain::event::Event>,
    detection_tx: mpsc::Sender<Detection>,
}

impl RuleEngine {
    pub fn new(
        rules:        Vec<Arc<dyn Rule>>,
        correlator:   Arc<Correlator>,
        event_rx:     broadcast::Receiver<crate::domain::event::Event>,
        detection_tx: mpsc::Sender<Detection>,
    ) -> Self {
        Self { rules, correlator, event_rx, detection_tx }
    }

    /// Run until the broadcast channel closes.
    pub async fn run(mut self) {
        info!(rules = self.rules.len(), "Rule engine started");
        let mut evaluated = 0u64;

        loop {
            use broadcast::error::RecvError;

            let event = match self.event_rx.recv().await {
                Ok(e)                   => e,
                Err(RecvError::Lagged(n)) => {
                    warn!(skipped = n, "Rule engine lagged — some events dropped");
                    continue;
                }
                Err(RecvError::Closed) => break,
            };

            // Build context snapshot for this evaluation cycle.
            let recent   = self.correlator.get_context(self.correlator.window_secs()).await;
            let context  = RuleContext::new(recent, self.correlator.window_secs());

            // Spawn one task per rule — fully concurrent evaluation.
            let mut join_set: JoinSet<Option<Detection>> = JoinSet::new();

            for rule in &self.rules {
                let rule    = Arc::clone(rule);
                let ev      = event.clone();
                let ctx     = context.clone();

                join_set.spawn(async move {
                    match rule.evaluate(&ev, &ctx).await {
                        Ok(opt)  => opt,
                        Err(e)   => {
                            warn!(rule = rule.id(), error = %e, "Rule evaluation error");
                            None
                        }
                    }
                });
            }

            // Collect detections from all concurrent tasks.
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Some(detection)) => {
                        info!(
                            rule   = detection.rule_name,
                            sev    = %detection.severity,
                            score  = detection.score_contribution,
                            "Detection fired"
                        );
                        if self.detection_tx.send(detection).await.is_err() {
                            debug!("Detection channel closed");
                            return;
                        }
                    }
                    Ok(None)  => {}
                    Err(e)    => warn!(error = %e, "Rule task panicked"),
                }
            }

            evaluated += 1;
        }

        debug!(evaluated, "Rule engine finished");
    }
}
