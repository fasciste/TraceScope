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

    pub async fn run(mut self) {
        info!(rules = self.rules.len(), "Rule engine started");
        let mut evaluated = 0u64;

        loop {
            use broadcast::error::RecvError;

            let event = match self.event_rx.recv().await {
                Ok(e)                    => e,
                Err(RecvError::Lagged(n)) => {
                    warn!(skipped = n, "Rule engine lagged — some events dropped");
                    continue;
                }
                Err(RecvError::Closed) => break,
            };

            let recent  = self.correlator.get_context(self.correlator.window_secs()).await;
            let context = RuleContext::new(recent, self.correlator.window_secs());

            // Evaluate all rules concurrently for this event.
            let mut join_set: JoinSet<Option<Detection>> = JoinSet::new();
            for rule in &self.rules {
                let rule = Arc::clone(rule);
                let ev   = event.clone();
                let ctx  = context.clone();
                join_set.spawn(async move {
                    match rule.evaluate(&ev, &ctx).await {
                        Ok(opt) => opt,
                        Err(e)  => {
                            warn!(rule = rule.id(), error = %e, "Rule evaluation error");
                            None
                        }
                    }
                });
            }

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Some(detection)) => {
                        info!(
                            rule  = detection.rule_name,
                            sev   = %detection.severity,
                            score = detection.score_contribution,
                            "Detection fired"
                        );
                        if self.detection_tx.send(detection).await.is_err() {
                            debug!("Detection channel closed");
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(e)   => warn!(error = %e, "Rule task panicked"),
                }
            }

            evaluated += 1;
        }

        debug!(evaluated, "Rule engine finished");
    }
}
