use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const THRESHOLD: usize = 5;

pub struct BruteForceRule;

#[async_trait]
impl Rule for BruteForceRule {
    fn id(&self)          -> &str { "AUTH-BRUTE-001" }
    fn name(&self)        -> &str { "Brute Force Authentication Attack" }
    fn description(&self) -> &str {
        "Multiple authentication failures from the same source host within \
         a short time window indicate a credential brute-force attempt."
    }
    fn tags(&self) -> &[&'static str] {
        &["brute-force", "authentication", "T1110"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::LoginFailure {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        let failure_count = context.count_where_before(
            &EventType::LoginFailure,
            "host",
            host,
            &event.timestamp,
        );

        // Fire at threshold boundaries to suppress repeated alerts.
        if failure_count < THRESHOLD || failure_count % THRESHOLD != 0 {
            return Ok(None);
        }

        let src_ip = event.get_meta("source_ip")
            .or_else(|| event.get_meta("src_ip"))
            .unwrap_or("unknown");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("{failure_count} failed login attempts against host '{host}' from {src_ip}"),
            ],
        );

        Ok(Some(detection))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::domain::event::EventSource;

    fn login_failure(host: &str) -> Event {
        let mut meta = HashMap::new();
        meta.insert("host".into(), host.into());
        meta.insert("source_ip".into(), "10.0.0.99".into());
        Event::new(EventSource::Mock, EventType::LoginFailure, Severity::Low, meta)
    }

    #[tokio::test]
    async fn fires_at_threshold() {
        let rule    = BruteForceRule;
        let events: Vec<Event> = (0..5).map(|_| login_failure("SRV01")).collect();
        let trigger = events.last().unwrap().clone();
        let ctx     = RuleContext::new(events.clone(), 60);
        let result  = rule.evaluate(&trigger, &ctx).await.unwrap();
        assert!(result.is_some(), "should fire at exactly 5 failures");
    }

    #[tokio::test]
    async fn no_fire_below_threshold() {
        let rule    = BruteForceRule;
        let events: Vec<Event> = (0..4).map(|_| login_failure("SRV01")).collect();
        let trigger = events.last().unwrap().clone();
        let ctx     = RuleContext::new(events.clone(), 60);
        let result  = rule.evaluate(&trigger, &ctx).await.unwrap();
        assert!(result.is_none(), "should not fire with < 5 failures");
    }

    #[tokio::test]
    async fn different_host_no_fire() {
        let rule    = BruteForceRule;
        let events: Vec<Event> = (0..5).map(|_| login_failure("SRV01")).collect();
        let trigger = login_failure("SRV02");
        let ctx     = RuleContext::new(events, 60);
        let result  = rule.evaluate(&trigger, &ctx).await.unwrap();
        assert!(result.is_none());
    }
}
