use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const FAIL_THRESHOLD: usize = 3;

pub struct SuccAfterFailRule;

#[async_trait]
impl Rule for SuccAfterFailRule {
    fn id(&self)          -> &str { "AUTH-SFBRUTE-001" }
    fn name(&self)        -> &str { "Successful Login After Multiple Failures" }
    fn description(&self) -> &str {
        "A successful authentication was preceded by multiple failed attempts from \
         the same source IP against the same host. Indicates a successful brute-force \
         or credential-stuffing attack — MITRE T1110."
    }
    fn tags(&self) -> &[&'static str] {
        &["brute-force", "credential-access", "T1110"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::LoginSuccess {
            return Ok(None);
        }

        let host   = event.get_meta("host").unwrap_or("unknown");
        let src_ip = event
            .get_meta("source_ip")
            .or_else(|| event.get_meta("src_ip"))
            .unwrap_or("");
        let user   = event.get_meta("user").unwrap_or("unknown");

        if src_ip.is_empty() {
            return Ok(None);
        }

        let fail_count = context.recent_events.iter().filter(|e| {
            if e.event_type != EventType::LoginFailure { return false; }
            if e.get_meta("host").unwrap_or("") != host { return false; }
            let e_src = e.get_meta("source_ip")
                .or_else(|| e.get_meta("src_ip"))
                .unwrap_or("");
            e_src == src_ip
        }).count();

        if fail_count < FAIL_THRESHOLD {
            return Ok(None);
        }

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Login SUCCESS for '{user}' on '{host}' after {fail_count} failures from {src_ip}"),
                "Source IP had repeated authentication failures before succeeding".to_owned(),
            ],
        );

        Ok(Some(detection))
    }
}
