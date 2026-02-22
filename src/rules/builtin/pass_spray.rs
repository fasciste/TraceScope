use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const SPRAY_THRESHOLD: usize = 5;

pub struct PassSprayRule;

#[async_trait]
impl Rule for PassSprayRule {
    fn id(&self)          -> &str { "AUTH-SPRAY-001" }
    fn name(&self)        -> &str { "Password Spraying Attack" }
    fn description(&self) -> &str {
        "The same source IP attempted authentication against multiple distinct user accounts \
         within the correlation window. Unlike brute-force (many passwords, one user), \
         spraying uses one password against many accounts to evade lockout — MITRE T1110.003."
    }
    fn tags(&self) -> &[&'static str] {
        &["brute-force", "password-spraying", "credential-access", "T1110.003"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::LoginFailure {
            return Ok(None);
        }

        let src_ip = event
            .get_meta("source_ip")
            .or_else(|| event.get_meta("src_ip"))
            .unwrap_or("");

        if src_ip.is_empty() {
            return Ok(None);
        }

        let mut distinct_users: HashSet<&str> = HashSet::new();
        for e in &context.recent_events {
            if e.event_type != EventType::LoginFailure { continue; }
            let e_src = e.get_meta("source_ip")
                .or_else(|| e.get_meta("src_ip"))
                .unwrap_or("");
            if e_src != src_ip { continue; }
            if let Some(u) = e.get_meta("user") {
                distinct_users.insert(u);
            }
        }

        let n = distinct_users.len();
        if n < SPRAY_THRESHOLD || n % SPRAY_THRESHOLD != 0 {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Source IP {src_ip} failed authentication against {n} distinct accounts on '{host}'"),
                "Low-and-slow password spray pattern — one password tried across many accounts".to_owned(),
            ],
        );

        Ok(Some(detection))
    }
}
