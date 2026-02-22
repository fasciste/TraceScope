use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const BEACON_THRESHOLD: usize = 8;

pub struct C2BeaconRule;

#[async_trait]
impl Rule for C2BeaconRule {
    fn id(&self)          -> &str { "NET-BEACON-001" }
    fn name(&self)        -> &str { "C2 Beaconing Pattern" }
    fn description(&self) -> &str {
        "The same host repeatedly connects to the same destination IP within \
         the correlation window, suggesting automated C2 check-in beaconing \
         behavior — MITRE T1071."
    }
    fn tags(&self) -> &[&'static str] {
        &["c2", "beaconing", "command-and-control", "T1071"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::NetworkConnection {
            return Ok(None);
        }

        let host   = event.get_meta("host").unwrap_or("unknown");
        let dst_ip = event.get_meta("dst_ip").unwrap_or("");
        if dst_ip.is_empty() {
            return Ok(None);
        }

        let count = context.recent_events.iter().filter(|e| {
            e.event_type == EventType::NetworkConnection
                && e.get_meta("host").unwrap_or("") == host
                && e.get_meta("dst_ip").unwrap_or("") == dst_ip
        }).count();

        if count < BEACON_THRESHOLD || count % BEACON_THRESHOLD != 0 {
            return Ok(None);
        }

        let dst_port = event.get_meta("dst_port").unwrap_or("?");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Medium,
            &[event],
            Severity::Medium.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("{count} connections from '{host}' to {dst_ip}:{dst_port} in the correlation window"),
                "Regular repeated connections suggest automated C2 beaconing".to_owned(),
            ],
        );

        Ok(Some(detection))
    }
}
