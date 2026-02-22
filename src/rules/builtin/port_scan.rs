use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const PORT_SCAN_THRESHOLD: usize = 15;

pub struct PortScanRule;

#[async_trait]
impl Rule for PortScanRule {
    fn id(&self)          -> &str { "NET-PORTSCAN-001" }
    fn name(&self)        -> &str { "Port Scan Detected" }
    fn description(&self) -> &str {
        "A single host connected to an unusually high number of distinct destination \
         ports within the correlation window, indicating a network port scan — MITRE T1046."
    }
    fn tags(&self) -> &[&'static str] {
        &["port-scan", "discovery", "T1046"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::NetworkConnection {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        let distinct_ports: HashSet<&str> = context.recent_events.iter()
            .filter(|e| {
                e.event_type == EventType::NetworkConnection
                    && e.get_meta("host").unwrap_or("") == host
            })
            .filter_map(|e| e.get_meta("dst_port"))
            .collect();

        let n = distinct_ports.len();
        if n < PORT_SCAN_THRESHOLD || n % PORT_SCAN_THRESHOLD != 0 {
            return Ok(None);
        }

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Medium,
            &[event],
            Severity::Medium.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Host '{host}' probed {n} distinct destination ports in the correlation window"),
            ],
        );

        Ok(Some(detection))
    }
}
