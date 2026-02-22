use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const SMB_THRESHOLD: usize = 3;

pub struct SmbLateralRule;

#[async_trait]
impl Rule for SmbLateralRule {
    fn id(&self)          -> &str { "NET-SMBLAT-001" }
    fn name(&self)        -> &str { "SMB Lateral Movement" }
    fn description(&self) -> &str {
        "The same host connected to multiple distinct SMB (port 445) targets within the \
         correlation window. Suggests lateral movement via SMB — file shares, remote service \
         installation, or PsExec-style execution — MITRE T1021.002."
    }
    fn tags(&self) -> &[&'static str] {
        &["lateral-movement", "smb", "T1021.002"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::NetworkConnection {
            return Ok(None);
        }

        let dst_port = event.get_meta("dst_port").unwrap_or("");
        if dst_port != "445" {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        let distinct_targets: HashSet<&str> = context.recent_events.iter()
            .filter(|e| {
                e.event_type == EventType::NetworkConnection
                    && e.get_meta("dst_port").unwrap_or("") == "445"
                    && e.get_meta("host").unwrap_or("") == host
            })
            .filter_map(|e| e.get_meta("dst_ip"))
            .collect();

        let n = distinct_targets.len();
        if n < SMB_THRESHOLD || n % SMB_THRESHOLD != 0 {
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
                format!("Host '{host}' made SMB connections to {n} distinct targets"),
                "Lateral movement via SMB — possible remote execution or file share access".to_owned(),
            ],
        );

        Ok(Some(detection))
    }
}
