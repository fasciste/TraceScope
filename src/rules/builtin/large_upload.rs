use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// Fire on a single transfer exceeding this threshold (50 MB).
const SINGLE_THRESHOLD: u64 = 50_000_000;
// Fire when cumulative outbound from the same host crosses this threshold (500 MB).
const CUMUL_THRESHOLD: u64 = 500_000_000;

pub struct LargeUploadRule;

#[async_trait]
impl Rule for LargeUploadRule {
    fn id(&self)          -> &str { "NET-DATAXFR-001" }
    fn name(&self)        -> &str { "Large Outbound Data Transfer" }
    fn description(&self) -> &str {
        "An unusually large volume of data was sent outbound from a single host — \
         either in a single connection (>50 MB) or cumulatively within the window (>500 MB). \
         May indicate data exfiltration — MITRE T1048."
    }
    fn tags(&self) -> &[&'static str] {
        &["exfiltration", "large-transfer", "T1048"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::NetworkConnection {
            return Ok(None);
        }

        let bytes_str = event
            .get_meta("bytes_out")
            .or_else(|| event.get_meta("bytes_sent"))
            .unwrap_or("0");
        let bytes: u64 = bytes_str.parse().unwrap_or(0);
        if bytes == 0 {
            return Ok(None);
        }

        let host    = event.get_meta("host").unwrap_or("unknown");
        let dst_ip  = event.get_meta("dst_ip").unwrap_or("unknown");

        // Single large transfer.
        if bytes >= SINGLE_THRESHOLD {
            let mb = bytes / 1_000_000;
            return Ok(Some(Detection::new(
                self.id(), self.name(), self.description(),
                Severity::Medium, &[event], Severity::Medium.weight(),
                self.tags().iter().map(|s| s.to_string()).collect(),
                vec![
                    format!("Single outbound transfer of {mb} MB from '{host}' to {dst_ip}"),
                ],
            )));
        }

        // Cumulative threshold — fire when crossing a new multiple of CUMUL_THRESHOLD.
        let prev_cumul: u64 = context.recent_events.iter()
            .filter(|e| {
                e.id != event.id
                    && e.event_type == EventType::NetworkConnection
                    && e.get_meta("host").unwrap_or("") == host
            })
            .filter_map(|e| {
                e.get_meta("bytes_out")
                    .or_else(|| e.get_meta("bytes_sent"))?
                    .parse::<u64>().ok()
            })
            .sum();

        let now_cumul = prev_cumul + bytes;
        let crossed = now_cumul >= CUMUL_THRESHOLD
            && now_cumul / CUMUL_THRESHOLD > prev_cumul / CUMUL_THRESHOLD;

        if !crossed {
            return Ok(None);
        }

        let gb = now_cumul / 1_000_000_000;
        let mb = (now_cumul % 1_000_000_000) / 1_000_000;

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Cumulative outbound transfer from '{host}': {gb} GB {mb} MB in the window"),
            ],
        );

        Ok(Some(detection))
    }
}
