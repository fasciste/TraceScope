/// Rule: DNS Tunneling / Exfiltration
///
/// Pattern (MITRE T1071.004):
///   • High-frequency DnsQuery events (≥ 10) from the same host within the
///     correlation window — consistent with a DNS-based C2 beacon loop.
///   • A single DnsQuery whose name exceeds 40 characters — typical of base64
///     or hex-encoded payloads stuffed into subdomain labels.
///
/// Fires on threshold boundaries to avoid duplicate detections on streaming data.
use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const FREQ_THRESHOLD: usize = 10;
const LEN_THRESHOLD:  usize = 40;

pub struct DnsTunnelingRule;

#[async_trait]
impl Rule for DnsTunnelingRule {
    fn id(&self)          -> &str { "DNS-TUNNEL-001" }
    fn name(&self)        -> &str { "DNS Tunneling / Exfiltration" }
    fn description(&self) -> &str {
        "High-frequency DNS queries or unusually long query names indicate \
         potential DNS tunneling for C2 communication or data exfiltration."
    }
    fn tags(&self) -> &[&'static str] {
        &["dns-tunneling", "exfiltration", "c2", "T1071.004"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::DnsQuery {
            return Ok(None);
        }

        let trigger_ts = &event.timestamp;
        let query_name = event
            .get_meta("query")
            .or_else(|| event.get_meta("name"))
            .unwrap_or("");
        let host = event.get_meta("host").unwrap_or("unknown");

        // ── Indicator 1: suspiciously long query name (encoded payload) ──────
        let long_query = query_name.len() > LEN_THRESHOLD;

        // ── Indicator 2: high-frequency beacon pattern ───────────────────────
        let dns_count = context.count_where_before(
            &EventType::DnsQuery,
            "host",
            host,
            trigger_ts,
        );
        let high_freq = dns_count >= FREQ_THRESHOLD;

        if !long_query && !high_freq {
            return Ok(None);
        }

        // For high-frequency: only fire on threshold boundaries.
        if high_freq && !long_query && dns_count % FREQ_THRESHOLD != 0 {
            return Ok(None);
        }

        let resolver = event
            .get_meta("dst_ip")
            .or_else(|| event.get_meta("resolver"))
            .unwrap_or("unknown");

        let mut evidence = Vec::new();
        if high_freq {
            evidence.push(format!(
                "{dns_count} DNS queries from host '{host}' within the correlation window"
            ));
        }
        if long_query {
            let truncated: String = query_name.chars().take(80).collect();
            evidence.push(format!(
                "Long DNS query name ({} chars): {truncated}",
                query_name.len()
            ));
        }
        evidence.push(format!("Resolver: {resolver}"));

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            evidence,
        );

        Ok(Some(detection))
    }
}
