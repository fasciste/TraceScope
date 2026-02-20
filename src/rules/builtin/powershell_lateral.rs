/// Rule: PowerShell Lateral Movement
///
/// Pattern (MITRE T1059.001 + T1543.003):
///   ServiceInstallation  ← trigger
///   + ProcessCreation with "powershell" in cmd  (within window)
///   + NetworkConnection                         (within window)
///
/// Why trigger on ServiceInstallation?  The service creation is usually the
/// *last* step; by that time the PowerShell spawn and network connection are
/// already in the correlator window.
use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

pub struct PowerShellLateralRule;

#[async_trait]
impl Rule for PowerShellLateralRule {
    fn id(&self)          -> &str { "PS-LATERAL-001" }
    fn name(&self)        -> &str { "PowerShell Lateral Movement" }
    fn description(&self) -> &str {
        "PowerShell process creation correlated with outbound network connection \
         and service installation within the correlation window."
    }
    fn tags(&self) -> &[&'static str] {
        &["lateral-movement", "powershell", "T1059.001", "T1543.003"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        // Only trigger when we see a service installation.
        if event.event_type != EventType::ServiceInstallation {
            return Ok(None);
        }

        // Point-in-time lookup: only consider events that happened before
        // this service installation (guards against dispatcher race-ahead).
        let trigger_ts = &event.timestamp;

        let ps_event = context.recent_events.iter().find(|e| {
            e.event_type == EventType::ProcessCreation
                && &e.timestamp <= trigger_ts
                && e.get_meta("cmd")
                    .map(|c| c.to_lowercase().contains("powershell"))
                    .unwrap_or(false)
        });

        let Some(ps) = ps_event else { return Ok(None) };

        let net_event = context
            .recent_events
            .iter()
            .find(|e| e.event_type == EventType::NetworkConnection && &e.timestamp <= trigger_ts);

        let Some(net) = net_event else { return Ok(None) };

        let svc_name = event.get_meta("service_name").unwrap_or("unknown");
        let ps_cmd   = ps.get_meta("cmd").unwrap_or("powershell.exe");
        let dst_ip   = net.get_meta("dst_ip").unwrap_or("unknown");
        let dst_port = net.get_meta("dst_port").unwrap_or("?");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Critical,
            &[event, ps, net],
            Severity::Critical.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("PowerShell spawned: {ps_cmd}"),
                format!("Outbound connection to {dst_ip}:{dst_port}"),
                format!("Service installed: {svc_name}"),
            ],
        );

        Ok(Some(detection))
    }
}
