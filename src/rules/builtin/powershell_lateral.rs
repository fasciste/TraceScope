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
        if event.event_type != EventType::ServiceInstallation {
            return Ok(None);
        }

        // Look for any PowerShell process and network connection anywhere in
        // the correlation window — event order doesn't matter for forensic replay.
        let ps_event = context.recent_events.iter().find(|e| {
            e.event_type == EventType::ProcessCreation && {
                let c = e.get_meta("cmd").unwrap_or("").to_lowercase();
                c.contains("powershell") || c.contains("pwsh")
            }
        });

        let Some(ps) = ps_event else { return Ok(None) };

        let net_event = context.recent_events.iter()
            .find(|e| e.event_type == EventType::NetworkConnection);

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
