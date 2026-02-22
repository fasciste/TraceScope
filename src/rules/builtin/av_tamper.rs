use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// Security services targeted by attackers trying to blind defenses.
static AV_SERVICES: &[&str] = &[
    "windefend", "wscsvc", "wdnissvc", "sense", "mssense",
    "avast", "avg", "mfefire", "mcshield", "sophos",
    "carbonblack", "cbdefense", "cylance", "crowdstrike",
    "sentinelone", "epp", "sysmon",
];

// PowerShell/registry-based AV disabling that doesn't go through service control.
static DISABLE_PATTERNS: &[&str] = &[
    "set-mppreference",
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableonaccess",
    "disableioavprotection",
    "add-mppreference -exclusionpath",
    "add-mppreference -exclusionextension",
    "disableantispyware",
];

pub struct AvTamperRule;

#[async_trait]
impl Rule for AvTamperRule {
    fn id(&self)          -> &str { "EXEC-AVDEF-001" }
    fn name(&self)        -> &str { "Security Tool Tampering" }
    fn description(&self) -> &str {
        "A security service (AV, EDR, Sysmon) was stopped, disabled, or excluded \
         from monitoring. Attackers disable defenses before executing payloads — MITRE T1562."
    }
    fn tags(&self) -> &[&'static str] {
        &["defense-evasion", "impair-defenses", "T1562"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        if !matches!(event.event_type, EventType::ProcessCreation | EventType::CommandExecution) {
            return Ok(None);
        }

        let cmd = event
            .get_meta("cmd")
            .or_else(|| event.get_meta("command_line"))
            .unwrap_or("")
            .to_lowercase();

        // Direct PowerShell/reg-based disabling (no service name needed).
        if let Some(&pattern) = DISABLE_PATTERNS.iter().find(|&&p| cmd.contains(p)) {
            let host = event.get_meta("host").unwrap_or("unknown");
            let user = event.get_meta("user").unwrap_or("unknown");
            return Ok(Some(Detection::new(
                self.id(), self.name(), self.description(),
                Severity::High, &[event], Severity::High.weight(),
                self.tags().iter().map(|s| s.to_string()).collect(),
                vec![
                    format!("AV/EDR disabling cmdlet detected: '{pattern}'"),
                    format!("Command: {cmd}"),
                    format!("Host: {host}  |  User: {user}"),
                ],
            )));
        }

        // Service stop/disable targeting a known security service.
        let is_service_action = cmd.contains("net stop")
            || cmd.contains("sc stop")
            || cmd.contains("sc config")
            || cmd.contains("sc delete")
            || cmd.contains("taskkill");

        if !is_service_action {
            return Ok(None);
        }

        let matched_svc = AV_SERVICES.iter().find(|&&svc| cmd.contains(svc));
        let Some(&service) = matched_svc else { return Ok(None) };

        let host = event.get_meta("host").unwrap_or("unknown");
        let user = event.get_meta("user").unwrap_or("unknown");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Security service '{service}' stopped or disabled"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
