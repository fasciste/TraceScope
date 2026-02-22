use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const THRESHOLD: usize = 5;

// Commands routinely run during attacker enumeration/reconnaissance.
static DISCOVERY_CMDS: &[&str] = &[
    "whoami",
    "ipconfig",
    "ifconfig",
    "arp ",
    "route print",
    "netstat",
    "systeminfo",
    "nltest",
    "net user",
    "net group",
    "net localgroup",
    "net view",
    "net session",
    "net accounts",
    "tasklist",
    "qwinsta",
    "quser",
    "query user",
    "query session",
    "nslookup",
    "dsquery",
    "dsget",
    "get-aduser",
    "get-adgroup",
    "get-adcomputer",
    "get-netdomaintrust",
    "get-netforest",
    "invoke-sharefinder",
    "wmic os get",
    "wmic useraccount",
    "wmic computersystem",
];

pub struct SysDiscoveryRule;

#[async_trait]
impl Rule for SysDiscoveryRule {
    fn id(&self)          -> &str { "EXEC-RECON-001" }
    fn name(&self)        -> &str { "System / Network Discovery Burst" }
    fn description(&self) -> &str {
        "Multiple system or network enumeration commands (whoami, ipconfig, net user, \
         nltest, etc.) from the same host within the correlation window — indicates \
         an attacker performing rapid environment reconnaissance — MITRE T1082 / T1016."
    }
    fn tags(&self) -> &[&'static str] {
        &["discovery", "reconnaissance", "T1082", "T1016"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if !matches!(event.event_type, EventType::ProcessCreation | EventType::CommandExecution) {
            return Ok(None);
        }

        let cmd = event
            .get_meta("cmd")
            .or_else(|| event.get_meta("command_line"))
            .unwrap_or("")
            .to_lowercase();

        // Only continue if this event itself is a discovery command.
        if !DISCOVERY_CMDS.iter().any(|&d| cmd.contains(d)) {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        // Count all discovery commands from this host in the window.
        let count = context.recent_events.iter().filter(|e| {
            if !matches!(e.event_type, EventType::ProcessCreation | EventType::CommandExecution) {
                return false;
            }
            if e.get_meta("host").unwrap_or("") != host {
                return false;
            }
            let c = e.get_meta("cmd").unwrap_or("").to_lowercase();
            DISCOVERY_CMDS.iter().any(|&d| c.contains(d))
        }).count();

        if count < THRESHOLD || count % THRESHOLD != 0 {
            return Ok(None);
        }

        let user = event.get_meta("user").unwrap_or("unknown");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Medium,
            &[event],
            Severity::Medium.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("{count} discovery commands executed from host '{host}'"),
                format!("Latest: {cmd}"),
                format!("User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
