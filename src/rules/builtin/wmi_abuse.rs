use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static WMI_TOOLS: &[&str] = &[
    "wmic",
    "invoke-wmimethod",
    "get-wmiobject",
    "invoke-cimmethod",
    "new-cimsession",
    "wbemtest",
];

// Sub-patterns that indicate execution or lateral movement intent.
static WMI_EXEC_SUBS: &[&str] = &[
    "process call create",
    "shadowcopy delete",
    "/node:",
    "win32_process",
    "invoke-wmimethod",
    "invoke-cimmethod",
];

pub struct WmiAbuseRule;

#[async_trait]
impl Rule for WmiAbuseRule {
    fn id(&self)          -> &str { "SUSP-WMI-001" }
    fn name(&self)        -> &str { "WMI Abuse for Execution or Lateral Movement" }
    fn description(&self) -> &str {
        "WMI (Windows Management Instrumentation) used for remote process creation, \
         shadow copy deletion, or lateral movement — MITRE T1047."
    }
    fn tags(&self) -> &[&'static str] {
        &["wmi", "execution", "lateral-movement", "T1047"]
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

        if !WMI_TOOLS.iter().any(|&t| cmd.contains(t)) {
            return Ok(None);
        }

        let matched_sub = WMI_EXEC_SUBS.iter().find(|&&s| cmd.contains(s));
        let Some(&sub) = matched_sub else { return Ok(None) };

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
                format!("WMI execution sub-command detected: '{sub}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
