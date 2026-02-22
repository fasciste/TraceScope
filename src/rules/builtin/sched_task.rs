use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static SCHED_TOOLS: &[&str] = &[
    "schtasks",
    "new-scheduledtask",
    "register-scheduledtask",
    "at.exe",
    "taskschd",
];

// Must also contain a creation/modification sub-command to reduce noise.
static CREATE_SUBS: &[&str] = &[
    "/create",
    "/change",
    "-action",
    "-trigger",
    "-repetitioninterval",
];

pub struct SchedTaskRule;

#[async_trait]
impl Rule for SchedTaskRule {
    fn id(&self)          -> &str { "SUSP-SCHTASK-001" }
    fn name(&self)        -> &str { "Suspicious Scheduled Task Creation" }
    fn description(&self) -> &str {
        "A new scheduled task or job was created or modified via schtasks.exe or \
         PowerShell task cmdlets, a common persistence and execution technique — MITRE T1053."
    }
    fn tags(&self) -> &[&'static str] {
        &["persistence", "scheduled-task", "T1053"]
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

        if !SCHED_TOOLS.iter().any(|&p| cmd.contains(p)) {
            return Ok(None);
        }

        if !CREATE_SUBS.iter().any(|&p| cmd.contains(p)) {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");
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
                format!("Scheduled task created/modified: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
