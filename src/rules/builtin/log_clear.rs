use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static CLEAR_PATTERNS: &[&str] = &[
    "wevtutil cl",
    "wevtutil.exe cl",
    "wevtutil clg",
    "clear-eventlog",
    "remove-eventlog",
    "auditpol /clear",
    "auditpol.exe /clear",
    "fsutil usn deletejournal",
    "wevtutil sl",         // set-log — sometimes used to shrink log to 0
    "clearall-eventlog",
    "limit-eventlog",
];

pub struct LogClearRule;

#[async_trait]
impl Rule for LogClearRule {
    fn id(&self)          -> &str { "EXEC-LOGCLR-001" }
    fn name(&self)        -> &str { "Event Log Clearing" }
    fn description(&self) -> &str {
        "Windows event logs or audit policies were cleared — a common anti-forensics \
         technique to destroy evidence of prior activity — MITRE T1070.001."
    }
    fn tags(&self) -> &[&'static str] {
        &["defense-evasion", "indicator-removal", "T1070.001"]
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

        let matched = CLEAR_PATTERNS.iter().find(|&&p| cmd.contains(p));
        let Some(&pattern) = matched else { return Ok(None) };

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
                format!("Log-clearing pattern matched: '{pattern}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
