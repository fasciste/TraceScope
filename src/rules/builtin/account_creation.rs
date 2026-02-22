use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// These patterns alone indicate account creation.
static CREATE_PATTERNS: &[&str] = &[
    "new-localuser",
    "new-aduser",
    "dsadd user",
    "useradd",
    "adduser",
];

pub struct AccountCreationRule;

#[async_trait]
impl Rule for AccountCreationRule {
    fn id(&self)          -> &str { "ACCOUNT-CREATE-001" }
    fn name(&self)        -> &str { "Local or Domain Account Creation" }
    fn description(&self) -> &str {
        "A new user account was created via net user, PowerShell, or system utilities. \
         Account creation by non-privileged processes or in unusual contexts can indicate \
         persistence or attacker foothold establishment — MITRE T1136."
    }
    fn tags(&self) -> &[&'static str] {
        &["persistence", "account-creation", "T1136"]
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

        // "net user /add" requires both parts; the PS/Linux patterns are specific enough alone.
        let matched = CREATE_PATTERNS.iter().any(|&p| cmd.contains(p))
            || (cmd.contains("net user") && cmd.contains("/add"));

        if !matched {
            return Ok(None);
        }

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
                format!("Account creation command detected: {cmd}"),
                format!("Host: {host}  |  Executed by: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
