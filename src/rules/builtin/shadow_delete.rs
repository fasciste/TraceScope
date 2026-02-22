use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static SHADOW_INDICATORS: &[&str] = &[
    "delete shadows",
    "delete shadow ",
    "shadowcopy delete",
    "vssadmin delete",
    "wbadmin delete catalog",
    "resize shadowstorage",
];

pub struct ShadowDeleteRule;

#[async_trait]
impl Rule for ShadowDeleteRule {
    fn id(&self)          -> &str { "EXEC-SHADOW-001" }
    fn name(&self)        -> &str { "Shadow Copy / Backup Deletion" }
    fn description(&self) -> &str {
        "Deletion or modification of shadow copies and system backups — \
         a critical pre-ransomware step that prevents recovery — MITRE T1490."
    }
    fn tags(&self) -> &[&'static str] {
        &["ransomware", "defense-evasion", "inhibit-recovery", "T1490"]
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

        // vssadmin/wmic shadow deletion
        let matched_shadow = SHADOW_INDICATORS.iter().find(|&&ind| cmd.contains(ind));
        // bcdedit disabling recovery
        let bcdedit_disable = cmd.contains("bcdedit") && cmd.contains("recoveryenabled");

        if matched_shadow.is_none() && !bcdedit_disable {
            return Ok(None);
        }

        let host      = event.get_meta("host").unwrap_or("unknown");
        let user      = event.get_meta("user").unwrap_or("unknown");
        let indicator = matched_shadow.copied()
            .unwrap_or("bcdedit recoveryenabled no");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Critical,
            &[event],
            Severity::Critical.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Backup-inhibit indicator: '{indicator}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
