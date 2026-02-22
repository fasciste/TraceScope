use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static PSEXEC_CMD_INDICATORS: &[&str] = &[
    "psexec",
    "psexec64",
    "paexec",
    "remcom",
    "csexec",
];

static PSEXEC_SERVICE_NAMES: &[&str] = &[
    "psexesvc",
    "paexecsvc",
    "remcomsvc",
];

pub struct PsexecRule;

#[async_trait]
impl Rule for PsexecRule {
    fn id(&self)          -> &str { "EXEC-PSEXEC-001" }
    fn name(&self)        -> &str { "PsExec / Remote Execution Tool" }
    fn description(&self) -> &str {
        "PsExec or equivalent remote execution tool detected via command line, parent \
         process, or service name. Commonly used for lateral movement in Windows \
         environments — MITRE T1570 / T1021.002."
    }
    fn tags(&self) -> &[&'static str] {
        &["lateral-movement", "psexec", "remote-execution", "T1570", "T1021.002"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        // Match ServiceInstallation by service name (the PSEXESVC service).
        if event.event_type == EventType::ServiceInstallation {
            let svc = event
                .get_meta("service_name")
                .or_else(|| event.get_meta("name"))
                .unwrap_or("")
                .to_lowercase();
            if let Some(&matched) = PSEXEC_SERVICE_NAMES.iter().find(|&&s| svc.contains(s)) {
                let host = event.get_meta("host").unwrap_or("unknown");
                return Ok(Some(Detection::new(
                    self.id(), self.name(), self.description(),
                    Severity::High, &[event], Severity::High.weight(),
                    self.tags().iter().map(|s| s.to_string()).collect(),
                    vec![
                        format!("PsExec service installed: '{matched}'"),
                        format!("Host: {host}"),
                    ],
                )));
            }
        }

        // Match ProcessCreation by command line or parent image.
        if !matches!(event.event_type, EventType::ProcessCreation | EventType::CommandExecution) {
            return Ok(None);
        }

        let cmd    = event.get_meta("cmd").or_else(|| event.get_meta("command_line")).unwrap_or("").to_lowercase();
        let parent = event.get_meta("parent_image").unwrap_or("").to_lowercase();
        let search = format!("{cmd} {parent}");

        let matched = PSEXEC_CMD_INDICATORS.iter().find(|&&p| search.contains(p));
        let Some(&indicator) = matched else { return Ok(None) };

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
                format!("Remote execution tool indicator: '{indicator}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
