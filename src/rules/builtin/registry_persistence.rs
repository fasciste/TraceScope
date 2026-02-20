/// Rule: Registry Persistence
///
/// Pattern (MITRE T1547.001):
///   A RegistryModification event targeting well-known Windows persistence
///   key paths (Run, RunOnce, Winlogon, Services, Shell Folders).
///
/// Optionally correlated with a preceding ProcessCreation in the same window.
use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

/// Registry paths (lowercased) commonly abused for persistence.
static PERSISTENCE_KEYS: &[&str] = &[
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"system\currentcontrolset\services",
    r"software\microsoft\windows\currentversion\explorer\shell folders",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
];

pub struct RegistryPersistenceRule;

#[async_trait]
impl Rule for RegistryPersistenceRule {
    fn id(&self)          -> &str { "REG-PERSIST-001" }
    fn name(&self)        -> &str { "Registry Persistence" }
    fn description(&self) -> &str {
        "Modification of well-known Windows registry persistence keys indicates \
         a potential persistence mechanism being installed (T1547.001)."
    }
    fn tags(&self) -> &[&'static str] {
        &["persistence", "registry", "T1547.001"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::RegistryModification {
            return Ok(None);
        }

        let reg_key = event
            .get_meta("registry_key")
            .or_else(|| event.get_meta("key"))
            .unwrap_or("")
            .to_lowercase();

        // Check whether the key matches any known persistence path.
        let matched = PERSISTENCE_KEYS.iter().find(|&&pat| reg_key.contains(pat));
        let Some(_matched_pat) = matched else { return Ok(None) };

        let host  = event.get_meta("host").unwrap_or("unknown");
        let user  = event.get_meta("user").unwrap_or("unknown");
        let value = event
            .get_meta("registry_value")
            .or_else(|| event.get_meta("value"))
            .unwrap_or("unknown");

        // Elevate confidence when a process was recently created on the same host.
        let correlated_process =
            context.has_event_type_before(&EventType::ProcessCreation, &event.timestamp);

        let mut evidence = vec![
            format!("Registry key modified: {reg_key}"),
            format!("Value written: {value}"),
            format!("Host: {host}  |  User: {user}"),
        ];
        if correlated_process {
            evidence.push(
                "Preceded by a ProcessCreation event in the same correlation window".to_owned(),
            );
        }

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Medium,
            &[event],
            Severity::Medium.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            evidence,
        );

        Ok(Some(detection))
    }
}
