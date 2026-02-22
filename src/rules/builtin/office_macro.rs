use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static OFFICE_APPS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mspub.exe",
    "msaccess.exe",
    "onenote.exe",
    "visio.exe",
    "wordpad.exe",
];

// Scripting engines or shells that should never be spawned by Office.
static SUSPICIOUS_CHILDREN: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

pub struct OfficeMacroRule;

#[async_trait]
impl Rule for OfficeMacroRule {
    fn id(&self)          -> &str { "EXEC-OFFMAC-001" }
    fn name(&self)        -> &str { "Office Application Spawning Suspicious Child Process" }
    fn description(&self) -> &str {
        "An Office application (Word, Excel, Outlook, etc.) spawned a scripting engine \
         or shell. This is the hallmark of a malicious macro or exploit delivering a \
         payload — MITRE T1566 / T1204.002."
    }
    fn tags(&self) -> &[&'static str] {
        &["initial-access", "macro", "phishing", "T1566", "T1204.002"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::ProcessCreation {
            return Ok(None);
        }

        let parent = event.get_meta("parent_image").unwrap_or("").to_lowercase();
        if parent.is_empty() {
            return Ok(None);
        }

        if !OFFICE_APPS.iter().any(|&app| parent.contains(app)) {
            return Ok(None);
        }

        // Check child process image or command line.
        let exe = event.get_meta("exe").unwrap_or("").to_lowercase();
        let cmd = event.get_meta("cmd").unwrap_or("").to_lowercase();
        let invoked = format!("{exe} {cmd}");

        let matched_child = SUSPICIOUS_CHILDREN.iter().find(|&&ch| invoked.contains(ch));
        let Some(&child) = matched_child else { return Ok(None) };

        let host = event.get_meta("host").unwrap_or("unknown");
        let user = event.get_meta("user").unwrap_or("unknown");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Critical,
            &[event],
            Severity::Critical.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Office parent: {parent}"),
                format!("Suspicious child: '{child}'  →  {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
