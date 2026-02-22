use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static SUSPICIOUS_DIRS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\recycler\\",
    "\\$recycle.bin\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
];

static EXEC_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".ps1", ".bat", ".cmd",
    ".vbs", ".js",  ".hta", ".jar", ".msi",
    ".scr", ".com", ".pif", ".wsf",
];

pub struct FileDropperRule;

#[async_trait]
impl Rule for FileDropperRule {
    fn id(&self)          -> &str { "FILE-DROP-001" }
    fn name(&self)        -> &str { "Executable Dropped in Suspicious Location" }
    fn description(&self) -> &str {
        "A file with an executable extension was created inside a writable or \
         temporary directory (Temp, AppData, Public, ProgramData, /tmp). \
         Common indicator of malware dropper or staged payload — MITRE T1105."
    }
    fn tags(&self) -> &[&'static str] {
        &["dropper", "ingress-tool-transfer", "T1105"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::FileCreation {
            return Ok(None);
        }

        let path = event
            .get_meta("file_path")
            .or_else(|| event.get_meta("path"))
            .or_else(|| event.get_meta("target"))
            .unwrap_or("")
            .to_lowercase();

        if path.is_empty() {
            return Ok(None);
        }

        if !SUSPICIOUS_DIRS.iter().any(|&dir| path.contains(dir)) {
            return Ok(None);
        }

        if !EXEC_EXTENSIONS.iter().any(|&ext| path.ends_with(ext)) {
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
                format!("Executable file created: {path}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
