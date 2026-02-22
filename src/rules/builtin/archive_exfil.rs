use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static ARCHIVE_TOOLS: &[&str] = &[
    "7z.exe", "7za.exe", "7zr.exe",
    "rar.exe", "winrar.exe",
    "zip.exe",
    "tar.exe",
    "compress-archive",
    "gzip",
];

// Destinations that suggest staging for exfiltration.
static SUSPICIOUS_DEST: &[&str] = &[
    "\\\\",           // UNC/network path
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\programdata\\",
    "/tmp/",
    "/dev/shm/",
    "ftp://",
    "http://",
    "https://",
];

pub struct ArchiveExfilRule;

#[async_trait]
impl Rule for ArchiveExfilRule {
    fn id(&self)          -> &str { "FILE-ARCEXF-001" }
    fn name(&self)        -> &str { "Data Archiving for Exfiltration" }
    fn description(&self) -> &str {
        "An archiving tool (7zip, RAR, tar, Compress-Archive) was invoked with an output \
         path in a writable staging area or network path, suggesting data collection \
         before exfiltration — MITRE T1560."
    }
    fn tags(&self) -> &[&'static str] {
        &["collection", "archive", "exfiltration", "T1560"]
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

        if !ARCHIVE_TOOLS.iter().any(|&tool| cmd.contains(tool)) {
            return Ok(None);
        }

        let matched_dest = SUSPICIOUS_DEST.iter().find(|&&dest| cmd.contains(dest));
        let Some(&dest) = matched_dest else { return Ok(None) };

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
                format!("Archive tool used with suspicious destination '{dest}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
