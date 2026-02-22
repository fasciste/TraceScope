use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

const THRESHOLD: usize = 10;

// Well-known ransomware encrypted file extensions.
static RANSOM_EXTENSIONS: &[&str] = &[
    ".locked", ".encrypted", ".enc", ".crypto", ".crypt",
    ".crypted", ".ransom", ".wncry", ".wcry", ".locky",
    ".thor", ".zepto", ".odin", ".osiris", ".zzz",
    ".wallet", ".cerber", ".cryp1", ".globe",
    ".dark", ".rip", ".fun", ".pay", ".kill",
    ".rapid", ".sodinokibi", ".revil", ".ryuk",
    ".phobos", ".dharma", ".matrix", ".makop",
    ".conti", ".lockbit", ".hive", ".alphv",
    ".babuk", ".avos", ".yanluowang",
];

pub struct RansomwareRule;

#[async_trait]
impl Rule for RansomwareRule {
    fn id(&self)          -> &str { "FILE-RANSOM-001" }
    fn name(&self)        -> &str { "Ransomware File Encryption Activity" }
    fn description(&self) -> &str {
        "Mass creation of files with known ransomware encrypted-file extensions \
         from a single host. Indicates active ransomware encryption in progress — MITRE T1486."
    }
    fn tags(&self) -> &[&'static str] {
        &["ransomware", "impact", "data-encrypted", "T1486"]
    }

    async fn evaluate(&self, event: &Event, context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::FileCreation {
            return Ok(None);
        }

        let path = event
            .get_meta("file_path")
            .or_else(|| event.get_meta("path"))
            .or_else(|| event.get_meta("target"))
            .or_else(|| event.get_meta("filename"))
            .unwrap_or("")
            .to_lowercase();

        if !RANSOM_EXTENSIONS.iter().any(|&ext| path.ends_with(ext)) {
            return Ok(None);
        }

        let host = event.get_meta("host").unwrap_or("unknown");

        let count = context.recent_events.iter().filter(|e| {
            if e.event_type != EventType::FileCreation { return false; }
            if e.get_meta("host").unwrap_or("") != host { return false; }
            let p = e.get_meta("file_path")
                .or_else(|| e.get_meta("path"))
                .or_else(|| e.get_meta("target"))
                .or_else(|| e.get_meta("filename"))
                .unwrap_or("")
                .to_lowercase();
            RANSOM_EXTENSIONS.iter().any(|&ext| p.ends_with(ext))
        }).count();

        if count < THRESHOLD || count % THRESHOLD != 0 {
            return Ok(None);
        }

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
                format!("{count} files with ransomware extensions created on '{host}'"),
                format!("Latest encrypted file: {path}"),
                format!("User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
