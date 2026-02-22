use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "odbcconf.exe",
    "mavinject.exe",
    "ieexec.exe",
    "forfiles.exe",
    "pcalua.exe",
];

// Patterns that make a LOLBin invocation suspicious (download, decode, proxy-exec).
static SUSPICIOUS_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\public\\",
    "\\programdata\\",
    "-urlcache",
    "-decode",
    "-decodefile",
    "javascript:",
    "vbscript:",
    "scrobj.dll",
    "/i http",
];

pub struct LolbinRule;

#[async_trait]
impl Rule for LolbinRule {
    fn id(&self)          -> &str { "EXEC-LOLBIN-001" }
    fn name(&self)        -> &str { "Living-off-the-Land Binary Abuse" }
    fn description(&self) -> &str {
        "A known LOLBin (certutil, mshta, rundll32, etc.) was invoked with \
         suspicious patterns such as remote URLs or writable-path references, \
         indicating possible download-and-execute or proxy-execution — MITRE T1218."
    }
    fn tags(&self) -> &[&'static str] {
        &["lolbin", "defense-evasion", "execution", "T1218"]
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

        let matched_bin = LOLBINS.iter().find(|&&bin| cmd.contains(bin));
        let Some(&bin) = matched_bin else { return Ok(None) };

        let matched_pat = SUSPICIOUS_PATTERNS.iter().find(|&&pat| cmd.contains(pat));
        let Some(&pattern) = matched_pat else { return Ok(None) };

        let host = event.get_meta("host").unwrap_or("unknown");
        let user = event.get_meta("user").unwrap_or("unknown");
        let pid  = event.get_meta("pid").unwrap_or("?");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::High,
            &[event],
            Severity::High.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("LOLBin '{bin}' invoked with suspicious pattern '{pattern}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}  |  PID: {pid}"),
            ],
        );

        Ok(Some(detection))
    }
}
