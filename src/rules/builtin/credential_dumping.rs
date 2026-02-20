/// Rule: Credential Dumping
///
/// Pattern (MITRE T1003):
///   A ProcessCreation event whose command line contains a known
///   credential-dumping tool name or LSASS-targeting pattern.
///
///   Covered indicators: Mimikatz, ProcDump targeting LSASS, comsvcs.dll
///   MiniDump, WCE, gsecdump, fgdump, pwdump, and generic `hashdump`.
use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static INDICATORS: &[&str] = &[
    "mimikatz",
    "sekurlsa",
    "lsadump",
    "procdump",
    "lsass.exe",
    "comsvcs.dll",
    "minidump",
    "wce.exe",
    "gsecdump",
    "fgdump",
    "pwdump",
    "hashdump",
];

pub struct CredentialDumpingRule;

#[async_trait]
impl Rule for CredentialDumpingRule {
    fn id(&self)          -> &str { "CRED-DUMP-001" }
    fn name(&self)        -> &str { "Credential Dumping" }
    fn description(&self) -> &str {
        "Process creation with known credential-dumping indicators (Mimikatz, \
         ProcDump against LSASS, comsvcs MiniDump, etc.) — MITRE T1003."
    }
    fn tags(&self) -> &[&'static str] {
        &["credential-dumping", "lsass", "mimikatz", "T1003"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::ProcessCreation {
            return Ok(None);
        }

        let cmd = event
            .get_meta("cmd")
            .or_else(|| event.get_meta("command_line"))
            .unwrap_or("")
            .to_lowercase();

        let matched_indicator = INDICATORS.iter().find(|&&ind| cmd.contains(ind));
        let Some(&indicator) = matched_indicator else { return Ok(None) };

        let host = event.get_meta("host").unwrap_or("unknown");
        let user = event.get_meta("user").unwrap_or("unknown");
        let pid  = event.get_meta("pid").unwrap_or("?");

        let detection = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            Severity::Critical,
            &[event],
            Severity::Critical.weight(),
            self.tags().iter().map(|s| s.to_string()).collect(),
            vec![
                format!("Credential-dumping indicator '{indicator}' matched in command line"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}  |  PID: {pid}"),
            ],
        );

        Ok(Some(detection))
    }
}
