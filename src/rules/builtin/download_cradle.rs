use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

static DOWNLOAD_PATTERNS: &[&str] = &[
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "net.webclient",
    "system.net.webclient",
    "invoke-webrequest",
    "start-bitstransfer",
    "bits.start",
];

// Execution indicators that turn a download into a download-and-execute cradle.
static EXEC_INDICATORS: &[&str] = &[
    "| iex",
    ";iex",
    "; iex",
    "(iex",
    "invoke-expression",
    "[system.reflection.assembly]::load",
    "[reflection.assembly]::load",
    "assembly::loadfrom",
    "|iex",
];

pub struct DownloadCradleRule;

#[async_trait]
impl Rule for DownloadCradleRule {
    fn id(&self)          -> &str { "EXEC-DLCRD-001" }
    fn name(&self)        -> &str { "PowerShell / Certutil Download Cradle" }
    fn description(&self) -> &str {
        "A PowerShell download function (Net.WebClient, Invoke-WebRequest) chained with \
         Invoke-Expression, or certutil used to download/decode a remote file. \
         Classic in-memory payload delivery — MITRE T1059.001 / T1105."
    }
    fn tags(&self) -> &[&'static str] {
        &["execution", "download", "cradle", "T1059.001", "T1105"]
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

        // certutil -urlcache or -decode is always a download-abuse pattern.
        let is_certutil_abuse = cmd.contains("certutil")
            && (cmd.contains("-urlcache") || cmd.contains("-decode") || cmd.contains("-decodefile"));

        if is_certutil_abuse {
            let host = event.get_meta("host").unwrap_or("unknown");
            let user = event.get_meta("user").unwrap_or("unknown");
            return Ok(Some(Detection::new(
                self.id(), self.name(), self.description(),
                Severity::High, &[event], Severity::High.weight(),
                self.tags().iter().map(|s| s.to_string()).collect(),
                vec![
                    "certutil used to download or decode a remote file".to_owned(),
                    format!("Command: {cmd}"),
                    format!("Host: {host}  |  User: {user}"),
                ],
            )));
        }

        // Download + execute chain.
        let has_download = DOWNLOAD_PATTERNS.iter().any(|&p| cmd.contains(p));
        let has_exec     = EXEC_INDICATORS.iter().any(|&p| cmd.contains(p));

        if !has_download || !has_exec {
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
                "Download-and-execute cradle detected (download function + IEX/assembly load)".to_owned(),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}"),
            ],
        );

        Ok(Some(detection))
    }
}
