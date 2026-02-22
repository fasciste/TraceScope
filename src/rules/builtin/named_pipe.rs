use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// Known C2 framework named pipe patterns (Cobalt Strike, Metasploit, etc.)
// and PowerShell named-pipe creation APIs.
static PIPE_INDICATORS: &[&str] = &[
    // Cobalt Strike default pipe names
    r"pipe\msse-",
    r"pipe\status_",
    r"pipe\msagent_",
    r"pipe\postex_",
    r"pipe\min_",
    r"pipe\netlogon_",
    // Metasploit named pipe patterns
    r"pipe\spoolss",
    r"pipe\lsarpc_",
    // PowerShell named pipe API usage
    "system.io.pipes",
    "namedpipeserverstream",
    "namedpipeclientstream",
    "createnamedpipe",
    // Generic suspicious pipe in command line
    r"\\.\pipe\",
];

pub struct NamedPipeRule;

#[async_trait]
impl Rule for NamedPipeRule {
    fn id(&self)          -> &str { "EXEC-PIPE-001" }
    fn name(&self)        -> &str { "Suspicious Named Pipe Usage" }
    fn description(&self) -> &str {
        "References to known C2 framework named pipe patterns (Cobalt Strike, Metasploit) \
         or PowerShell named pipe creation APIs in a process command line — \
         often used for inter-process communication in post-exploitation — MITRE T1559."
    }
    fn tags(&self) -> &[&'static str] {
        &["c2", "inter-process-communication", "cobalt-strike", "T1559"]
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

        let matched = PIPE_INDICATORS.iter().find(|&&p| cmd.contains(p));
        let Some(&indicator) = matched else { return Ok(None) };

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
                format!("Named pipe indicator matched: '{indicator}'"),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}  |  PID: {pid}"),
            ],
        );

        Ok(Some(detection))
    }
}
