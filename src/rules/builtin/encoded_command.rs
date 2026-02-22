use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// Strong obfuscation markers — any of these alone is sufficient to trigger.
static STRONG_INDICATORS: &[&str] = &[
    "-encodedcommand",
    "frombase64string(",
    "[system.convert]::frombase64",
    "[convert]::frombase64",
    "`i`e`x",           // backtick-obfuscated iex
    "i`ex",
    "&([char]",         // char-array execution trick
    "[scriptblock]::create",
    "::getstring(",     // text.encoding.getstring decode
];

pub struct EncodedCommandRule;

#[async_trait]
impl Rule for EncodedCommandRule {
    fn id(&self)          -> &str { "EXEC-ENCODE-001" }
    fn name(&self)        -> &str { "Encoded / Obfuscated Command Execution" }
    fn description(&self) -> &str {
        "Process creation or command execution with known obfuscation patterns \
         (Base64 encoding, backtick-obfuscated Invoke-Expression, char-array eval, etc.) \
         — a strong indicator of payload concealment — MITRE T1027 / T1059.001."
    }
    fn tags(&self) -> &[&'static str] {
        &["obfuscation", "defense-evasion", "T1027", "T1059.001"]
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

        let matched: Vec<&str> = STRONG_INDICATORS.iter()
            .filter(|&&p| cmd.contains(p))
            .copied()
            .collect();

        if matched.is_empty() {
            return Ok(None);
        }

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
                format!("Obfuscation patterns matched: {}", matched.join(", ")),
                format!("Command: {cmd}"),
                format!("Host: {host}  |  User: {user}  |  PID: {pid}"),
            ],
        );

        Ok(Some(detection))
    }
}
