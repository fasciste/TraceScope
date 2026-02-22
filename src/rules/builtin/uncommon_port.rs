use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

// Ports almost exclusively associated with attacker tooling or C2 frameworks.
static KNOWN_C2_PORTS: &[&str] = &[
    "4444",  // Metasploit default
    "4445",  // Metasploit alternate
    "4443",  // Cobalt Strike HTTPS alternate
    "31337", // Elite / Back Orifice
    "1337",  // Common leet/PoC port
    "8888",  // Generic C2 / notebooks
    "9001",  // Tor / common C2
    "9050",  // Tor SOCKS proxy
    "6666",  // IRC-based C2
    "6667",
    "6668",
    "6669",
    "12345", // Netbus
    "27374", // Sub7
];

// Ports suspicious only when connecting to external (non-RFC1918) IPs.
static SUSPICIOUS_EXTERNAL_PORTS: &[&str] = &[
    "23",    // Telnet — cleartext
    "1080",  // SOCKS proxy
    "3128",  // Squid proxy
    "8080",  // Web proxy / C2
    "8443",  // HTTPS alternate — common for C2
];

fn is_rfc1918(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("127.") || ip.starts_with("169.254.") {
        return true;
    }
    if ip.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(oct) = rest.split('.').next() {
            if let Ok(n) = oct.parse::<u8>() {
                return (16..=31).contains(&n);
            }
        }
    }
    false
}

pub struct UncommonPortRule;

#[async_trait]
impl Rule for UncommonPortRule {
    fn id(&self)          -> &str { "NET-C2PORT-001" }
    fn name(&self)        -> &str { "Connection on Known Attacker / C2 Port" }
    fn description(&self) -> &str {
        "Outbound connection to a port associated with attacker tooling (Metasploit 4444, \
         Back Orifice 31337, Tor 9050, etc.) or a suspicious proxy/cleartext service \
         to an external IP — MITRE T1571."
    }
    fn tags(&self) -> &[&'static str] {
        &["c2", "command-and-control", "suspicious-port", "T1571"]
    }

    async fn evaluate(&self, event: &Event, _context: &RuleContext) -> Result<Option<Detection>> {
        if event.event_type != EventType::NetworkConnection {
            return Ok(None);
        }

        let dst_port = event.get_meta("dst_port").unwrap_or("");
        let dst_ip   = event.get_meta("dst_ip").unwrap_or("");
        let host     = event.get_meta("host").unwrap_or("unknown");

        // Always fire on known C2 ports regardless of destination.
        if KNOWN_C2_PORTS.contains(&dst_port) {
            return Ok(Some(Detection::new(
                self.id(), self.name(), self.description(),
                Severity::High, &[event], Severity::High.weight(),
                self.tags().iter().map(|s| s.to_string()).collect(),
                vec![
                    format!("Connection to known C2 port {dst_port} → {dst_ip}"),
                    format!("Host: {host}"),
                ],
            )));
        }

        // Suspicious external-only ports.
        if SUSPICIOUS_EXTERNAL_PORTS.contains(&dst_port) && !dst_ip.is_empty() && !is_rfc1918(dst_ip) {
            return Ok(Some(Detection::new(
                self.id(), self.name(), self.description(),
                Severity::Medium, &[event], Severity::Medium.weight(),
                self.tags().iter().map(|s| s.to_string()).collect(),
                vec![
                    format!("Connection to suspicious port {dst_port} on external host {dst_ip}"),
                    format!("Host: {host}"),
                ],
            )));
        }

        Ok(None)
    }
}
