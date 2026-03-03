# TraceScope

[![CI](https://github.com/kyvran/TraceScope/actions/workflows/ci.yml/badge.svg)](https://github.com/kyvran/TraceScope/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**TraceScope** is a next-generation async forensic correlation engine written in Rust.

Drop in your Windows EVTX logs, PCAP captures, syslog files, or JSON-lines events. TraceScope streams them through a concurrent normalization pipeline, correlates events over a configurable sliding window, and fires detection rules to produce a scored threat report — all without loading the entire event stream into memory.

---

## Features

- **Native EVTX parsing** — reads `.evtx` files directly via pure-Rust `evtx` crate, no external tools needed
- **Native PCAP parsing** — deep packet inspection with `pcap-file` + `etherparse`: extracts IPs, ports, and DNS queries
- **Live network capture** — capture from a live interface with `--features live-capture` (requires libpcap / `CAP_NET_RAW`)
- **Sigma rule loader** — load any YAML Sigma rule at runtime with `--sigma rule.yml`; supports `contains`, `startswith`, `endswith`, `and/or/not`, `1 of X*`, `all of X*`
- **5 built-in detection rules** — PowerShell lateral movement, brute force, DNS tunneling, registry persistence, credential dumping
- **Sliding-window correlation** — configurable window (default 120 s); replay-safe (uses event timestamps, not wall clock)
- **Atomic threat scoring** — lock-free `AtomicU32` incremented by concurrent rule tasks; four levels: `CLEAN` → `SUSPICIOUS` → `LIKELY_COMPROMISE` → `CRITICAL_INCIDENT`
- **Three output modes** — ANSI-coloured CLI report, machine-readable JSON, or a live web dashboard
- **Prometheus metrics** — expose `tracescope_events_total`, `tracescope_detections_total`, `tracescope_threat_score` on any port with `--metrics-port`
- **Fully async** — Tokio runtime with bounded `mpsc` + `broadcast` channels; backpressure throughout

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     TraceScope Pipeline                     │
│                                                             │
│  Ingestors ──mpsc──▶ Normalizer ──mpsc──▶ Dispatcher       │
│  (concurrent)                              │       │        │
│                                       correlator  broadcast │
│                                                      │      │
│                                               Rule Engine   │
│                                               (JoinSet)     │
│                                                      │      │
│                                             Score + Report  │
└─────────────────────────────────────────────────────────────┘
```

All channels are **bounded** (backpressure). Shutdown is **cascade-automatic**: ingestors close their senders when done, which propagates EOF through each stage without any explicit signal.

---

## Built-in Detection Rules

| Rule ID | Name | MITRE ATT&CK | Severity |
|---|---|---|---|
| `PS-LATERAL-001` | PowerShell Lateral Movement | T1059.001 + T1543.003 | Critical |
| `AUTH-BRUTE-001` | Brute Force Authentication | T1110 | High |
| `DNS-TUNNEL-001` | DNS Tunneling / Exfiltration | T1071.004 | High |
| `REG-PERSIST-001` | Registry Persistence | T1547.001 | Medium |
| `CRED-DUMP-001` | Credential Dumping | T1003 | Critical |

- **PS-LATERAL-001** — fires on `ServiceInstallation` if the same host also had a `ProcessCreation` with `powershell` and a `NetworkConnection` within the correlation window.
- **AUTH-BRUTE-001** — fires when ≥ 5 `LoginFailure` events from the same host appear within the window.
- **DNS-TUNNEL-001** — fires when ≥ 10 `DnsQuery` events come from the same host within the window, or when a single query name exceeds 40 characters.
- **REG-PERSIST-001** — fires on `RegistryModification` targeting known Windows persistence paths (Run, RunOnce, Winlogon, Services).
- **CRED-DUMP-001** — fires on `ProcessCreation` whose command line contains known credential-dumping indicators (mimikatz, sekurlsa, lsadump, procdump+lsass, etc.).

---

## Installation

```bash
git clone https://github.com/kyvran/TraceScope.git
cd TraceScope
cargo build --release
# binary: ./target/release/tracescope
```

**Requirements:** Rust stable ≥ 1.75. No other dependencies for offline analysis.
For live capture: `cargo build --release --features live-capture` (requires libpcap headers).

---

## Usage

```
tracescope ingest [OPTIONS]

  --evtx   <FILE>    Windows EVTX file (repeatable)
  --pcap   <FILE>    PCAP capture file (repeatable)
  --syslog <FILE>    Syslog file (repeatable)
  --json   <FILE>    JSON-lines event file (repeatable)
  --sigma  <FILE>    Sigma YAML rule (repeatable, stacks on built-ins)

  --output <FORMAT>  cli (default) | json | web
  --window <SECS>    Correlation window in seconds [default: 120]

  --metrics-port <PORT>  Expose Prometheus /metrics on this port
  --web-port     <PORT>  Port for the web dashboard [default: 3000]
```

### Examples

```bash
# Analyse a Windows EVTX file
tracescope ingest --evtx security.evtx

# Mix sources with a 5-minute correlation window
tracescope ingest --evtx security.evtx --pcap traffic.pcap --window 300

# Multiple JSON files ingested concurrently
tracescope ingest --json host1.json --json host2.json --json host3.json

# Load a custom Sigma rule on top of built-ins
tracescope ingest --evtx security.evtx --sigma my_rule.yml

# Machine-readable JSON output (pipe to jq, SIEM, etc.)
tracescope ingest --json events.json --output json | jq '.score'

# Web dashboard — opens at http://localhost:3000 after the pipeline finishes
tracescope ingest --evtx security.evtx --output web --web-port 3000

# Expose Prometheus metrics while processing
tracescope ingest --json events.json --metrics-port 9090

# Verbose logging
RUST_LOG=tracescope=debug tracescope ingest --json events.json
```

### Sample CLI output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TRACESCOPE FORENSIC REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Generated : 2026-02-20 14:32:01 UTC
  Duration  : 0.004s
  Events    : 8
  Score     : 80/100  [LIKELY_COMPROMISE]
────────────────────────────────────────────────────────────────
  Detections: 2 total  ●1 CRIT  ●1 HIGH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [1/2]  [CRITICAL]  PowerShell Lateral Movement
    Rule    : PS-LATERAL-001
    Score   : +50
    Tags    : powershell, lateral-movement, T1059.001, T1543.003
    Evidence:
      • ServiceInstallation 'updater_svc' on host WORKSTATION01
      • PowerShell ProcessCreation: powershell.exe -EncodedCommand …
      • Outbound NetworkConnection to 192.168.100.50:443
```

---

## JSON-lines event format

The `--json` ingestor reads one JSON object per line:

```json
{
  "event_type": "process_creation",
  "timestamp":  "2024-11-15T08:23:11Z",
  "severity":   "high",
  "host":       "WORKSTATION01",
  "user":       "jdoe",
  "pid":        "4521",
  "cmd":        "powershell.exe -EncodedCommand AGUAbQBz"
}
```

Supported `event_type` values: `process_creation`, `network_connection`, `file_creation`, `service_installation`, `registry_modification`, `login_attempt`, `login_success`, `login_failure`, `privilege_escalation`, `command_execution`, `dns_query`.

All other fields are stored as string metadata accessible to rules via `event.get_meta("key")`.

---

## Writing a Sigma rule

Any standard Sigma YAML file works:

```yaml
title: Suspicious Base64 PowerShell
id: MY-PS-001
level: high
logsource:
  category: process_creation
detection:
  selection:
    cmd|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
tags:
  - attack.execution
  - T1059.001
```

Load it at runtime:

```bash
tracescope ingest --json events.json --sigma my_rule.yml
```

---

## Writing a custom Rust rule

1. Create `src/rules/builtin/my_rule.rs`:

```rust
use async_trait::async_trait;
use anyhow::Result;
use crate::domain::{detection::Detection, event::Event, rule::{Rule, RuleContext}};

pub struct MyRule;

#[async_trait]
impl Rule for MyRule {
    fn id(&self)          -> &str { "MY-RULE-001" }
    fn name(&self)        -> &str { "My Custom Rule" }
    fn description(&self) -> &str { "Detects X." }
    fn tags(&self)        -> &[&'static str] { &["custom", "T1234"] }

    async fn evaluate(&self, event: &Event, ctx: &RuleContext) -> Result<Option<Detection>> {
        // inspect event + ctx.recent_events(); return Some(Detection::new(...)) or None
        Ok(None)
    }
}
```

2. Register it in `src/rules/builtin/mod.rs`:

```rust
pub mod my_rule;

pub fn load_all() -> Vec<Arc<dyn Rule>> {
    vec![
        // existing rules...
        Arc::new(my_rule::MyRule),
    ]
}
```

---

## Project structure

```
src/
├── domain/         # Core types: Event, Detection, Rule trait, ScoreEngine
├── ingestion/      # Async ingestors: EVTX, PCAP, Syslog, JSON-lines
├── pipeline/       # Normalizer, Dispatcher, Correlator (sliding window)
├── rules/
│   ├── engine.rs   # Concurrent rule evaluation (JoinSet per event)
│   ├── sigma.rs    # Sigma YAML rule loader
│   └── builtin/    # 5 built-in detection rules
├── output/         # CLI (ANSI), JSON, and web dashboard reporters
├── capture/        # Live network capture (feature-gated)
├── metrics.rs      # Prometheus metrics
└── app/            # Runner: pipeline orchestration + RunConfig
tests/
└── integration_test.rs
```

---

## Running tests

```bash
cargo test                     # unit + integration tests
cargo test -- --nocapture      # with stdout
cargo clippy -- -D warnings    # zero warnings enforced in CI
```

---

## License

MIT — see [LICENSE](LICENSE).
