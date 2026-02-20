# TraceScope

[![CI](https://github.com/fasciste/TraceScope/actions/workflows/ci.yml/badge.svg)](https://github.com/fasciste/TraceScope/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**TraceScope** is a next-generation, fully-async forensic correlation engine written in Rust.
It ingests raw security events (Windows EVTX, PCAP, syslog, JSON-lines), normalizes them through a streaming pipeline, evaluates concurrent detection rules with a sliding-window correlator, and produces a scored threat report — without materializing the entire event stream into memory.

---

## Key Features

| Feature | Detail |
|---|---|
| **100 % async / non-blocking** | Tokio runtime, bounded `mpsc` + `broadcast` channels, `JoinSet` concurrency |
| **Streaming pipeline** | No `Vec<Event>` accumulation — events flow: Ingestor → Normalizer → Dispatcher → Rule Engine → Scorer |
| **Replay-safe correlator** | Reference "now" = max event timestamp (not wall clock) — works correctly on historical forensic data |
| **Sliding-window correlation** | Configurable window (default 120 s); O(1) cached `latest_ts` with front-eviction |
| **5 built-in detection rules** | PS lateral movement, brute-force, DNS tunneling, registry persistence, credential dumping |
| **Atomic threat scoring** | Lock-free `AtomicU32`, four threat levels: CLEAN → SUSPICIOUS → LIKELY_COMPROMISE → CRITICAL_INCIDENT |
| **Multi-file ingestion** | Each `--json / --evtx / --pcap / --syslog` flag is repeatable; all files are ingested concurrently |
| **Detection summary** | Per-severity breakdown (CRITICAL / HIGH / MEDIUM / LOW / INFO) in every report |
| **Dual output** | ANSI-coloured CLI report or machine-readable JSON (`--output json`) |
| **Plugin system** | Feature-gated (`--features plugins`) for custom rule extensions |
| **GitHub Actions CI** | `cargo build`, `cargo test`, `cargo clippy -D warnings` on every push |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     TraceScope Pipeline                      │
│                                                              │
│  Ingestors ──mpsc──▶ Normalizer ──mpsc──▶ Dispatcher        │
│  (concurrent)                              │                 │
│                                     broadcast (fan-out)      │
│                                            │                 │
│                                     Rule Engine              │
│                                     (JoinSet per event)      │
│                                            │                 │
│                                     mpsc──▶ Score + Report  │
└──────────────────────────────────────────────────────────────┘
```

All channels are **bounded** (backpressure). Shutdown is **cascade-automatic**: when ingestors finish they drop their senders, and each stage propagates EOF downstream. No explicit shutdown signals are needed.

---

## Built-in Detection Rules

| Rule ID | Name | MITRE ATT&CK | Severity |
|---|---|---|---|
| `PS-LATERAL-001` | PowerShell Lateral Movement | T1059.001 + T1543.003 | Critical |
| `AUTH-BRUTE-001` | Brute Force Authentication | T1110 | High |
| `DNS-TUNNEL-001` | DNS Tunneling / Exfiltration | T1071.004 | High |
| `REG-PERSIST-001` | Registry Persistence | T1547.001 | Medium |
| `CRED-DUMP-001` | Credential Dumping | T1003 | Critical |

### Rule Logic

- **PS-LATERAL-001** — triggers on `ServiceInstallation` and looks back for a `ProcessCreation` containing `powershell` AND a `NetworkConnection` from the same host, all within the correlation window.
- **AUTH-BRUTE-001** — fires when ≥ 5 `LoginFailure` events for the same host appear within the window (re-fires at every 5th multiple).
- **DNS-TUNNEL-001** — fires when ≥ 10 `DnsQuery` events come from the same host within the window, OR when a single DNS query name exceeds 40 characters (base64/hex encoded payload).
- **REG-PERSIST-001** — fires on any `RegistryModification` targeting known Windows Run/RunOnce/Winlogon/Services paths.
- **CRED-DUMP-001** — fires on `ProcessCreation` whose command line contains known credential-dumping indicators (mimikatz, sekurlsa, lsadump, procdump+lsass, comsvcs MiniDump, WCE, and more).

---

## Installation

### Prerequisites

- [Rust stable toolchain](https://rustup.rs/) (≥ 1.75)

### Build from source

```bash
git clone https://github.com/fasciste/TraceScope.git
cd TraceScope
cargo build --release
# Binary: ./target/release/tracescope
```

---

## Usage

```
tracescope ingest [OPTIONS]

Options:
  --json   <FILE>    JSON-lines event file (repeatable)
  --evtx   <FILE>    EVTX / JSON-lines EVTX export (repeatable)
  --pcap   <FILE>    PCAP / JSON-lines PCAP export (repeatable)
  --syslog <FILE>    Syslog file (repeatable)
  --output <FORMAT>  Output format: cli (default) | json
  --window <SECS>    Correlation window in seconds (default: 120)
```

### Examples

```bash
# Analyse a single JSON-lines event file
tracescope ingest --json events.json

# Multiple files of the same type (ingested concurrently)
tracescope ingest --json host1.json --json host2.json --json host3.json

# Mix sources with a 5-minute correlation window
tracescope ingest --evtx security.evtx --pcap traffic.pcap --window 300

# Machine-readable JSON output (pipe to jq, SIEM, etc.)
tracescope ingest --json events.json --output json | jq '.score'

# Verbose debug logging
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

The `--json` ingestor reads one JSON object per line. Supported fields:

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

`event_type` values: `process_creation`, `network_connection`, `file_creation`, `service_installation`, `registry_modification`, `login_attempt`, `login_success`, `login_failure`, `privilege_escalation`, `command_execution`, `dns_query`.

All other fields are stored as string metadata and are accessible to rules via `event.get_meta("key")`.

---

## Running the test suite

```bash
cargo test                     # all unit + integration tests
cargo test -- --nocapture      # with stdout
cargo clippy -- -D warnings    # lint (zero warnings enforced in CI)
```

---

## Project structure

```
src/
├── domain/         # Core types: Event, Detection, Rule trait, ScoreEngine
├── ingestion/      # Async ingestors: JSON, EVTX, PCAP, Syslog
├── pipeline/       # Normalizer, Dispatcher, Correlator (sliding window)
├── rules/
│   ├── engine.rs   # JoinSet concurrent rule evaluation
│   └── builtin/    # 5 built-in rules + mod.rs loader
├── output/         # CLI (ANSI) + JSON reporters, ForensicReport, DetectionSummary
├── plugins/        # Feature-gated plugin system
├── app/            # Runner (pipeline orchestration) + RunConfig
├── error.rs        # TracescopeError
└── lib.rs          # Public module re-exports
tests/
└── integration_test.rs   # End-to-end tests (6 scenarios)
.github/
└── workflows/ci.yml      # GitHub Actions CI
```

---

## Adding a custom rule

1. Create `src/rules/builtin/my_rule.rs` and implement the `Rule` async trait:

```rust
use async_trait::async_trait;
use anyhow::Result;
use crate::domain::{detection::Detection, event::Event, rule::{Rule, RuleContext}};

pub struct MyRule;

#[async_trait]
impl Rule for MyRule {
    fn id(&self)   -> &str { "MY-RULE-001" }
    fn name(&self) -> &str { "My Custom Rule" }
    fn description(&self) -> &str { "Detects X." }
    fn tags(&self) -> &[&'static str] { &["custom", "T1234"] }

    async fn evaluate(&self, event: &Event, ctx: &RuleContext) -> Result<Option<Detection>> {
        // Inspect event and correlator context; return Some(Detection) or None.
        Ok(None)
    }
}
```

2. Register it in `src/rules/builtin/mod.rs`:

```rust
pub mod my_rule;

pub fn load_all() -> Vec<Arc<dyn Rule>> {
    vec![
        // ... existing rules ...
        Arc::new(my_rule::MyRule),
    ]
}
```

---

## Pushing to GitHub

### First push

```bash
# 1. Create a new EMPTY repository on github.com
#    (do NOT initialize it with README, .gitignore or license)

# 2. Inside the TraceScope directory:
git init
git add .
git commit -m "feat: initial TraceScope release"

# 3. Link and push
git remote add origin https://github.com/fasciste/TraceScope.git
git branch -M main
git push -u origin main
```

### Subsequent changes

```bash
git add .
git commit -m "feat: describe your change"
git push
```

### Recommended branch workflow

```bash
git checkout -b feat/my-new-rule
# ... make changes and commit ...
git push -u origin feat/my-new-rule
# Open a Pull Request → CI runs → merge after green checks
```

---

## Roadmap

- [ ] Native EVTX parsing via `evtx` crate
- [ ] PCAP deep-packet inspection via `pcap` crate
- [ ] Sigma rule loader (YAML → `Rule` trait)
- [ ] Live network capture mode
- [ ] Web dashboard output
- [ ] OpenTelemetry metrics export

---

## License

MIT — see [LICENSE](LICENSE).
