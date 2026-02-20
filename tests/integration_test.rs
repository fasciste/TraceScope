/// Integration tests — end-to-end pipeline with synthetic events.
///
/// `MockIngestor` is defined locally here because it is only needed for tests
/// and doesn't belong in the library's public API.
use tracescope::app::runner::{run, OutputFormat, RunConfig};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn ps_creation() -> serde_json::Value {
    serde_json::json!({
        "event_type": "process_creation",
        "severity":   "high",
        "cmd":        "powershell.exe -EncodedCommand AGUAbQBz",
        "host":       "WORKSTATION01",
        "user":       "jdoe",
        "pid":        "4521"
    })
}

fn network_conn() -> serde_json::Value {
    serde_json::json!({
        "event_type": "network_connection",
        "severity":   "medium",
        "host":       "WORKSTATION01",
        "dst_ip":     "192.168.100.50",
        "dst_port":   "443",
        "bytes_out":  "15234"
    })
}

fn service_install() -> serde_json::Value {
    serde_json::json!({
        "event_type":    "service_installation",
        "severity":      "high",
        "host":          "WORKSTATION01",
        "service_name":  "updater_svc",
        "image_path":    "C:\\Windows\\Temp\\upd.exe"
    })
}

fn login_failure(host: &str) -> serde_json::Value {
    serde_json::json!({
        "event_type": "login_failure",
        "severity":   "low",
        "host":       host,
        "user":       "admin",
        "source_ip":  "10.0.0.99"
    })
}

fn config_with_no_source() -> RunConfig {
    RunConfig {
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
        json_paths:    vec![],
        output_format: OutputFormat::Json,
        window_secs:   120,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Full pipeline: PS + network + service → 1 Critical detection.
#[tokio::test]
async fn pipeline_detects_powershell_lateral() {
    let dir   = tempfile::TempDir::new().unwrap();
    let path  = dir.path().join("events.json");

    let mut content = String::new();
    for ev in &[ps_creation(), network_conn(), service_install()] {
        content.push_str(&serde_json::to_string(ev).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&path, &content).await.unwrap();

    let config = RunConfig {
        json_paths:    vec![path],
        output_format: OutputFormat::Json,
        window_secs:   120,
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
    };

    let report = run(config).await.unwrap();

    assert_eq!(report.events_processed, 3, "all 3 events should be processed");
    assert!(
        !report.detections.is_empty(),
        "PowerShell lateral movement should be detected"
    );
    assert!(
        report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"),
        "PS-LATERAL-001 rule should fire"
    );
    assert!(report.score.score >= 50, "score should include Critical weight");
    assert_eq!(report.summary.total, report.detections.len());
}

/// Full pipeline: 5 login failures → 1 High detection.
#[tokio::test]
async fn pipeline_detects_brute_force() {
    let dir   = tempfile::TempDir::new().unwrap();
    let path  = dir.path().join("bruteforce.json");

    let mut content = String::new();
    for _ in 0..5 {
        content.push_str(&serde_json::to_string(&login_failure("SERVER02")).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&path, &content).await.unwrap();

    let config = RunConfig {
        json_paths:    vec![path],
        output_format: OutputFormat::Json,
        window_secs:   120,
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
    };

    let report = run(config).await.unwrap();

    assert_eq!(report.events_processed, 5);
    assert!(
        report.detections.iter().any(|d| d.rule_id == "AUTH-BRUTE-001"),
        "AUTH-BRUTE-001 rule should fire"
    );
    assert_eq!(report.summary.high, 1, "should be exactly 1 high-severity detection");
}

/// No source → error.
#[tokio::test]
async fn no_source_returns_error() {
    let result = run(config_with_no_source()).await;
    assert!(result.is_err(), "running without sources should return an error");
}

/// Empty file → zero events, no detections.
#[tokio::test]
async fn empty_file_no_detections() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("empty.json");
    tokio::fs::write(&path, "").await.unwrap();

    let config = RunConfig {
        json_paths:    vec![path],
        output_format: OutputFormat::Json,
        window_secs:   120,
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
    };

    let report = run(config).await.unwrap();
    assert_eq!(report.events_processed, 0);
    assert!(report.detections.is_empty());
    assert_eq!(report.score.score, 0);
    assert_eq!(report.summary.total, 0);
}

/// Both attack patterns together → combined score ≥ 60 (LIKELY_COMPROMISE).
#[tokio::test]
async fn combined_score_reaches_likely_compromise() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("combined.json");

    let mut content = String::new();
    for ev in &[ps_creation(), network_conn(), service_install()] {
        content.push_str(&serde_json::to_string(ev).unwrap());
        content.push('\n');
    }
    for _ in 0..5 {
        content.push_str(&serde_json::to_string(&login_failure("SRV02")).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&path, &content).await.unwrap();

    let config = RunConfig {
        json_paths:    vec![path],
        output_format: OutputFormat::Json,
        window_secs:   120,
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
    };

    let report = run(config).await.unwrap();
    assert!(
        report.score.score >= 60,
        "combined score should reach LIKELY_COMPROMISE (got {})",
        report.score.score
    );
    assert!(report.summary.total >= 2, "at least 2 detections expected");
}

/// Multi-file ingestion: two JSON files must yield all events.
#[tokio::test]
async fn multi_file_ingestion() {
    let dir = tempfile::TempDir::new().unwrap();

    let path1 = dir.path().join("ps.json");
    let mut c1 = String::new();
    for ev in &[ps_creation(), network_conn(), service_install()] {
        c1.push_str(&serde_json::to_string(ev).unwrap());
        c1.push('\n');
    }
    tokio::fs::write(&path1, &c1).await.unwrap();

    let path2 = dir.path().join("brute.json");
    let mut c2 = String::new();
    for _ in 0..5 {
        c2.push_str(&serde_json::to_string(&login_failure("DC01")).unwrap());
        c2.push('\n');
    }
    tokio::fs::write(&path2, &c2).await.unwrap();

    let config = RunConfig {
        json_paths:    vec![path1, path2],
        output_format: OutputFormat::Json,
        window_secs:   120,
        evtx_paths:    vec![],
        pcap_paths:    vec![],
        syslog_paths:  vec![],
    };

    let report = run(config).await.unwrap();

    assert_eq!(report.events_processed, 8, "all 8 events across both files");
    assert!(report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"));
    assert!(report.detections.iter().any(|d| d.rule_id == "AUTH-BRUTE-001"));
}
