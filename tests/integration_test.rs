use tracescope::app::runner::{run, OutputFormat, RunConfig};

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
        "event_type":   "service_installation",
        "severity":     "high",
        "host":         "WORKSTATION01",
        "service_name": "updater_svc",
        "image_path":   "C:\\Windows\\Temp\\upd.exe"
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

fn base_config(json_paths: Vec<std::path::PathBuf>) -> RunConfig {
    RunConfig {
        evtx_paths:     vec![],
        pcap_paths:     vec![],
        syslog_paths:   vec![],
        json_paths,
        sigma_paths:    vec![],
        output_format:  OutputFormat::Json,
        window_secs:    120,
        metrics_port:   None,
        web_port:       3000,
        filter_hosts:   vec![],
        disabled_rules: vec![],
    }
}

async fn write_jsonl(path: &std::path::Path, events: &[serde_json::Value]) {
    let content = events.iter()
        .map(|ev| serde_json::to_string(ev).unwrap())
        .collect::<Vec<_>>()
        .join("\n") + "\n";
    tokio::fs::write(path, content).await.unwrap();
}

#[tokio::test]
async fn pipeline_detects_powershell_lateral() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("events.json");
    write_jsonl(&path, &[ps_creation(), network_conn(), service_install()]).await;

    let report = run(base_config(vec![path])).await.unwrap();

    assert_eq!(report.events_processed, 3);
    assert!(!report.detections.is_empty(), "PowerShell lateral movement should be detected");
    assert!(report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"));
    assert!(report.score.score >= 50);
    assert_eq!(report.summary.total, report.detections.len());
}

// Regression test: rule must fire even when the network event comes AFTER service install.
#[tokio::test]
async fn pipeline_detects_lateral_out_of_order() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("oot.json");
    // Deliberately: ps_creation → service_install → network_conn (network AFTER service)
    write_jsonl(&path, &[
        ps_creation(),
        service_install(),
        network_conn(),
    ]).await;

    let report = run(base_config(vec![path])).await.unwrap();

    assert!(
        report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"),
        "PS-LATERAL-001 should fire regardless of event ordering within the window"
    );
}

// Nested metadata: cmd inside a sub-object should still work via alias/flattening.
#[tokio::test]
async fn pipeline_detects_lateral_nested_metadata() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("nested.json");
    // cmd is inside a nested "metadata" object, not at the top level.
    write_jsonl(&path, &[
        serde_json::json!({
            "event_type": "process_creation",
            "host":       "WORKSTATION01",
            "metadata":   { "cmd": "powershell.exe -EncodedCommand AGUAbQBz", "pid": 4521 }
        }),
        network_conn(),
        service_install(),
    ]).await;

    let report = run(base_config(vec![path])).await.unwrap();

    assert!(
        report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"),
        "PS-LATERAL-001 should fire when cmd is nested inside a metadata sub-object"
    );
}

// --filter-host: events for the wrong host must be silently dropped.
#[tokio::test]
async fn filter_host_drops_non_matching_events() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("mixed.json");
    // 5 login failures for OTHERHOST, all should be dropped by the filter.
    let mut events = vec![];
    for _ in 0..5 { events.push(login_failure("OTHERHOST")); }
    write_jsonl(&path, &events).await;

    let config = RunConfig {
        filter_hosts:   vec!["WORKSTATION01".into()],
        ..base_config(vec![path])
    };
    let report = run(config).await.unwrap();
    assert_eq!(report.events_processed, 0, "all events should be filtered out");
    assert!(report.detections.is_empty());
}

// --disable-rule: disabled rules must not fire.
#[tokio::test]
async fn disable_rule_suppresses_detection() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("events.json");
    write_jsonl(&path, &[ps_creation(), network_conn(), service_install()]).await;

    let config = RunConfig {
        disabled_rules: vec!["PS-LATERAL-001".into()],
        ..base_config(vec![path])
    };
    let report = run(config).await.unwrap();
    assert!(
        !report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"),
        "PS-LATERAL-001 should not fire when disabled"
    );
}

#[tokio::test]
async fn pipeline_detects_brute_force() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bruteforce.json");
    let events: Vec<_> = (0..5).map(|_| login_failure("SERVER02")).collect();
    write_jsonl(&path, &events).await;

    let report = run(base_config(vec![path])).await.unwrap();

    assert_eq!(report.events_processed, 5);
    assert!(report.detections.iter().any(|d| d.rule_id == "AUTH-BRUTE-001"));
    assert_eq!(report.summary.high, 1);
}

#[tokio::test]
async fn no_source_returns_error() {
    let result = run(base_config(vec![])).await;
    assert!(result.is_err(), "running without sources should return an error");
}

#[tokio::test]
async fn empty_file_no_detections() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("empty.json");
    tokio::fs::write(&path, "").await.unwrap();

    let report = run(base_config(vec![path])).await.unwrap();
    assert_eq!(report.events_processed, 0);
    assert!(report.detections.is_empty());
    assert_eq!(report.score.score, 0);
    assert_eq!(report.summary.total, 0);
}

#[tokio::test]
async fn combined_score_reaches_likely_compromise() {
    let dir  = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("combined.json");
    let mut events = vec![ps_creation(), network_conn(), service_install()];
    for _ in 0..5 { events.push(login_failure("SRV02")); }
    write_jsonl(&path, &events).await;

    let report = run(base_config(vec![path])).await.unwrap();
    assert!(
        report.score.score >= 60,
        "combined score should reach LIKELY_COMPROMISE (got {})",
        report.score.score
    );
    assert!(report.summary.total >= 2);
}

#[tokio::test]
async fn multi_file_ingestion() {
    let dir = tempfile::TempDir::new().unwrap();

    let path1 = dir.path().join("ps.json");
    write_jsonl(&path1, &[ps_creation(), network_conn(), service_install()]).await;

    let path2 = dir.path().join("brute.json");
    let events: Vec<_> = (0..5).map(|_| login_failure("DC01")).collect();
    write_jsonl(&path2, &events).await;

    let report = run(base_config(vec![path1, path2])).await.unwrap();

    assert_eq!(report.events_processed, 8);
    assert!(report.detections.iter().any(|d| d.rule_id == "PS-LATERAL-001"));
    assert!(report.detections.iter().any(|d| d.rule_id == "AUTH-BRUTE-001"));
}
