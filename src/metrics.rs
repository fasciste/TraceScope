use anyhow::Result;

pub fn init(port: u16) -> Result<()> {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()?;
    tracing::info!(port, "Prometheus metrics endpoint started at /metrics");
    Ok(())
}

#[inline]
pub fn event_ingested(source: &str) {
    metrics::counter!("tracescope_events_total", "source" => source.to_owned()).increment(1);
}

#[inline]
pub fn detection_fired(rule_id: &str, severity: &str) {
    metrics::counter!(
        "tracescope_detections_total",
        "rule"     => rule_id.to_owned(),
        "severity" => severity.to_owned()
    ).increment(1);
}

#[inline]
pub fn set_score(score: u32) {
    metrics::gauge!("tracescope_threat_score").set(score as f64);
}

#[inline]
pub fn pipeline_duration(secs: f64) {
    metrics::histogram!("tracescope_pipeline_duration_seconds").record(secs);
}
