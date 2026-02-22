use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{bail, Result};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::domain::event::RawEvent;
use crate::domain::score::ScoreEngine;
use crate::error::TracescopeError;
use crate::ingestion::{Ingestor, evtx::EvtxIngestor, json::JsonIngestor,
                       pcap::PcapIngestor, syslog::SyslogIngestor};
use crate::output::{DetectionSummary, ForensicReport};
use crate::pipeline::{correlator::Correlator, dispatcher::Dispatcher, normalizer::Normalizer};
use crate::rules::{builtin, engine::RuleEngine, sigma};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat { Cli, Json, Web }

#[derive(Debug)]
pub struct RunConfig {
    pub evtx_paths:     Vec<PathBuf>,
    pub pcap_paths:     Vec<PathBuf>,
    pub syslog_paths:   Vec<PathBuf>,
    pub json_paths:     Vec<PathBuf>,
    pub sigma_paths:    Vec<PathBuf>,
    pub output_format:  OutputFormat,
    pub window_secs:    i64,
    pub metrics_port:   Option<u16>,
    pub web_port:       u16,
    pub filter_hosts:   Vec<String>,
    pub disabled_rules: Vec<String>,
}

pub async fn run(config: RunConfig) -> Result<ForensicReport> {
    let ingestors = build_ingestors(&config)?;
    if ingestors.is_empty() {
        bail!(TracescopeError::NoSource);
    }

    if let Some(port) = config.metrics_port {
        if let Err(e) = crate::metrics::init(port) {
            warn!(error = %e, "Failed to start metrics endpoint");
        }
    }

    info!(sources = ingestors.len(), window = config.window_secs, "Pipeline starting");
    let start = Instant::now();

    let (raw_tx, raw_rx)       = mpsc::channel::<RawEvent>(1_024);
    let (norm_tx, norm_rx)     = mpsc::channel::<crate::domain::event::Event>(1_024);
    let (bc_tx, _bc_rx_unused) = broadcast::channel::<crate::domain::event::Event>(1_024);
    let (det_tx, mut det_rx)   = mpsc::channel::<crate::domain::detection::Detection>(256);

    let correlator   = Arc::new(Correlator::new(config.window_secs));
    let score_engine = ScoreEngine::new();
    let events_ctr   = Arc::new(AtomicU64::new(0));

    let mut ingest_set: JoinSet<()> = JoinSet::new();
    for ingestor in ingestors {
        let tx = raw_tx.clone();
        ingest_set.spawn(async move {
            let name = ingestor.name().to_owned();
            if let Err(e) = ingestor.ingest(tx).await {
                tracing::error!(ingestor = name, error = %e, "Ingestor failed");
            }
        });
    }
    drop(raw_tx);

    let normalizer = Normalizer::new().with_filter_hosts(config.filter_hosts.clone());
    let ctr_clone  = Arc::clone(&events_ctr);
    let norm_task  = tokio::spawn(async move {
        normalizer.run(raw_rx, norm_tx, ctr_clone).await;
    });

    let bc_tx_disp = bc_tx.clone();
    let corr_disp  = Arc::clone(&correlator);
    let disp_task  = tokio::spawn(async move {
        Dispatcher::new(corr_disp, bc_tx_disp).run(norm_rx).await;
    });

    let event_rx = bc_tx.subscribe();
    drop(bc_tx);

    let mut rules = builtin::load_all();
    for path in &config.sigma_paths {
        match sigma::load_from_path(path) {
            Ok(rule) => {
                info!(path = %path.display(), id = rule.id(), "Sigma rule loaded");
                rules.push(rule);
            }
            Err(e) => warn!(path = %path.display(), error = %e, "Failed to load Sigma rule"),
        }
    }
    if !config.disabled_rules.is_empty() {
        rules.retain(|r| !config.disabled_rules.iter().any(|id| id == r.id()));
        info!(disabled = config.disabled_rules.join(", "), "Rules disabled");
    }

    let corr_eng    = Arc::clone(&correlator);
    let det_tx_eng  = det_tx.clone();
    let engine_task = tokio::spawn(async move {
        RuleEngine::new(rules, corr_eng, event_rx, det_tx_eng).run().await;
    });
    drop(det_tx);

    let mut detections = Vec::new();
    while let Some(det) = det_rx.recv().await {
        crate::metrics::detection_fired(&det.rule_id, &det.severity.to_string());
        score_engine.increment(det.score_contribution);
        detections.push(det);
    }

    while let Some(res) = ingest_set.join_next().await {
        if let Err(e) = res { tracing::error!(error = %e, "Ingestor panicked"); }
    }
    if let Err(e) = norm_task.await   { tracing::error!(error = %e, "Normalizer panicked"); }
    if let Err(e) = disp_task.await   { tracing::error!(error = %e, "Dispatcher panicked"); }
    if let Err(e) = engine_task.await { tracing::error!(error = %e, "Rule engine panicked"); }

    let events_processed = events_ctr.load(Ordering::Relaxed);
    let duration_secs    = start.elapsed().as_secs_f64();
    let summary          = DetectionSummary::from_detections(&detections);

    crate::metrics::set_score(score_engine.get());
    crate::metrics::pipeline_duration(duration_secs);

    info!(
        events = events_processed, detections = detections.len(),
        score = score_engine.get(), threat = %score_engine.threat_level(),
        "Pipeline complete"
    );

    Ok(ForensicReport {
        generated_at:     chrono::Utc::now(),
        duration_secs,
        events_processed,
        score:            score_engine.snapshot(),
        summary,
        detections,
    })
}

fn build_ingestors(config: &RunConfig) -> Result<Vec<Box<dyn Ingestor>>> {
    let mut list: Vec<Box<dyn Ingestor>> = Vec::new();
    for p in &config.evtx_paths   { list.push(Box::new(EvtxIngestor::new(p)));   }
    for p in &config.pcap_paths   { list.push(Box::new(PcapIngestor::new(p)));   }
    for p in &config.syslog_paths { list.push(Box::new(SyslogIngestor::new(p))); }
    for p in &config.json_paths   { list.push(Box::new(JsonIngestor::new(p)));   }
    Ok(list)
}
