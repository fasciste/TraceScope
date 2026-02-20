/// Pipeline orchestrator.
///
/// Creates all channels, spawns async tasks for each pipeline stage, waits
/// for the cascade shutdown, and returns a `ForensicReport`.
///
/// Shutdown cascade (automatic, no explicit signals needed):
///   Ingestors finish
///     → raw_tx all dropped  → Normalizer sees channel EOF
///     → norm_tx dropped     → Dispatcher sees channel EOF → drops broadcast sender
///     → broadcast Closed    → Rule engine breaks loop     → drops detection_tx
///     → detection_tx dropped → collection loop sees None  → ForensicReport built
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{bail, Result};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tracing::info;

use crate::domain::event::RawEvent;
use crate::domain::score::ScoreEngine;
use crate::error::TracescopeError;
use crate::ingestion::{
    Ingestor,
    evtx::EvtxIngestor,
    json::JsonIngestor,
    pcap::PcapIngestor,
    syslog::SyslogIngestor,
};
use crate::output::{DetectionSummary, ForensicReport};
use crate::pipeline::{
    correlator::Correlator,
    dispatcher::Dispatcher,
    normalizer::Normalizer,
};
use crate::rules::{
    builtin,
    engine::RuleEngine,
};

// ─── Configuration ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat { Json, Cli }

/// Everything the runner needs to start the pipeline.
///
/// Each source field is a `Vec` so the caller can supply multiple files of
/// the same type (e.g. `--json a.json --json b.json`).
#[derive(Debug)]
pub struct RunConfig {
    pub evtx_paths:    Vec<PathBuf>,
    pub pcap_paths:    Vec<PathBuf>,
    pub syslog_paths:  Vec<PathBuf>,
    pub json_paths:    Vec<PathBuf>,
    pub output_format: OutputFormat,
    /// Correlation window in seconds (default 120).
    pub window_secs:   i64,
}

// ─── Runner ───────────────────────────────────────────────────────────────────

/// Entry point: wire the pipeline and drive it to completion.
pub async fn run(config: RunConfig) -> Result<ForensicReport> {
    // ── 0. Validate inputs ────────────────────────────────────────────────────
    let ingestors = build_ingestors(&config)?;
    if ingestors.is_empty() {
        bail!(TracescopeError::NoSource);
    }

    info!(
        sources  = ingestors.len(),
        window   = config.window_secs,
        "TraceScope pipeline starting"
    );

    let start = Instant::now();

    // ── 1. Create bounded channels ────────────────────────────────────────────
    //
    //   raw      : ingestors → normalizer          (1 024 RawEvents)
    //   norm     : normalizer → dispatcher         (1 024 Events)
    //   broadcast: dispatcher → rule engines       (1 024 Events, fan-out)
    //   detection: rule engine → collection loop   (  256 Detections)
    let (raw_tx, raw_rx)       = mpsc::channel::<RawEvent>(1_024);
    let (norm_tx, norm_rx)     = mpsc::channel::<crate::domain::event::Event>(1_024);
    let (bc_tx, _bc_rx_unused) = broadcast::channel::<crate::domain::event::Event>(1_024);
    let (det_tx, mut det_rx)   = mpsc::channel::<crate::domain::detection::Detection>(256);

    // ── 2. Shared state ───────────────────────────────────────────────────────
    let correlator   = Arc::new(Correlator::new(config.window_secs));
    let score_engine = ScoreEngine::new();
    let events_ctr   = Arc::new(AtomicU64::new(0));

    // ── 3. Spawn ingestor tasks ───────────────────────────────────────────────
    // Each ingestor owns a clone of raw_tx.  When ALL clones are dropped (all
    // ingestors finished), the normalizer's raw_rx.recv() returns None.
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
    drop(raw_tx); // Original sender dropped; only per-task clones remain.

    // ── 4. Normalizer task ────────────────────────────────────────────────────
    let ctr_clone = Arc::clone(&events_ctr);
    let norm_task = tokio::spawn(async move {
        Normalizer::new().run(raw_rx, norm_tx, ctr_clone).await;
    });
    // When raw_rx is exhausted, normalizer drops norm_tx → dispatcher sees EOF.

    // ── 5. Dispatcher task ────────────────────────────────────────────────────
    let bc_tx_disp = bc_tx.clone();
    let corr_disp  = Arc::clone(&correlator);
    let disp_task  = tokio::spawn(async move {
        Dispatcher::new(corr_disp, bc_tx_disp).run(norm_rx).await;
    });
    // When disp_task finishes it drops bc_tx_disp.  We also drop bc_tx below,
    // so the broadcast channel closes and the rule engine sees Closed.

    // ── 6. Rule engine task ───────────────────────────────────────────────────
    let event_rx   = bc_tx.subscribe();
    drop(bc_tx);                          // Only dispatcher's clone remains.

    let rules      = builtin::load_all();
    let corr_eng   = Arc::clone(&correlator);
    let det_tx_eng = det_tx.clone();

    let engine_task = tokio::spawn(async move {
        RuleEngine::new(rules, corr_eng, event_rx, det_tx_eng).run().await;
    });
    drop(det_tx); // Only engine's clone remains → det_rx gets None when engine exits.

    // ── 7. Collect detections (drives the cascade to completion) ─────────────
    let mut detections = Vec::new();

    while let Some(detection) = det_rx.recv().await {
        score_engine.increment(detection.score_contribution);
        detections.push(detection);
    }
    // det_rx returned None → engine task has already exited.

    // ── 8. Join remaining tasks ───────────────────────────────────────────────
    while let Some(res) = ingest_set.join_next().await {
        if let Err(e) = res { tracing::error!(error = %e, "Ingestor task panicked"); }
    }
    if let Err(e) = norm_task.await   { tracing::error!(error = %e, "Normalizer panicked"); }
    if let Err(e) = disp_task.await   { tracing::error!(error = %e, "Dispatcher panicked"); }
    if let Err(e) = engine_task.await { tracing::error!(error = %e, "Rule engine panicked"); }

    let events_processed = events_ctr.load(Ordering::Relaxed);
    let duration_secs    = start.elapsed().as_secs_f64();
    let summary          = DetectionSummary::from_detections(&detections);

    info!(
        events     = events_processed,
        detections = detections.len(),
        score      = score_engine.get(),
        duration   = duration_secs,
        threat     = %score_engine.threat_level(),
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_ingestors(config: &RunConfig) -> Result<Vec<Box<dyn Ingestor>>> {
    let mut list: Vec<Box<dyn Ingestor>> = Vec::new();

    for p in &config.evtx_paths   { list.push(Box::new(EvtxIngestor::new(p)));   }
    for p in &config.pcap_paths   { list.push(Box::new(PcapIngestor::new(p)));   }
    for p in &config.syslog_paths { list.push(Box::new(SyslogIngestor::new(p))); }
    for p in &config.json_paths   { list.push(Box::new(JsonIngestor::new(p)));   }

    Ok(list)
}
