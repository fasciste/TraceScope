/// TraceScope — Next-generation async forensic correlation engine.
///
/// Architecture: hexagonal / clean architecture
///   domain/     → Core types (Event, Detection, Rule trait, ScoreEngine)
///   ingestion/  → Async ingestors (EVTX, Syslog, PCAP, JSON)
///   pipeline/   → Normalizer, Correlator (sliding window), Dispatcher
///   rules/      → Async rule engine + built-in detection rules
///   output/     → JSON / CLI report sinks
///   plugins/    → Extensible plugin system (feature-gated)
///   app/        → Orchestration layer (runner)
pub mod app;
pub mod domain;
pub mod error;
pub mod ingestion;
pub mod output;
pub mod pipeline;
pub mod plugins;
pub mod rules;
