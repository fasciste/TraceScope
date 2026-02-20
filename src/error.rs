use thiserror::Error;

#[derive(Debug, Error)]
pub enum TracescopeError {
    #[error("Ingestion error from '{origin}': {message}")]
    Ingestion { origin: String, message: String },

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Pipeline channel closed unexpectedly")]
    ChannelClosed,

    #[error("Rule evaluation error in rule '{rule_id}': {message}")]
    RuleEvaluation { rule_id: String, message: String },

    #[error("No ingestion source provided")]
    NoSource,
}
