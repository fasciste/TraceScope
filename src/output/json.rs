use anyhow::Result;
use super::ForensicReport;

/// Serialize the report to pretty-printed JSON on stdout.
pub fn print_report(report: &ForensicReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

/// Serialize the report to a compact JSON string (for piping / storage).
pub fn to_string(report: &ForensicReport) -> Result<String> {
    Ok(serde_json::to_string(report)?)
}
