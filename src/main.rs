use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tracescope::app::runner::{run, OutputFormat, RunConfig};
use tracescope::output::{cli as cli_out, json as json_out};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "tracescope",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Next-generation async forensic correlation engine",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingest one or more sources, correlate events, and produce a report.
    ///
    /// Flags can be repeated to supply multiple files of the same type:
    ///   tracescope ingest --json host1.json --json host2.json
    ///   tracescope ingest --evtx security.evtx --pcap traffic.pcap
    ///   tracescope ingest --json events.json --output json > report.json
    Ingest {
        /// Path(s) to EVTX / JSON-lines EVTX export (repeatable).
        #[arg(long, value_name = "FILE", num_args = 1)]
        evtx: Vec<PathBuf>,

        /// Path(s) to PCAP / JSON-lines PCAP export (repeatable).
        #[arg(long, value_name = "FILE", num_args = 1)]
        pcap: Vec<PathBuf>,

        /// Path(s) to syslog file (repeatable).
        #[arg(long, value_name = "FILE", num_args = 1)]
        syslog: Vec<PathBuf>,

        /// Path(s) to JSON-lines event file (repeatable).
        #[arg(long, value_name = "FILE", num_args = 1)]
        json: Vec<PathBuf>,

        /// Output format: `cli` (default) or `json`.
        #[arg(long, default_value = "cli", value_name = "FORMAT")]
        output: String,

        /// Correlation window in seconds (default 120).
        #[arg(long, default_value = "120", value_name = "SECS")]
        window: u64,
    },
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise tracing.  Honour RUST_LOG; fall back to info-level for the
    // tracescope crate.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tracescope=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Ingest { evtx, pcap, syslog, json, output, window } => {
            let fmt = match output.as_str() {
                "json" => OutputFormat::Json,
                _      => OutputFormat::Cli,
            };

            let config = RunConfig {
                evtx_paths:    evtx,
                pcap_paths:    pcap,
                syslog_paths:  syslog,
                json_paths:    json,
                output_format: fmt.clone(),
                window_secs:   window as i64,
            };

            let report = run(config).await?;

            match fmt {
                OutputFormat::Json => json_out::print_report(&report)?,
                OutputFormat::Cli  => cli_out::print_report(&report),
            }
        }
    }

    Ok(())
}
