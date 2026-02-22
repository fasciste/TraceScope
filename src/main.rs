use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tracescope::app::runner::{run, OutputFormat, RunConfig};
use tracescope::output::{cli as cli_out, json as json_out, web as web_out};

#[derive(Parser)]
#[command(
    name    = "tracescope",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Next-generation async forensic correlation engine",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingest files, correlate events, and produce a threat report.
    Ingest {
        /// EVTX file (repeatable, native parser)
        #[arg(long, value_name = "FILE", num_args = 1)]
        evtx: Vec<PathBuf>,

        /// PCAP file (repeatable, native parser)
        #[arg(long, value_name = "FILE", num_args = 1)]
        pcap: Vec<PathBuf>,

        /// Syslog file (repeatable)
        #[arg(long, value_name = "FILE", num_args = 1)]
        syslog: Vec<PathBuf>,

        /// JSON-lines event file (repeatable)
        #[arg(long, value_name = "FILE", num_args = 1)]
        json: Vec<PathBuf>,

        /// Sigma YAML rule file (repeatable, stacks on top of built-ins)
        #[arg(long, value_name = "FILE", num_args = 1)]
        sigma: Vec<PathBuf>,

        /// Only process events from this host (repeatable, case-insensitive)
        #[arg(long, value_name = "HOST", num_args = 1)]
        filter_host: Vec<String>,

        /// Disable a built-in rule by ID (repeatable, e.g. PS-LATERAL-001)
        #[arg(long, value_name = "RULE_ID", num_args = 1)]
        disable_rule: Vec<String>,

        /// Output format: cli (default) | json | web
        #[arg(long, default_value = "cli", value_name = "FORMAT")]
        output: String,

        /// Correlation window in seconds
        #[arg(long, default_value = "120", value_name = "SECS")]
        window: u64,

        /// Export Prometheus metrics on this port (e.g. 9090)
        #[arg(long, value_name = "PORT")]
        metrics_port: Option<u16>,

        /// Port for the web dashboard (with --output web)
        #[arg(long, default_value = "3000", value_name = "PORT")]
        web_port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
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
        Commands::Ingest {
            evtx, pcap, syslog, json, sigma,
            filter_host, disable_rule,
            output, window, metrics_port, web_port,
        } => {
            let fmt = match output.as_str() {
                "json" => OutputFormat::Json,
                "web"  => OutputFormat::Web,
                _      => OutputFormat::Cli,
            };

            let config = RunConfig {
                evtx_paths:     evtx,
                pcap_paths:     pcap,
                syslog_paths:   syslog,
                json_paths:     json,
                sigma_paths:    sigma,
                output_format:  fmt.clone(),
                window_secs:    window as i64,
                metrics_port,
                web_port,
                filter_hosts:   filter_host,
                disabled_rules: disable_rule,
            };

            let report = run(config).await?;

            match fmt {
                OutputFormat::Cli  => cli_out::print_report(&report),
                OutputFormat::Json => json_out::print_report(&report)?,
                OutputFormat::Web  => web_out::serve(report, web_port).await?,
            }
        }
    }

    Ok(())
}
