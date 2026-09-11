mod output;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use thiserror::Error;

use slopguard_core::config::{load_config, load_config_file, ConfigError, OutputFormat};
use slopguard_core::finding::ScanResult;
use slopguard_core::rule::{load_effective_rules, RuleError, Severity};
use slopguard_core::scanner::{scan, ScanError};

use crate::output::{json, sarif, text};

#[derive(Parser)]
#[command(
    name = "slopguard",
    about = "Catch AI-generated code patterns and common issues"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum SeverityThreshold {
    Error,
    Warning,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files for findings
    Scan {
        /// Paths to scan (defaults to current directory)
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,

        /// Output format
        #[arg(long)]
        format: Option<Format>,

        /// Only exit non-zero for findings at or above this severity
        #[arg(long, default_value = "warning")]
        severity_threshold: SeverityThreshold,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable colored output
        #[arg(long)]
        no_colors: bool,
    },
    /// Generate a slopguard.toml config file
    Init,
    /// Validate inline tests for all rules
    Test,
    /// List active rules
    List,
}

fn has_findings_above_threshold(result: &ScanResult, threshold: &SeverityThreshold) -> bool {
    result.findings.iter().any(|f| match threshold {
        SeverityThreshold::Warning => true,
        SeverityThreshold::Error => f.severity == Severity::Error,
    })
}

fn write_output(
    result: &ScanResult,
    format: &Format,
    w: &mut impl Write,
    use_colors: bool,
) -> io::Result<()> {
    match format {
        Format::Text => text::format_text(result, w, use_colors),
        Format::Json => json::format_json(result, w),
        Format::Sarif => sarif::format_sarif(result, w),
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Rule(#[from] RuleError),
    #[error("{0}")]
    Scan(#[from] ScanError),
    #[error("{0}")]
    Io(#[from] io::Error),
}

fn run_scan(
    paths: Vec<PathBuf>,
    format: Option<Format>,
    severity_threshold: SeverityThreshold,
    config_path: Option<PathBuf>,
    no_colors: bool,
) -> Result<bool, AppError> {
    let use_colors = !no_colors && std::env::var_os("NO_COLOR").is_none();

    let config = match &config_path {
        Some(path) => load_config_file(path)?,
        None => {
            let cwd = std::env::current_dir().map_err(|e| {
                AppError::Config(ConfigError::Io {
                    path: ".".to_string(),
                    source: e,
                })
            })?;
            load_config(&cwd)?
        }
    };

    let format = format.unwrap_or(match config.output.format {
        OutputFormat::Text => Format::Text,
        OutputFormat::Json => Format::Json,
        OutputFormat::Sarif => Format::Sarif,
    });

    let rules = load_effective_rules(&config)?;
    let result = scan(&paths, &rules, &config)?;
    let has_findings = has_findings_above_threshold(&result, &severity_threshold);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_output(&result, &format, &mut out, use_colors)?;

    Ok(has_findings)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            paths,
            format,
            severity_threshold,
            config,
            no_colors,
        } => match run_scan(paths, format, severity_threshold, config, no_colors) {
            Ok(true) => ExitCode::from(1),
            Ok(false) => ExitCode::SUCCESS,
            Err(AppError::Config(e)) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
            Err(AppError::Rule(e)) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
            Err(AppError::Scan(e)) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
            Err(AppError::Io(e)) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Command::Init | Command::Test | Command::List => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_scan_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "."])
            .expect("scan subcommand should parse");
    }

    #[test]
    fn cli_parses_scan_subcommand_default_path() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan"])
            .expect("scan subcommand should parse without explicit path");
    }

    #[test]
    fn cli_parses_scan_with_format() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--format", "json", "."])
            .expect("scan with --format json should parse");
    }

    #[test]
    fn cli_parses_scan_with_severity_threshold() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--severity-threshold", "error", "."])
            .expect("scan with --severity-threshold should parse");
    }

    #[test]
    fn cli_parses_scan_with_config() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--config", "my.toml", "."])
            .expect("scan with --config should parse");
    }

    #[test]
    fn cli_parses_scan_with_no_colors() {
        Cli::command()
            .try_get_matches_from(["slopguard", "scan", "--no-colors", "."])
            .expect("scan with --no-colors should parse");
    }

    #[test]
    fn cli_parses_init_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "init"])
            .expect("init subcommand should parse");
    }

    #[test]
    fn cli_parses_test_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "test"])
            .expect("test subcommand should parse");
    }

    #[test]
    fn cli_parses_list_subcommand() {
        Cli::command()
            .try_get_matches_from(["slopguard", "list"])
            .expect("list subcommand should parse");
    }
}
