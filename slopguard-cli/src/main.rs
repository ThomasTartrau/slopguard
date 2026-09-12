mod output;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use thiserror::Error;

use slopguard_core::config::{load_config, load_config_file, Config, ConfigError, OutputFormat};
use slopguard_core::finding::ScanResult;
use slopguard_core::rule::{
    load_builtin_rules, load_effective_rules, Category, RuleError, Severity,
};
use slopguard_core::scanner::{scan, ScanError};
use slopguard_core::testing::{self, RuleTestStatus, TestError, TestFailureKind};

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

#[derive(Clone, ValueEnum)]
enum CategoryFilter {
    Slop,
    Security,
    Correctness,
}

#[derive(Clone, ValueEnum)]
enum LanguageFilter {
    Rust,
    Typescript,
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
    Init {
        /// Overwrite existing slopguard.toml
        #[arg(long)]
        force: bool,
    },
    /// Validate inline tests for all rules
    Test {
        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List active rules
    List {
        /// Show all rules including disabled ones
        #[arg(long)]
        all: bool,

        /// Filter by category
        #[arg(long)]
        category: Option<CategoryFilter>,

        /// Filter by language
        #[arg(long)]
        language: Option<LanguageFilter>,

        /// Path to a specific slopguard.toml config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
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
    Test(#[from] TestError),
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
    let use_colors = !no_colors && env::var_os("NO_COLOR").is_none();

    let config = resolve_config(config_path.as_deref())?;

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

const DEFAULT_CONFIG: &str = r#"[rulesets]
slop = true
security = true
correctness = true

[rules]
disable = []
# custom_dirs = ["./my-rules"]

[scan]
ignores = []

[output]
format = "text"
colors = true

# [ai]
# ai.enabled = false
# provider = "anthropic"
# model = "claude-sonnet-5"
"#;

fn resolve_config(config_path: Option<&Path>) -> Result<Config, AppError> {
    match config_path {
        Some(path) => Ok(load_config_file(path)?),
        None => {
            let cwd = env::current_dir().map_err(|e| {
                AppError::Config(ConfigError::Io {
                    path: ".".to_string(),
                    source: e,
                })
            })?;
            Ok(load_config(&cwd)?)
        }
    }
}

fn run_test(config_path: Option<PathBuf>) -> Result<bool, AppError> {
    let config = resolve_config(config_path.as_deref())?;
    let rules = load_effective_rules(&config)?;
    let summary = testing::test_rules(&rules)?;

    for result in &summary.results {
        match &result.status {
            RuleTestStatus::Pass => {
                println!("  PASS  {}", result.rule_id);
            }
            RuleTestStatus::Fail { failures } => {
                println!("  FAIL  {}", result.rule_id);
                for failure in failures {
                    let label = match failure.kind {
                        TestFailureKind::ShouldMatchDidNot => "should_match did not match",
                        TestFailureKind::ShouldNotMatchDid => "should_not_match matched",
                    };
                    println!(
                        "        {label}: {}",
                        failure.snippet.lines().next().unwrap_or("")
                    );
                }
            }
            RuleTestStatus::NoTests => {
                println!("  WARN  {} - no tests", result.rule_id);
            }
        }
    }

    println!(
        "\n{} rules tested, {} passed, {} failed",
        summary.total_tested, summary.passed, summary.failed
    );
    if summary.no_tests > 0 {
        println!("{} rules with no tests", summary.no_tests);
    }

    Ok(summary.failed > 0)
}

struct ListEntry {
    id: String,
    language: String,
    severity: String,
    category: String,
    status: String,
}

fn run_list(
    show_all: bool,
    category: Option<CategoryFilter>,
    language: Option<LanguageFilter>,
    config_path: Option<PathBuf>,
) -> Result<(), AppError> {
    let config = resolve_config(config_path.as_deref())?;

    let rules = if show_all {
        load_builtin_rules()?
    } else {
        load_effective_rules(&config)?
    };

    let is_enabled = |r: &slopguard_core::rule::Rule| -> bool {
        let cat_on = match r.category.as_ref().unwrap_or(&Category::Correctness) {
            Category::Slop => config.rulesets.slop,
            Category::Security => config.rulesets.security,
            Category::Correctness => config.rulesets.correctness,
        };
        cat_on && r.enabled && !config.rules.disable.iter().any(|d| d == r.id.as_str())
    };

    let entries: Vec<ListEntry> = rules
        .iter()
        .map(|r| ListEntry {
            id: r.id.to_string(),
            language: r.language.to_string(),
            severity: r.severity.to_string(),
            category: r
                .category
                .as_ref()
                .unwrap_or(&Category::Correctness)
                .to_string(),
            status: if !show_all || is_enabled(r) {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
        })
        .collect();

    let filtered: Vec<&ListEntry> = entries
        .iter()
        .filter(|e| match &category {
            Some(CategoryFilter::Slop) => e.category == "slop",
            Some(CategoryFilter::Security) => e.category == "security",
            Some(CategoryFilter::Correctness) => e.category == "correctness",
            None => true,
        })
        .filter(|e| match &language {
            Some(LanguageFilter::Rust) => e.language == "rust",
            Some(LanguageFilter::Typescript) => e.language == "typescript",
            None => true,
        })
        .collect();

    let id_w = filtered
        .iter()
        .map(|e| e.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let lang_w = filtered
        .iter()
        .map(|e| e.language.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let sev_w = filtered
        .iter()
        .map(|e| e.severity.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let cat_w = filtered
        .iter()
        .map(|e| e.category.len())
        .max()
        .unwrap_or(8)
        .max(8);

    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  status",
        "id", "language", "severity", "category"
    );
    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  ------",
        "--", "--------", "--------", "--------"
    );
    for e in &filtered {
        println!(
            "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {}",
            e.id, e.language, e.severity, e.category, e.status
        );
    }

    println!("\n{} rules", filtered.len());
    Ok(())
}

fn run_init(force: bool) -> Result<(), AppError> {
    let config_path = Path::new("slopguard.toml");
    if config_path.exists() && !force {
        eprintln!("error: slopguard.toml already exists (use --force to overwrite)");
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "slopguard.toml already exists",
        )));
    }
    fs::write(config_path, DEFAULT_CONFIG)?;
    println!("Created slopguard.toml");
    Ok(())
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
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Init { force } => match run_init(force) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        },
        Command::Test { config } => match run_test(config) {
            Ok(true) => ExitCode::from(1),
            Ok(false) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::List {
            all,
            category,
            language,
            config,
        } => match run_list(all, category, language, config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
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
