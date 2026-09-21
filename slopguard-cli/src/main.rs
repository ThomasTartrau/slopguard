mod baseline_cmd;
mod cli;
mod output;
mod scan_exec;
mod stats_cmd;

use std::cmp::Ordering;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use strsim::normalized_levenshtein;
use thiserror::Error;

use slopguard_core::baseline::BaselineError;
use slopguard_core::config::{load_config, load_config_file, Config, ConfigError};
use slopguard_core::git::GitError;
use slopguard_core::preset::{presets_help, Preset};
use slopguard_core::rule::{
    is_rule_active, load_all_rules, load_builtin_rules, load_effective_rules, Category, Rule,
    RuleError,
};
use slopguard_core::scanner::ScanError;
use slopguard_core::testing::{self, RuleTestStatus, TestError, TestFailureKind};

use crate::baseline_cmd::{run_baseline, BaselineOpts};
use crate::cli::{CategoryFilter, Cli, Command, Format, LanguageFilter};
use crate::output::json::{self, ListEntry};
use crate::output::text;
use crate::scan_exec::{run_scan, ScanOpts};
use crate::stats_cmd::{run_stats, StatsOpts};

// Shared with the `baseline` and `stats` subcommands and the HTML renderer,
// which reach these by their crate-root path.
pub(crate) use crate::scan_exec::{collect_findings, language_for_path, CollectOpts};

#[derive(Debug, Error)]
pub enum AppError {
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
    #[error("{0}")]
    Baseline(#[from] BaselineError),
    #[error("{0}")]
    Git(#[from] GitError),
}

/// The closest rule id to `id` by normalized edit distance, if one clears the
/// 0.6 similarity bar. Powers the "did you mean" hint for unknown rule ids.
pub(crate) fn suggest_similar<'a>(id: &str, rules: &'a [Rule]) -> Option<&'a str> {
    rules
        .iter()
        .map(|r| (r.id.as_str(), normalized_levenshtein(id, r.id.as_str())))
        .filter(|(_, score)| *score >= 0.6)
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal))
        .map(|(id, _)| id)
}

pub(crate) fn resolve_cache_dir(cli_flag: Option<PathBuf>, config: &Config) -> PathBuf {
    cli_flag
        .or_else(|| {
            env::var("SLOPGUARD_CACHE_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| config.scan.cache_dir.clone())
        .unwrap_or_else(|| {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            cwd.join(".slopguard-cache")
        })
}

pub(crate) fn resolve_config(config_path: Option<&Path>) -> Result<Config, AppError> {
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

fn run_explain(
    rule_id: String,
    format: Option<Format>,
    config_path: Option<PathBuf>,
) -> Result<(), AppError> {
    let config = resolve_config(config_path.as_deref())?;
    let rules = load_all_rules(&config)?;

    let rule = rules.iter().find(|r| r.id.as_str() == rule_id);
    match rule {
        Some(r) => {
            let format = format.unwrap_or(Format::Text);
            let stdout = io::stdout();
            let mut out = stdout.lock();
            match format {
                Format::Text => text::format_explain(r, &mut out),
                Format::Json => json::format_explain_json(r, &mut out),
                Format::Sarif => {
                    eprintln!("error: SARIF format is not supported for explain");
                    return Err(AppError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SARIF format is not supported for explain",
                    )));
                }
                Format::Html => {
                    return Err(AppError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTML format is not supported for explain",
                    )));
                }
            }?;
            Ok(())
        }
        None => {
            let suggestion = suggest_similar(&rule_id, &rules);
            if let Some(suggested) = suggestion {
                eprintln!("error: unknown rule '{rule_id}'. Did you mean '{suggested}'?");
            } else {
                eprintln!("error: unknown rule '{rule_id}'");
            }
            Err(AppError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown rule '{rule_id}'"),
            )))
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
                    match &failure.kind {
                        TestFailureKind::ShouldMatchDidNot => println!(
                            "        should_match did not match: {}",
                            failure.snippet.lines().next().unwrap_or("")
                        ),
                        TestFailureKind::ShouldNotMatchDid => println!(
                            "        should_not_match matched: {}",
                            failure.snippet.lines().next().unwrap_or("")
                        ),
                        TestFailureKind::FixMismatch { actual } => println!(
                            "        should_fix mismatch: {} -> got {}",
                            failure.snippet.lines().next().unwrap_or(""),
                            actual.lines().next().unwrap_or("")
                        ),
                    }
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

fn run_list(
    show_all: bool,
    category: Option<CategoryFilter>,
    language: Option<LanguageFilter>,
    format: Option<Format>,
    config_path: Option<PathBuf>,
) -> Result<(), AppError> {
    let config = resolve_config(config_path.as_deref())?;

    let rules = if show_all {
        load_builtin_rules()?
    } else {
        load_effective_rules(&config)?
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
            kind: json::rule_kind(r).to_string(),
            status: if !show_all || is_rule_active(r, &config) {
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

    match format {
        Some(Format::Json) => {
            return json::format_list_json(&filtered, &mut io::stdout().lock())
                .map_err(AppError::Io);
        }
        Some(Format::Sarif) => {
            eprintln!("error: SARIF format is not supported for list");
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SARIF format is not supported for list",
            )));
        }
        Some(Format::Html) => {
            eprintln!("error: HTML format is not supported for list");
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTML format is not supported for list",
            )));
        }
        None | Some(Format::Text) => {}
    }

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
    let kind_w = filtered
        .iter()
        .map(|e| e.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  status",
        "id", "language", "severity", "category", "type"
    );
    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  ------",
        "--", "--------", "--------", "--------", "----"
    );
    for e in &filtered {
        println!(
            "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  {}",
            e.id, e.language, e.severity, e.category, e.kind, e.status
        );
    }

    println!("\n{} rules", filtered.len());
    Ok(())
}

fn run_init(force: bool, preset: Option<Option<Preset>>) -> Result<(), AppError> {
    // `--preset` with no value lists the presets and writes nothing.
    if matches!(preset, Some(None)) {
        print!("{}", presets_help());
        return Ok(());
    }
    let preset = preset.flatten().unwrap_or_default();

    let config_path = Path::new("slopguard.toml");
    if config_path.exists() && !force {
        eprintln!("error: slopguard.toml already exists (use --force to overwrite)");
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "slopguard.toml already exists",
        )));
    }
    fs::write(config_path, preset.render()?)?;
    println!("Created slopguard.toml (preset: {preset})");
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            paths,
            format,
            output,
            severity_threshold,
            config,
            no_colors,
            cli_disable,
            cli_enable,
            cli_test_paths,
            rule_filter,
            no_cache,
            cache_dir,
            no_ai,
            no_baseline,
            baseline_path,
            no_escalation,
            diff,
            base,
            fix,
            dry_run,
            allow_dirty,
        } => match run_scan(ScanOpts {
            paths,
            format,
            output,
            severity_threshold,
            config_path: config,
            no_colors,
            cli_disable,
            cli_enable,
            cli_test_paths,
            rule_filter,
            no_cache,
            cache_dir,
            no_ai,
            no_baseline,
            baseline_path,
            no_escalation,
            diff,
            base,
            fix,
            dry_run,
            allow_dirty,
        }) {
            Ok(true) => ExitCode::from(1),
            Ok(false) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Stats {
            paths,
            format,
            config,
            no_colors,
            cli_disable,
            cli_enable,
            rule_filter,
            no_cache,
            cache_dir,
            no_ai,
            no_baseline,
            baseline_path,
            no_escalation,
        } => match run_stats(StatsOpts {
            paths,
            format,
            config_path: config,
            no_colors,
            cli_disable,
            cli_enable,
            rule_filter,
            no_cache,
            cache_dir,
            no_ai,
            no_baseline,
            baseline_path,
            no_escalation,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Baseline {
            paths,
            output,
            config,
            cli_disable,
            cli_enable,
            no_cache,
            cache_dir,
            no_ai,
        } => match run_baseline(BaselineOpts {
            paths,
            output,
            config_path: config,
            cli_disable,
            cli_enable,
            no_cache,
            cache_dir,
            no_ai,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Explain {
            rule_id,
            format,
            config,
        } => match run_explain(rule_id, format, config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Init { force, preset } => match run_init(force, preset) {
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
            format,
            category,
            language,
            config,
        } => match run_list(all, category, language, format, config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
    }
}
