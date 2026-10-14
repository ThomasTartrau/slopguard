mod ai_phase;
mod app;
mod baseline_cmd;
mod cli;
mod fix_exec;
mod output;
mod scan_exec;
mod stats_cmd;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use slopguard_core::config::ProjectTrust;
use slopguard_core::preset::{presets_help, Preset};
use slopguard_core::rule::{is_rule_active, load_all_rules, load_effective_rules, Category};
use slopguard_core::sanitize::sanitize_control;
use slopguard_core::testing::{self, RuleTestStatus, TestFailureKind};

use crate::app::set_repo_trust;
use crate::baseline_cmd::{run_baseline, BaselineOpts};
use crate::cli::{CategoryFilter, Cli, Command, Format, LanguageFilter};
use crate::output::json::{self, ListEntry};
use crate::output::text;
use crate::scan_exec::{run_scan, ScanOpts};
use crate::stats_cmd::{run_stats, StatsOpts};

// Shared with every subcommand module and the HTML renderer, which reach these
// by their crate-root path.
pub(crate) use crate::app::{
    resolve_cache_dir, resolve_config, resolve_config_sources, suggest_similar, AppError,
};
pub(crate) use crate::scan_exec::{collect_findings, language_for_path, CollectOpts};

fn run_explain(
    rule_id: String,
    format: Option<Format>,
    config_path: Option<PathBuf>,
    offline: bool,
) -> Result<(), AppError> {
    let config = resolve_config(config_path.as_deref())?;
    let sources = resolve_config_sources(&config, offline)?;
    let rules = load_all_rules(&config, &sources)?;

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

fn run_test(config_path: Option<PathBuf>, offline: bool) -> Result<bool, AppError> {
    let config = resolve_config(config_path.as_deref())?;
    let sources = resolve_config_sources(&config, offline)?;
    let rules = load_effective_rules(&config, &sources)?;
    let summary = testing::test_rules(&rules)?;

    for result in &summary.results {
        match &result.status {
            RuleTestStatus::Pass => {
                println!("  PASS  {}", sanitize_control(result.rule_id.as_str()));
            }
            RuleTestStatus::Fail { failures } => {
                println!("  FAIL  {}", sanitize_control(result.rule_id.as_str()));
                for failure in failures {
                    match &failure.kind {
                        TestFailureKind::ShouldMatchDidNot => println!(
                            "        should_match did not match: {}",
                            sanitize_control(failure.snippet.lines().next().unwrap_or(""))
                        ),
                        TestFailureKind::ShouldNotMatchDid => println!(
                            "        should_not_match matched: {}",
                            sanitize_control(failure.snippet.lines().next().unwrap_or(""))
                        ),
                        TestFailureKind::FixMismatch { actual } => println!(
                            "        should_fix mismatch: {} -> got {}",
                            sanitize_control(failure.snippet.lines().next().unwrap_or("")),
                            sanitize_control(actual.lines().next().unwrap_or(""))
                        ),
                    }
                }
            }
            RuleTestStatus::NoTests => {
                println!(
                    "  WARN  {} - no tests",
                    sanitize_control(result.rule_id.as_str())
                );
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
    offline: bool,
) -> Result<(), AppError> {
    let config = resolve_config(config_path.as_deref())?;

    let sources = resolve_config_sources(&config, offline)?;
    let rules = if show_all {
        load_all_rules(&config, &sources)?
    } else {
        load_effective_rules(&config, &sources)?
    };

    let entries: Vec<ListEntry> = rules
        .iter()
        .map(|r| ListEntry {
            id: sanitize_control(r.id.as_str()).into_owned(),
            language: r.language.to_string(),
            severity: r.severity.to_string(),
            category: r
                .category
                .as_ref()
                .unwrap_or(&Category::Correctness)
                .to_string(),
            kind: json::rule_kind(r).to_string(),
            source: r.origin.label(),
            status: if is_rule_active(r, &config) {
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

    let status_w = filtered
        .iter()
        .map(|e| e.status.len())
        .max()
        .unwrap_or(6)
        .max(6);

    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  {:<status_w$}  source",
        "id", "language", "severity", "category", "type", "status"
    );
    println!(
        "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  {:<status_w$}  ------",
        "--", "--------", "--------", "--------", "----", "------"
    );
    for e in &filtered {
        println!(
            "{:<id_w$}  {:<lang_w$}  {:<sev_w$}  {:<cat_w$}  {:<kind_w$}  {:<status_w$}  {}",
            e.id, e.language, e.severity, e.category, e.kind, e.status, e.source
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
    let trust = if cli.trust_repo_config {
        ProjectTrust::Trusted
    } else {
        ProjectTrust::Untrusted
    };
    // Stored before any subcommand loads config.
    set_repo_trust(trust);

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
            report_unused_disable,
            diff,
            base,
            fix,
            dry_run,
            allow_dirty,
            offline,
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
            report_unused_disable,
            diff,
            base,
            fix,
            dry_run,
            allow_dirty,
            offline,
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
            offline,
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
            offline,
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
            offline,
        } => match run_baseline(BaselineOpts {
            paths,
            output,
            config_path: config,
            cli_disable,
            cli_enable,
            no_cache,
            cache_dir,
            no_ai,
            offline,
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
            offline,
        } => match run_explain(rule_id, format, config, offline) {
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
        Command::Test { config, offline } => match run_test(config, offline) {
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
            offline,
        } => match run_list(all, category, language, format, config, offline) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
    }
}
