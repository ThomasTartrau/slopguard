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
use std::sync::OnceLock;

use clap::Parser;
use strsim::normalized_levenshtein;
use thiserror::Error;

use slopguard_core::baseline::BaselineError;
use slopguard_core::cache::project_cache_dir;
use slopguard_core::config::{load_config, load_config_file, Config, ConfigError, ProjectTrust};
use slopguard_core::git::GitError;
use slopguard_core::preset::{presets_help, Preset};
use slopguard_core::rule::{
    is_rule_active, load_all_rules, load_effective_rules, Category, Rule, RuleError,
};
use slopguard_core::sanitize::sanitize_control;
use slopguard_core::scanner::ScanError;
use slopguard_core::source::{
    default_allowed_protocols, default_cache_root, git_token_from_env, resolve_sources,
    unpinned_source_warnings, ResolvedSource, SourceError, SourceOptions,
};
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
    #[error("{0}")]
    Source(#[from] SourceError),
}

/// Resolve the external rule sources declared in `config`, cloning or
/// refreshing git sources (unless `offline`). Shared by every subcommand that
/// loads rules. Each git source not pinned to a commit sha is reported on
/// stderr first, and the token is only bound to the user's trusted host.
pub(crate) fn resolve_config_sources(
    config: &Config,
    offline: bool,
) -> Result<Vec<ResolvedSource>, AppError> {
    for warning in unpinned_source_warnings(&config.rules.sources) {
        // CLI diagnostic to stderr, not application logging.
        // slopguard-disable-next-line no-println-in-prod
        eprintln!("warning: {warning}");
    }
    let opts = SourceOptions {
        cache_root: default_cache_root(),
        offline,
        git_token: git_token_from_env(config.git.token_host.as_deref()),
        allowed_protocols: default_allowed_protocols(),
    };
    Ok(resolve_sources(&config.rules.sources, &opts)?)
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
            project_cache_dir(&cwd)
        })
}

/// Trust granted to the scanned repo's `slopguard.toml`, set once from
/// `--trust-repo-config` so every subcommand loads config the same way.
static REPO_TRUST: OnceLock<ProjectTrust> = OnceLock::new();

/// The trust set by `--trust-repo-config`, untrusted by default.
fn repo_trust() -> ProjectTrust {
    REPO_TRUST.get().copied().unwrap_or_default()
}

/// Load the config: the explicit `--config` file (trusted, chosen by the
/// user), or the global config merged with the repo's `slopguard.toml`.
/// Reserved keys dropped from an untrusted repo file are reported on stderr.
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
            let loaded = load_config(&cwd, repo_trust())?;
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            Ok(loaded.config)
        }
    }
}

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
    REPO_TRUST.get_or_init(|| trust);

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
