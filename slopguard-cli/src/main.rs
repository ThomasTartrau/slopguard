mod baseline_cmd;
mod cli;
mod output;
mod stats_cmd;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use strsim::normalized_levenshtein;
use thiserror::Error;

use slopguard_ai::{build_provider, run_ai_pass, AiCache, AiCandidate, DEFAULT_MODEL};
use slopguard_core::baseline::BaselineError;
use slopguard_core::config::{load_config, load_config_file, Config, ConfigError, OutputFormat};
use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::git::{changed_files, GitError};
use slopguard_core::rule::{
    is_rule_active, load_all_rules, load_builtin_rules, load_effective_rules, Category, Language,
    Rule, RuleError, Severity,
};
use slopguard_core::scanner::{
    count_severities, scan, scan_cached, scan_files, scan_files_cached, ScanError,
};
use slopguard_core::testing::{self, RuleTestStatus, TestError, TestFailureKind};

use crate::baseline_cmd::{apply_baseline, run_baseline, BaselineOpts};
use crate::cli::{CategoryFilter, Cli, Command, Format, LanguageFilter, SeverityThreshold};
use crate::output::{json, sarif, text};
use crate::stats_cmd::{run_stats, StatsOpts};

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

fn suggest_similar<'a>(id: &str, rules: &'a [Rule]) -> Option<&'a str> {
    rules
        .iter()
        .map(|r| (r.id.as_str(), normalized_levenshtein(id, r.id.as_str())))
        .filter(|(_, score)| *score >= 0.6)
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal))
        .map(|(id, _)| id)
}

struct ScanOpts {
    paths: Vec<PathBuf>,
    format: Option<Format>,
    severity_threshold: SeverityThreshold,
    config_path: Option<PathBuf>,
    no_colors: bool,
    cli_disable: Vec<String>,
    cli_enable: Vec<String>,
    rule_filter: Option<String>,
    no_cache: bool,
    cache_dir: Option<PathBuf>,
    no_ai: bool,
    no_baseline: bool,
    baseline_path: Option<PathBuf>,
    diff: bool,
    base: Option<String>,
}

/// Options shared by `scan` and `baseline`, which collect findings the same
/// way and only differ in what they do with them.
pub struct CollectOpts {
    pub paths: Vec<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_ai: bool,
    pub diff: bool,
    pub diff_base: Option<String>,
}

/// Where the AST pass looks: directory roots to walk (normal scan), or the
/// exact list of files git reported as changed (`--diff`).
enum ScanTargets {
    Walk(Vec<PathBuf>),
    Files(Vec<PathBuf>),
}

impl ScanTargets {
    fn run(
        &self,
        rules: &[Rule],
        config: &Config,
        no_cache: bool,
        cache_dir: &Path,
    ) -> Result<ScanResult, ScanError> {
        match (self, no_cache) {
            (ScanTargets::Walk(p), true) => scan(p, rules, config),
            (ScanTargets::Walk(p), false) => scan_cached(p, rules, config, cache_dir),
            (ScanTargets::Files(f), true) => scan_files(f, rules, config),
            (ScanTargets::Files(f), false) => scan_files_cached(f, rules, config, cache_dir),
        }
    }
}

/// Keep the changed files that live under one of the requested paths, so
/// `slopguard scan src/ --diff` stays scoped to `src/`.
///
/// Paths that cannot be canonicalized are compared as given.
fn under_requested_paths(files: Vec<PathBuf>, paths: &[PathBuf]) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = paths
        .iter()
        .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
        .collect();
    files
        .into_iter()
        .filter(|file| {
            let resolved = file.canonicalize().unwrap_or_else(|_| file.clone());
            roots.iter().any(|root| resolved.starts_with(root))
        })
        .collect()
}

/// Resolve the config, load the active rules, run the AST pass (cached or
/// not) then the AI pass, and return the raw unfiltered result along with the
/// resolved config.
pub fn collect_findings(opts: CollectOpts) -> Result<(ScanResult, Config), AppError> {
    let CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        diff,
        diff_base,
    } = opts;

    let mut config = resolve_config(config_path.as_deref())?;
    config.rules.disable.extend(cli_disable);
    config.rules.enable.extend(cli_enable);

    let mut rules = load_effective_rules(&config)?;

    if let Some(ref filter_id) = rule_filter {
        let found = rules.iter().any(|r| r.id.as_str() == filter_id);
        if !found {
            let suggestion = suggest_similar(filter_id, &rules);
            if let Some(suggested) = suggestion {
                eprintln!("error: unknown rule '{filter_id}'. Did you mean '{suggested}'?");
            } else {
                eprintln!("error: unknown rule '{filter_id}'");
            }
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown rule '{filter_id}'"),
            )));
        }
        rules.retain(|r| r.id.as_str() == filter_id);
    }

    // --no-ai: exclude AI rules entirely so their AST pre-filter matches
    // never appear as unconfirmed findings.
    if no_ai {
        rules.retain(|r| r.ai_check.is_none());
    }

    let (ai_rules, ast_rules): (Vec<Rule>, Vec<Rule>) =
        rules.into_iter().partition(|r| r.ai_check.is_some());

    let targets = if diff {
        let cwd = env::current_dir().map_err(AppError::Io)?;
        let changed = under_requested_paths(changed_files(&cwd, diff_base.as_deref())?, &paths);
        ScanTargets::Files(changed)
    } else {
        ScanTargets::Walk(paths)
    };

    let resolved_cache_dir = resolve_cache_dir(cache_dir, &config);
    let mut result = targets.run(&ast_rules, &config, no_cache, &resolved_cache_dir)?;

    if !ai_rules.is_empty() {
        let ai_findings =
            run_ai_phase(&targets, &ai_rules, &config, no_cache, &resolved_cache_dir)?;
        if !ai_findings.is_empty() {
            merge_ai_findings(&mut result, ai_findings);
        }
    }

    // Set last, so the AI merge cannot drop the diff metadata.
    if let ScanTargets::Files(ref files) = targets {
        result.stats.diff_base = Some(diff_base.unwrap_or_else(|| "HEAD".to_string()));
        result.stats.files_changed = Some(files.len());
    }

    Ok((result, config))
}

fn run_scan(opts: ScanOpts) -> Result<bool, AppError> {
    let ScanOpts {
        paths,
        format,
        severity_threshold,
        config_path,
        no_colors,
        cli_disable,
        cli_enable,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        no_baseline,
        baseline_path,
        diff,
        base,
    } = opts;
    let use_colors = !no_colors && env::var_os("NO_COLOR").is_none();

    let (mut result, config) = collect_findings(CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        diff,
        diff_base: base,
    })?;

    apply_baseline(&mut result, no_baseline, baseline_path)?;

    let format = format.unwrap_or(match config.output.format {
        OutputFormat::Text => Format::Text,
        OutputFormat::Json => Format::Json,
        OutputFormat::Sarif => Format::Sarif,
    });

    let has_findings = has_findings_above_threshold(&result, &severity_threshold);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_output(&result, &format, &mut out, use_colors)?;

    Ok(has_findings)
}

/// Map a file path to the rule language it is scanned as.
pub(crate) fn language_for_path(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Some(Language::Rust),
        Some("ts" | "tsx") => Some(Language::TypeScript),
        _ => None,
    }
}

/// Find the `ai_check` rule that produced a candidate finding, matching on id
/// and (when possible) the file's language, so a shared id across Rust and
/// TypeScript resolves to the right variant.
fn find_ai_rule<'a>(ai_rules: &'a [Rule], finding: &Finding) -> Option<&'a Rule> {
    let lang = language_for_path(&finding.file);
    ai_rules
        .iter()
        .find(|r| r.id == finding.rule_id && Some(&r.language) == lang.as_ref())
        .or_else(|| ai_rules.iter().find(|r| r.id == finding.rule_id))
}

/// Turn AST candidate findings into AI candidates: attach each rule's prompt,
/// resolved model, and the file content used for context and cache keys. Files
/// are read once each; unreadable files or unmatched findings are skipped.
fn build_candidates(
    findings: Vec<Finding>,
    ai_rules: &[Rule],
    config: &Config,
) -> Vec<AiCandidate> {
    let mut contents: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut candidates = Vec::new();
    for finding in findings {
        let Some(rule) = find_ai_rule(ai_rules, &finding) else {
            continue;
        };
        let Some(ai_check) = rule.ai_check.as_ref() else {
            continue;
        };
        let content = contents
            .entry(finding.file.clone())
            .or_insert_with(|| fs::read_to_string(&finding.file).ok());
        let Some(file_content) = content.clone() else {
            continue;
        };
        let model = ai_check
            .model
            .clone()
            .or_else(|| config.ai.model.clone())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        let rule_context = rule.note.clone().unwrap_or_else(|| rule.message.clone());
        candidates.push(AiCandidate {
            finding,
            file_content,
            prompt_template: ai_check.prompt.clone(),
            model,
            rule_context,
        });
    }
    candidates
}

/// Merge AI-confirmed findings into the AST result, keeping ordering, dedup,
/// and severity counts consistent (`files_scanned` is preserved).
fn merge_ai_findings(result: &mut ScanResult, ai_findings: Vec<Finding>) {
    result.findings.extend(ai_findings);
    result
        .findings
        .sort_by(|a, b| (&a.file, a.line, a.column).cmp(&(&b.file, b.line, b.column)));
    result.findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
    });
    let (errors, warnings) = count_severities(&result.findings);
    result.stats.errors = errors;
    result.stats.warnings = warnings;
    result.stats.total = errors + warnings;
}

/// Run the AI confirmation phase for `ai_rules`.
///
/// When the provider cannot be built (disabled, missing credentials), a single
/// warning is emitted and no LLM call is made. Otherwise the AST pre-filter
/// produces candidates that the LLM confirms.
fn run_ai_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    let provider = match build_provider(&config.ai) {
        Ok(provider) => provider,
        Err(err) => {
            // Clear, credential-specific reason (disabled, missing API key,
            // missing claude binary, missing OAuth token). Non-fatal: the AST
            // findings still stand.
            eprintln!("warning: {} AI rules skipped ({err})", ai_rules.len());
            return Ok(Vec::new());
        }
    };

    // Pre-filter: run the AST patterns of the AI rules to collect candidates.
    let candidate_result = targets.run(ai_rules, config, true, cache_dir)?;
    if candidate_result.findings.is_empty() {
        return Ok(Vec::new());
    }
    let candidates = build_candidates(candidate_result.findings, ai_rules, config);
    let cache = (!no_cache).then(|| AiCache::new(cache_dir));
    Ok(run_ai_pass(
        &*provider,
        candidates,
        config.ai.concurrency,
        cache.as_ref(),
    ))
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

const DEFAULT_CONFIG: &str = r#"[rulesets]
slop = true
security = true
correctness = true

[rules]
disable = []
# Opt-in rules (disabled by default): pub-fn-needs-tracing, test-needs-timeout
enable = []
# custom_dirs = ["./my-rules"]

[scan]
ignores = []
# cache_dir = ".slopguard-cache"

[output]
format = "text"
colors = true

# [ai]
# enabled = false
# provider = "api"        # "api" (HTTP) | "cli" (local claude)
# vendor = "anthropic"    # "anthropic" | "openai" (for provider = "api")
# model = "claude-haiku-4-5"
# concurrency = 4
# api_key via ANTHROPIC_API_KEY / OPENAI_API_KEY env, or ai.api_key
"#;

fn resolve_cache_dir(cli_flag: Option<PathBuf>, config: &Config) -> PathBuf {
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
    kind: String,
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
            kind: if r.ai_check.is_some() {
                "ai".to_string()
            } else {
                "ast".to_string()
            },
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
            cli_disable,
            cli_enable,
            rule_filter,
            no_cache,
            cache_dir,
            no_ai,
            no_baseline,
            baseline_path,
            diff,
            base,
        } => match run_scan(ScanOpts {
            paths,
            format,
            severity_threshold,
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
            diff,
            base,
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
