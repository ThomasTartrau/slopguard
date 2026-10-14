//! Scan execution: resolving rules, running the AST pass (cached or not) and
//! the AI phase (`ai_phase`), then rendering the report. `--fix` is delegated
//! to `fix_exec`. `collect_findings` is shared with the `baseline` and `stats`
//! subcommands.

use std::env;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use slopguard_core::config::{Config, OutputFormat};
use slopguard_core::escalation::apply_escalation;
use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::git::changed_files;
use slopguard_core::rule::{load_effective_rules, Language, Rule, Severity};
use slopguard_core::scanner::{
    count_severities, scan, scan_cached, scan_files, scan_files_cached, scan_files_unused_disables,
    scan_unused_disables, ScanError,
};
use slopguard_core::source::RuleOrigin;

use crate::ai_phase::{run_ai_phase, warn_external_ai_skipped};
use crate::baseline_cmd::apply_baseline;
use crate::cli::{Format, SeverityThreshold};
use crate::fix_exec::{run_fix, FixOpts};
use crate::output::html::{project_name, HtmlMeta};
use crate::output::{html, json, sarif, text};
use crate::stats_cmd::compute_report;
use crate::{resolve_cache_dir, resolve_config, resolve_config_sources, suggest_similar, AppError};

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
    html_meta: &HtmlMeta,
    rules: &[Rule],
) -> io::Result<()> {
    match format {
        Format::Text => text::format_text(result, w, use_colors),
        Format::Json => json::format_json(result, w),
        Format::Sarif => sarif::format_sarif(result, rules, w),
        Format::Html => html::format_html(result, &compute_report(result), html_meta, w),
    }
}

pub(crate) struct ScanOpts {
    pub paths: Vec<PathBuf>,
    pub format: Option<Format>,
    pub output: Option<PathBuf>,
    pub severity_threshold: SeverityThreshold,
    pub config_path: Option<PathBuf>,
    pub no_colors: bool,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub cli_test_paths: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_ai: bool,
    pub no_baseline: bool,
    pub baseline_path: Option<PathBuf>,
    pub no_escalation: bool,
    pub report_unused_disable: bool,
    pub diff: bool,
    pub base: Option<String>,
    pub fix: bool,
    pub dry_run: bool,
    pub allow_dirty: bool,
    pub offline: bool,
}

/// Options shared by `scan` and `baseline`, which collect findings the same
/// way and only differ in what they do with them.
pub struct CollectOpts {
    pub paths: Vec<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub cli_test_paths: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_ai: bool,
    pub report_unused: bool,
    pub diff: bool,
    pub diff_base: Option<String>,
    pub offline: bool,
}

/// Where the AST pass looks: directory roots to walk (normal scan), or the
/// exact list of files git reported as changed (`--diff`).
pub(crate) enum ScanTargets {
    Walk(Vec<PathBuf>),
    Files(Vec<PathBuf>),
}

impl ScanTargets {
    pub(crate) fn run(
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
pub(crate) fn under_requested_paths(files: Vec<PathBuf>, paths: &[PathBuf]) -> Vec<PathBuf> {
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
/// resolved config and the rules that were scanned with.
pub fn collect_findings(opts: CollectOpts) -> Result<(ScanResult, Config, Vec<Rule>), AppError> {
    let CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        cli_test_paths,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        report_unused,
        diff,
        diff_base,
        offline,
    } = opts;

    let mut config = resolve_config(config_path.as_deref())?;
    config.rules.disable.extend(cli_disable);
    config.rules.enable.extend(cli_enable);
    config.scan.test_paths.extend(cli_test_paths);

    let sources = resolve_config_sources(&config, offline)?;
    let mut rules = load_effective_rules(&config, &sources)?;
    retain_requested_rules(&mut rules, rule_filter.as_deref(), no_ai)?;

    let targets = if diff {
        let cwd = env::current_dir().map_err(AppError::Io)?;
        let changed = under_requested_paths(changed_files(&cwd, diff_base.as_deref())?, &paths);
        ScanTargets::Files(changed)
    } else {
        ScanTargets::Walk(paths)
    };

    let result = scan_with_rules(
        targets,
        rules.clone(),
        &config,
        no_cache,
        cache_dir,
        report_unused,
        diff_base,
    )?;
    Ok((result, config, rules))
}

/// Narrow the loaded rules to the `--rule` filter (an unknown id is an error,
/// with a suggestion) and, with `--no-ai`, drop the AI rules.
pub(crate) fn retain_requested_rules(
    rules: &mut Vec<Rule>,
    rule_filter: Option<&str>,
    no_ai: bool,
) -> Result<(), AppError> {
    if let Some(filter_id) = rule_filter {
        let found = rules.iter().any(|r| r.id.as_str() == filter_id);
        if !found {
            let suggestion = suggest_similar(filter_id, rules);
            // CLI diagnostics to stderr, not application logging (as in `main.rs`).
            if let Some(suggested) = suggestion {
                // slopguard-disable-next-line no-println-in-prod
                eprintln!("error: unknown rule '{filter_id}'. Did you mean '{suggested}'?");
            } else {
                // slopguard-disable-next-line no-println-in-prod
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
    Ok(())
}

/// Run the AST pass (cached or not), the AI pass and the unused-disable report
/// over `targets` with already resolved `rules` and `config`. `diff_base` is
/// only recorded in the stats of a `--diff` run (`ScanTargets::Files`).
pub(crate) fn scan_with_rules(
    targets: ScanTargets,
    rules: Vec<Rule>,
    config: &Config,
    no_cache: bool,
    cache_dir: Option<PathBuf>,
    report_unused: bool,
    diff_base: Option<String>,
) -> Result<ScanResult, AppError> {
    let (mut ai_rules, ast_rules): (Vec<Rule>, Vec<Rule>) =
        rules.into_iter().partition(|r| r.ai_check.is_some());

    // External AI rules (custom dirs, sources) carry prompts the user never
    // reviewed and send code to the provider, so they need the user's opt-in.
    // They are dropped, not downgraded to AST rules, so their unconfirmed
    // candidates never surface as findings.
    if !config.ai.allow_external_rules {
        let before = ai_rules.len();
        ai_rules.retain(|r| r.origin == RuleOrigin::Builtin);
        warn_external_ai_skipped(before - ai_rules.len());
    }

    let resolved_cache_dir = resolve_cache_dir(cache_dir, config);
    let mut result = targets.run(&ast_rules, config, no_cache, &resolved_cache_dir)?;

    if !ai_rules.is_empty() {
        let ai_findings = run_ai_phase(&targets, &ai_rules, config, no_cache, &resolved_cache_dir)?;
        if !ai_findings.is_empty() {
            merge_findings(&mut result, ai_findings);
        }
    }

    // A disable's consumption is judged against the AST-level matches of every
    // active rule (AI rules included, pre-LLM), so the report is stable and
    // independent of the provider. Uses the same targets, so `--diff` only looks
    // at changed files.
    if report_unused {
        let mut all_rules = ast_rules;
        all_rules.extend(ai_rules);
        let unused = match &targets {
            ScanTargets::Walk(p) => scan_unused_disables(p, &all_rules, config)?,
            ScanTargets::Files(f) => scan_files_unused_disables(f, &all_rules, config)?,
        };
        if !unused.is_empty() {
            merge_findings(&mut result, unused);
        }
    }

    // Set last, so the AI merge cannot drop the diff metadata.
    if let ScanTargets::Files(ref files) = targets {
        result.stats.diff_base = Some(diff_base.unwrap_or_else(|| "HEAD".to_string()));
        result.stats.files_changed = Some(files.len());
    }

    Ok(result)
}

pub(crate) fn run_scan(opts: ScanOpts) -> Result<bool, AppError> {
    let ScanOpts {
        paths,
        format,
        output,
        severity_threshold,
        config_path,
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
    } = opts;
    let use_colors = !no_colors && env::var_os("NO_COLOR").is_none();

    if fix {
        return run_fix(FixOpts {
            paths,
            config_path,
            cli_disable,
            cli_enable,
            cli_test_paths,
            rule_filter,
            no_ai,
            no_baseline,
            baseline_path,
            dry_run,
            allow_dirty,
            offline,
        });
    }

    // `paths` is moved into CollectOpts below, so derive the title first.
    let project = project_name(&paths);

    let (mut result, config, rules) = collect_findings(CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        cli_test_paths,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        report_unused: report_unused_disable,
        diff,
        diff_base: base,
        offline,
    })?;

    let baseline_active = apply_baseline(&mut result, no_baseline, baseline_path)?;

    // After the baseline (suppressed findings must not inflate the per-file
    // count) and before the severity threshold, so an escalated finding can
    // fail a `--severity-threshold error` run.
    if !no_escalation {
        apply_escalation(&mut result, &config.escalation);
    }

    let format = format.unwrap_or(match config.output.format {
        OutputFormat::Text => Format::Text,
        OutputFormat::Json => Format::Json,
        OutputFormat::Sarif => Format::Sarif,
        OutputFormat::Html => Format::Html,
    });

    let has_findings = has_findings_above_threshold(&result, &severity_threshold);

    let html_meta = HtmlMeta {
        project_name: project,
        generated_at_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        baseline_active,
    };

    match output {
        Some(path) => {
            let file = fs::File::create(&path)?;
            let mut w = BufWriter::new(file);
            // A file is never a terminal: never emit ANSI escapes into it.
            write_output(&result, &format, &mut w, false, &html_meta, &rules)?;
            w.flush()?;
        }
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            write_output(&result, &format, &mut out, use_colors, &html_meta, &rules)?;
        }
    }

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

/// Find the rule that produced a finding, matching on id
/// and (when possible) the file's language, so a shared id across Rust and
/// TypeScript resolves to the right variant.
pub(crate) fn find_rule<'a>(rules: &'a [Rule], finding: &Finding) -> Option<&'a Rule> {
    let lang = language_for_path(&finding.file);
    rules
        .iter()
        .find(|r| r.id == finding.rule_id && Some(&r.language) == lang.as_ref())
        .or_else(|| rules.iter().find(|r| r.id == finding.rule_id))
}

/// Merge extra findings (AI-confirmed, or synthetic `unused-disable`) into the
/// AST result, keeping ordering, dedup, and severity counts consistent
/// (`files_scanned` is preserved).
fn merge_findings(result: &mut ScanResult, extra: Vec<Finding>) {
    result.findings.extend(extra);
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
