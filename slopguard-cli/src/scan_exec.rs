//! Scan execution: resolving rules, running the AST pass (cached or not) and
//! the AI confirmation phase, then rendering the report. `collect_findings` is
//! shared with the `baseline` and `stats` subcommands.

use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use similar::TextDiff;
use slopguard_ai::{
    build_classifier, build_provider, resolve_jev_model, run_ai_pass, run_classifier_pass, AiCache,
    AiCandidate, BatchConfig, DEFAULT_MODEL,
};
use slopguard_core::baseline::{project_root, Baseline};
use slopguard_core::config::{Config, OutputFormat};
use slopguard_core::escalation::apply_escalation;
use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::fix::fix_paths;
use slopguard_core::git::{self, changed_files, GitError};
use slopguard_core::rule::{load_effective_rules, Language, ReasonMode, Rule, Severity};
use slopguard_core::scanner::{
    count_severities, scan, scan_cached, scan_files, scan_files_cached, scan_files_unused_disables,
    scan_unused_disables, ScanError,
};

use crate::baseline_cmd::{apply_baseline, resolve_baseline};
use crate::cli::{Format, SeverityThreshold};
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
) -> io::Result<()> {
    match format {
        Format::Text => text::format_text(result, w, use_colors),
        Format::Json => json::format_json(result, w),
        Format::Sarif => sarif::format_sarif(result, w),
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

    if let Some(ref filter_id) = rule_filter {
        let found = rules.iter().any(|r| r.id.as_str() == filter_id);
        if !found {
            let suggestion = suggest_similar(filter_id, &rules);
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
            ScanTargets::Walk(p) => scan_unused_disables(p, &all_rules, &config)?,
            ScanTargets::Files(f) => scan_files_unused_disables(f, &all_rules, &config)?,
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

    Ok((result, config))
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

    let (mut result, config) = collect_findings(CollectOpts {
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
            write_output(&result, &format, &mut w, false, &html_meta)?;
            w.flush()?;
        }
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            write_output(&result, &format, &mut out, use_colors, &html_meta)?;
        }
    }

    Ok(has_findings)
}

/// Options for the `scan --fix` flow, a subset of [`ScanOpts`]. Caching,
/// escalation, output format and severity threshold do not apply to rewriting.
pub(crate) struct FixOpts {
    pub paths: Vec<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub cli_test_paths: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_ai: bool,
    pub no_baseline: bool,
    pub baseline_path: Option<PathBuf>,
    pub dry_run: bool,
    pub allow_dirty: bool,
    pub offline: bool,
}

/// Refuse to rewrite files when the working tree has uncommitted changes under
/// the scanned paths. Outside a git repository there is nothing to guard, so it
/// passes silently. `--dry-run` and `--allow-dirty` skip this entirely.
fn guard_clean_tree(paths: &[PathBuf]) -> Result<(), AppError> {
    // Probe the repository that holds the scanned paths, not the process cwd, so
    // `slopguard scan /elsewhere --fix` guards the tree it will actually rewrite.
    let probe_dir = |p: &Path| -> PathBuf {
        let dir = if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent().map(Path::to_path_buf).unwrap_or_default()
        };
        // A bare filename has an empty parent; `git -C ""` would fail to spawn.
        if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        }
    };
    let probe = paths
        .first()
        .map(|p| probe_dir(p))
        .unwrap_or_else(|| PathBuf::from("."));
    let dirty = match git::dirty_files(&probe) {
        Ok(dirty) => dirty,
        Err(GitError::NotARepository { .. }) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let under = under_requested_paths(dirty, paths);
    if under.is_empty() {
        return Ok(());
    }
    // CLI diagnostic to stderr, not application logging.
    // slopguard-disable-next-line no-println-in-prod
    eprintln!(
        "error: {} uncommitted change(s) under the scanned paths; commit or stash \
         them, pass --allow-dirty to rewrite anyway, or preview with --dry-run",
        under.len()
    );
    Err(AppError::Io(io::Error::other(
        "refusing to --fix a dirty working tree",
    )))
}

/// Apply autofix-safe rewrites in place (or preview them with `--dry-run`).
///
/// Returns `true` when findings remain after the rewrite (exit code 1), `false`
/// when the tree is clean of findings or when previewing.
fn run_fix(opts: FixOpts) -> Result<bool, AppError> {
    let FixOpts {
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
    } = opts;

    let mut config = resolve_config(config_path.as_deref())?;
    config.rules.disable.extend(cli_disable.iter().cloned());
    config.rules.enable.extend(cli_enable.iter().cloned());
    config
        .scan
        .test_paths
        .extend(cli_test_paths.iter().cloned());

    let sources = resolve_config_sources(&config, offline)?;
    let mut rules = load_effective_rules(&config, &sources)?;
    if let Some(filter_id) = &rule_filter {
        rules.retain(|r| r.id.as_str() == filter_id);
    }
    if no_ai {
        rules.retain(|r| r.ai_check.is_none());
    }

    if !dry_run && !allow_dirty {
        guard_clean_tree(&paths)?;
    }

    let resolved = resolve_baseline(no_baseline, baseline_path.clone())?;
    let (baseline, baseline_root): (Option<&Baseline>, PathBuf) = match &resolved {
        Some((bl, root)) => (Some(bl), root.clone()),
        None => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            (None, project_root(&cwd))
        }
    };

    let report = fix_paths(&paths, &rules, &config, baseline, &baseline_root)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if dry_run {
        for file in &report.files {
            let rel = file.path.display().to_string();
            let diff = TextDiff::from_lines(file.original.as_str(), file.fixed.as_str());
            let unified = diff
                .unified_diff()
                .header(&format!("a/{rel}"), &format!("b/{rel}"))
                .to_string();
            write!(out, "{unified}")?;
        }
        writeln!(
            out,
            "Would apply {} fix(es) across {} file(s) (dry run, nothing written)",
            report.applied,
            report.files_changed()
        )?;
        return Ok(false);
    }

    for file in &report.files {
        fs::write(&file.path, &file.fixed)?;
    }

    // Re-scan from disk to report what could not be fixed; this drives the exit
    // code (0 only when no finding remains).
    let (mut result, _config) = collect_findings(CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        cli_test_paths,
        rule_filter,
        no_cache: true,
        cache_dir: None,
        no_ai,
        report_unused: false,
        diff: false,
        diff_base: None,
        offline,
    })?;
    apply_baseline(&mut result, no_baseline, baseline_path)?;
    let remaining = result.findings.len();

    writeln!(
        out,
        "Applied {} fix(es) across {} file(s); {} finding(s) remaining",
        report.applied,
        report.files_changed(),
        remaining
    )?;

    Ok(remaining > 0)
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
            reason_mode: ai_check.reason,
            threshold: ai_check.threshold,
            if_true: ai_check.if_true.clone(),
            if_false: ai_check.if_false.clone(),
        });
    }
    candidates
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

/// Run the AI phase for `ai_rules`: the System One classifier when
/// `[ai.classifier].enabled`, otherwise the generative LLM confirmation.
fn run_ai_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    if config.ai.classifier.enabled {
        return run_classifier_phase(targets, ai_rules, config, no_cache, cache_dir);
    }
    run_llm_phase(targets, ai_rules, config, no_cache, cache_dir)
}

/// Collect the AST pre-filter candidates for `ai_rules`, reading each matched
/// file once. Shared by the LLM and classifier phases.
fn collect_ai_candidates(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<Vec<AiCandidate>, AppError> {
    let candidate_result = targets.run(ai_rules, config, true, cache_dir)?;
    Ok(build_candidates(
        candidate_result.findings,
        ai_rules,
        config,
    ))
}

/// The single non-fatal warning for AI rules skipped because no provider could
/// be built: a clear, credential-specific reason (disabled, missing API key,
/// missing claude binary, missing OAuth token). The AST findings still stand.
fn warn_ai_skipped(ai_rules: &[Rule], err: &dyn Display) {
    // CLI diagnostic to stderr, not application logging.
    // slopguard-disable-next-line no-println-in-prod
    eprintln!("warning: {} AI rules skipped ({err})", ai_rules.len());
}

/// Classify candidates with the System One provider (Jev).
///
/// When the classifier cannot be built (disabled, missing key), a single
/// warning is emitted and no call is made. `generated` rules escalate to the
/// LLM for a per-instance reason when one is available.
fn run_classifier_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    let decider = match build_classifier(&config.ai.classifier) {
        Ok(decider) => decider,
        Err(err) => {
            warn_ai_skipped(ai_rules, &err);
            return Ok(Vec::new());
        }
    };

    let candidates = collect_ai_candidates(targets, ai_rules, config, cache_dir)?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // The LLM writes reasons for `generated` rules, so it is only built when
    // one is present. Optional: without it, those rules fall back to their
    // static note (handled inside the pass).
    let needs_llm = candidates
        .iter()
        .any(|c| c.reason_mode == ReasonMode::Generated);
    let llm = needs_llm.then(|| build_provider(&config.ai).ok()).flatten();
    let cache = (!no_cache).then(|| AiCache::new(cache_dir));
    let jev_model = resolve_jev_model(&config.ai.classifier);
    Ok(run_classifier_pass(
        &*decider,
        llm.as_deref(),
        candidates,
        &jev_model,
        config.ai.classifier.threshold,
        config.ai.concurrency,
        BatchConfig {
            batch: config.ai.classifier.batch,
            max_questions: config.ai.classifier.batch_max_questions,
            max_state_lines: config.ai.classifier.batch_max_state_lines,
        },
        cache.as_ref(),
    ))
}

/// Run the generative LLM confirmation phase for `ai_rules`.
///
/// When the provider cannot be built (disabled, missing credentials), a single
/// warning is emitted and no LLM call is made. Otherwise the AST pre-filter
/// produces candidates that the LLM confirms.
fn run_llm_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    let provider = match build_provider(&config.ai) {
        Ok(provider) => provider,
        Err(err) => {
            warn_ai_skipped(ai_rules, &err);
            return Ok(Vec::new());
        }
    };

    let candidates = collect_ai_candidates(targets, ai_rules, config, cache_dir)?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let cache = (!no_cache).then(|| AiCache::new(cache_dir));
    Ok(run_ai_pass(
        &*provider,
        candidates,
        config.ai.concurrency,
        cache.as_ref(),
    ))
}
