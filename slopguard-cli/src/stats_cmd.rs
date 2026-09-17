//! The `stats` subcommand: aggregate findings into a distribution report.

use std::collections::HashMap;
use std::env;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use slopguard_core::config::OutputFormat;
use slopguard_core::finding::ScanResult;
use slopguard_core::rule::{Category, Language, Severity};

use crate::baseline_cmd::apply_baseline;
use crate::cli::Format;
use crate::output::stats::{format_stats_json, format_stats_text};
use crate::{collect_findings, language_for_path, AppError, CollectOpts};

/// How many rules the report keeps in `top_rules`.
pub const TOP_RULES: usize = 10;
/// How many files the report keeps in `top_files`.
pub const TOP_FILES: usize = 5;

#[derive(Debug, Clone, Default, Serialize)]
pub struct BySeverity {
    pub error: usize,
    pub warning: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ByCategory {
    pub slop: usize,
    pub security: usize,
    pub correctness: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ByLanguage {
    pub rust: usize,
    pub typescript: usize,
    /// Findings in files with no known rule language. Normally 0, omitted then.
    #[serde(skip_serializing_if = "is_zero")]
    pub other: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileCount {
    pub file: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsReport {
    pub total: usize,
    pub files_scanned: usize,
    pub baseline_filtered: usize,
    pub by_severity: BySeverity,
    pub by_category: ByCategory,
    pub by_language: ByLanguage,
    pub top_rules: Vec<RuleCount>,
    pub top_files: Vec<FileCount>,
}

/// Aggregate a scan result into the distribution report `stats` prints.
///
/// Totals come from `result.stats` rather than from the findings vector, so
/// the report always agrees with the summary line `scan` prints for the same
/// run. Call this after `apply_baseline` so the counts are post-filter.
pub fn compute_report(result: &ScanResult) -> StatsReport {
    let mut by_severity = BySeverity::default();
    let mut by_category = ByCategory::default();
    let mut by_language = ByLanguage::default();
    let mut rule_tally: HashMap<&str, usize> = HashMap::new();
    let mut file_tally: HashMap<&Path, usize> = HashMap::new();

    for f in &result.findings {
        match f.severity {
            Severity::Error => by_severity.error += 1,
            Severity::Warning => by_severity.warning += 1,
        }
        match f.category {
            Category::Slop => by_category.slop += 1,
            Category::Security => by_category.security += 1,
            Category::Correctness => by_category.correctness += 1,
        }
        match language_for_path(&f.file) {
            Some(Language::Rust) => by_language.rust += 1,
            Some(Language::TypeScript) => by_language.typescript += 1,
            None => by_language.other += 1,
        }
        *rule_tally.entry(f.rule_id.as_str()).or_insert(0) += 1;
        *file_tally.entry(f.file.as_path()).or_insert(0) += 1;
    }

    let mut top_rules = Vec::with_capacity(rule_tally.len());
    for (rule_id, count) in rule_tally {
        top_rules.push(RuleCount {
            rule_id: rule_id.to_string(),
            count,
        });
    }
    // Count descending, then rule id ascending so ties are deterministic.
    top_rules.sort_by(|a, b| (b.count, &a.rule_id).cmp(&(a.count, &b.rule_id)));
    top_rules.truncate(TOP_RULES);

    let mut top_files = Vec::with_capacity(file_tally.len());
    for (file, count) in file_tally {
        top_files.push(FileCount {
            file: file.display().to_string(),
            count,
        });
    }
    top_files.sort_by(|a, b| (b.count, &a.file).cmp(&(a.count, &b.file)));
    top_files.truncate(TOP_FILES);

    StatsReport {
        total: result.stats.total,
        files_scanned: result.stats.files_scanned,
        baseline_filtered: result.stats.baseline_filtered,
        by_severity,
        by_category,
        by_language,
        top_rules,
        top_files,
    }
}

pub struct StatsOpts {
    pub paths: Vec<PathBuf>,
    pub format: Option<Format>,
    pub config_path: Option<PathBuf>,
    pub no_colors: bool,
    pub cli_disable: Vec<String>,
    pub cli_enable: Vec<String>,
    pub rule_filter: Option<String>,
    pub no_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_ai: bool,
    pub no_baseline: bool,
    pub baseline_path: Option<PathBuf>,
}

/// Run the same pipeline as `scan`, then print the aggregated distribution
/// instead of the individual findings.
///
/// Always exits 0 when it ran successfully, findings or not: like `list` and
/// `explain` this is a reporting command, and a non-zero exit would break
/// `slopguard stats --format json | jq ...` under `set -o pipefail`.
pub fn run_stats(opts: StatsOpts) -> Result<(), AppError> {
    let StatsOpts {
        paths,
        format,
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
    } = opts;
    let use_colors = !no_colors && env::var_os("NO_COLOR").is_none();

    if let Some(Format::Sarif) = format {
        eprintln!("error: SARIF format is not supported for stats");
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SARIF format is not supported for stats",
        )));
    }

    if let Some(Format::Html) = format {
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTML format is not supported for stats",
        )));
    }

    let (mut result, config) = collect_findings(CollectOpts {
        paths,
        config_path,
        cli_disable,
        cli_enable,
        rule_filter,
        no_cache,
        cache_dir,
        no_ai,
        diff: false,
        diff_base: None,
    })?;

    let _baseline_active = apply_baseline(&mut result, no_baseline, baseline_path)?;

    // A config-level `format = "sarif"` or `"html"` falls back to text rather
    // than failing: only an explicit `--format sarif|html` is an error.
    let format = format.unwrap_or(match config.output.format {
        OutputFormat::Text => Format::Text,
        OutputFormat::Json => Format::Json,
        OutputFormat::Sarif | OutputFormat::Html => Format::Text,
    });

    let report = compute_report(&result);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    match format {
        Format::Json => format_stats_json(&report, &mut out)?,
        Format::Text | Format::Sarif | Format::Html => {
            format_stats_text(&report, &mut out, use_colors)?
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use slopguard_core::finding::{Finding, ScanResult, ScanStats};
    use slopguard_core::rule::{Category, Severity};

    use super::compute_report;

    fn finding(rule_id: &str, severity: Severity, category: Category, file: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category,
            message: "m".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from(file),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
        }
    }

    fn result_of(findings: Vec<Finding>) -> ScanResult {
        let mut errors = 0;
        let mut warnings = 0;
        for f in &findings {
            match f.severity {
                Severity::Error => errors += 1,
                Severity::Warning => warnings += 1,
            }
        }
        ScanResult {
            findings,
            stats: ScanStats {
                errors,
                warnings,
                total: errors + warnings,
                files_scanned: 3,
                baseline_filtered: 0,
                diff_base: None,
                files_changed: None,
            },
            cache_stats: None,
        }
    }

    #[test]
    fn counts_by_severity() {
        let result = result_of(vec![
            finding("a", Severity::Error, Category::Slop, "a.rs"),
            finding("b", Severity::Error, Category::Slop, "b.rs"),
            finding("c", Severity::Warning, Category::Slop, "c.rs"),
        ]);

        let report = compute_report(&result);
        assert_eq!(report.by_severity.error, 2);
        assert_eq!(report.by_severity.warning, 1);
    }

    #[test]
    fn counts_by_category() {
        let result = result_of(vec![
            finding("a", Severity::Warning, Category::Slop, "a.rs"),
            finding("b", Severity::Warning, Category::Security, "b.rs"),
            finding("c", Severity::Warning, Category::Correctness, "c.rs"),
        ]);

        let report = compute_report(&result);
        assert_eq!(report.by_category.slop, 1);
        assert_eq!(report.by_category.security, 1);
        assert_eq!(report.by_category.correctness, 1);
    }

    #[test]
    fn counts_by_language_from_extension() {
        let result = result_of(vec![
            finding("a", Severity::Warning, Category::Slop, "a.rs"),
            finding("b", Severity::Warning, Category::Slop, "b.ts"),
            finding("c", Severity::Warning, Category::Slop, "c.tsx"),
        ]);

        let report = compute_report(&result);
        assert_eq!(report.by_language.rust, 1);
        assert_eq!(report.by_language.typescript, 2);
        assert_eq!(report.by_language.other, 0);
    }

    #[test]
    fn unknown_extension_counts_as_other() {
        let f = finding("a", Severity::Warning, Category::Slop, "a.py");

        let report = compute_report(&result_of(vec![f]));
        assert_eq!(report.by_language.other, 1);
        assert_eq!(report.by_language.rust, 0);
    }

    #[test]
    fn top_rules_capped_at_ten() {
        let mut findings = Vec::new();
        for i in 0..12 {
            let id = format!("rule-{i:02}");
            findings.push(finding(&id, Severity::Warning, Category::Slop, "a.rs"));
        }

        let report = compute_report(&result_of(findings));
        assert_eq!(report.top_rules.len(), 10);
    }

    #[test]
    fn top_files_capped_at_five() {
        let mut findings = Vec::new();
        for i in 0..7 {
            let file = format!("file-{i}.rs");
            findings.push(finding("a", Severity::Warning, Category::Slop, &file));
        }

        let report = compute_report(&result_of(findings));
        assert_eq!(report.top_files.len(), 5);
    }

    #[test]
    fn top_rules_sorted_by_count_then_id() {
        let mut findings = Vec::new();
        for _ in 0..2 {
            findings.push(finding("b", Severity::Warning, Category::Slop, "a.rs"));
            findings.push(finding("a", Severity::Warning, Category::Slop, "a.rs"));
        }
        for _ in 0..3 {
            findings.push(finding("c", Severity::Warning, Category::Slop, "a.rs"));
        }

        let report = compute_report(&result_of(findings));
        assert_eq!(report.top_rules[0].rule_id, "c");
        assert_eq!(report.top_rules[1].rule_id, "a");
        assert_eq!(report.top_rules[2].rule_id, "b");
    }

    #[test]
    fn empty_result_has_zeroed_axes() {
        let report = compute_report(&result_of(Vec::new()));

        assert_eq!(report.total, 0);
        assert_eq!(report.by_severity.error, 0);
        assert_eq!(report.by_severity.warning, 0);
        assert_eq!(report.by_category.slop, 0);
        assert_eq!(report.by_category.security, 0);
        assert_eq!(report.by_category.correctness, 0);
        assert_eq!(report.by_language.rust, 0);
        assert_eq!(report.by_language.typescript, 0);
        assert!(report.top_rules.is_empty());
        assert!(report.top_files.is_empty());
    }

    #[test]
    fn report_uses_scan_stats_for_totals() {
        let f = finding("a", Severity::Warning, Category::Slop, "a.rs");
        let mut result = result_of(vec![f]);
        result.stats.baseline_filtered = 4;

        let report = compute_report(&result);
        assert_eq!(report.baseline_filtered, 4);
        assert_eq!(report.total, result.stats.total);
        assert_eq!(report.files_scanned, 3);
    }
}
