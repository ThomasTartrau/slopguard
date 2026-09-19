use std::io::{self, Write};

use serde::Serialize;

use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::metric::Metric;
use slopguard_core::rule::{Category, Language, Rule, Severity};

use crate::output::write_json_pretty;

#[derive(Serialize)]
struct JsonOutput<'a> {
    findings: &'a [Finding],
    /// Kept for backward compatibility with consumers written before `stats`.
    summary: &'a ScanSummary,
    stats: &'a JsonStats<'a>,
}

#[derive(Serialize)]
struct JsonStats<'a> {
    errors: usize,
    warnings: usize,
    total: usize,
    files_scanned: usize,
    /// Always emitted, `0` when no baseline applies, so CI can rely on it.
    baseline_filtered: usize,
    /// Present only in `--diff` mode: the ref the scan was diffed against.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_base: Option<&'a str>,
    /// Present only in `--diff` mode: how many changed files were selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    files_changed: Option<usize>,
}

#[derive(Serialize)]
struct ScanSummary {
    errors: usize,
    warnings: usize,
    total: usize,
}

/// One row of `slopguard list`, shared by the text table and the JSON output.
#[derive(Serialize)]
pub struct ListEntry {
    pub id: String,
    pub language: String,
    pub severity: String,
    pub category: String,
    /// "ast", "ai", "metric", or "cross-file".
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
}

/// The rule kind reported by `list` and `explain`.
pub fn rule_kind(rule: &Rule) -> &'static str {
    if rule.is_metric() {
        "metric"
    } else if rule.is_cross_file() {
        "cross-file"
    } else if rule.ai_check.is_some() {
        "ai"
    } else {
        "ast"
    }
}

/// `slopguard list --format json`, emitted as a top-level array so a consumer
/// can filter it directly (`jq '[.[] | select(.type == "metric")] | length'`).
// Part of the format_* public API surface of this module.
// slopguard-disable-next-line no-trivial-function
pub fn format_list_json(entries: &[&ListEntry], w: &mut impl Write) -> io::Result<()> {
    write_json_pretty(w, &entries)
}

#[derive(Serialize)]
struct ExplainOutput<'a> {
    id: &'a str,
    language: &'a Language,
    severity: &'a Severity,
    category: &'a Category,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'a str>,
    /// "metric" for file-level rules, "cross-file" for project-wide rules,
    /// "ai" for rules with an `ai_check`, "ast" otherwise.
    #[serde(rename = "type")]
    kind: &'a str,
    /// The measured file-level property, present only for metric rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<&'a Metric>,
    /// The value the metric must exceed, present only for metric rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<f64>,
    /// The LLM prompt template, present only for AI rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    should_match: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    should_not_match: Option<&'a [String]>,
}

pub fn format_explain_json(rule: &Rule, w: &mut impl Write) -> io::Result<()> {
    let default_category = Category::Correctness;
    let output = ExplainOutput {
        id: rule.id.as_str(),
        language: &rule.language,
        severity: &rule.severity,
        category: rule.category.as_ref().unwrap_or(&default_category),
        message: &rule.message,
        note: rule.note.as_deref(),
        fix: rule.fix.as_deref(),
        kind: rule_kind(rule),
        metric: rule.metric.as_ref(),
        threshold: rule.threshold,
        prompt: rule.ai_check.as_ref().map(|a| a.prompt.as_str()),
        should_match: rule.tests.as_ref().map(|t| t.should_match.as_slice()),
        should_not_match: rule.tests.as_ref().map(|t| t.should_not_match.as_slice()),
    };
    write_json_pretty(w, &output)
}

pub fn format_json(result: &ScanResult, w: &mut impl Write) -> io::Result<()> {
    let summary = ScanSummary {
        errors: result.stats.errors,
        warnings: result.stats.warnings,
        total: result.stats.total,
    };
    let stats = JsonStats {
        errors: result.stats.errors,
        warnings: result.stats.warnings,
        total: result.stats.total,
        files_scanned: result.stats.files_scanned,
        baseline_filtered: result.stats.baseline_filtered,
        diff_base: result.stats.diff_base.as_deref(),
        files_changed: result.stats.files_changed,
    };
    let output = JsonOutput {
        findings: &result.findings,
        summary: &summary,
        stats: &stats,
    };
    write_json_pretty(w, &output)
}
