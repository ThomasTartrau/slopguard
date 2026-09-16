use std::io::{self, Write};

use serde::Serialize;

use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::rule::{Category, Language, Rule, Severity};

use crate::output::write_json_pretty;

#[derive(Serialize)]
struct JsonOutput<'a> {
    findings: &'a [Finding],
    /// Kept for backward compatibility with consumers written before `stats`.
    summary: &'a ScanSummary,
    stats: &'a JsonStats,
}

#[derive(Serialize)]
struct JsonStats {
    errors: usize,
    warnings: usize,
    total: usize,
    files_scanned: usize,
    /// Always emitted, `0` when no baseline applies, so CI can rely on it.
    baseline_filtered: usize,
}

#[derive(Serialize)]
struct ScanSummary {
    errors: usize,
    warnings: usize,
    total: usize,
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
    /// "ai" for rules with an `ai_check`, "ast" otherwise.
    kind: &'a str,
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
        kind: if rule.ai_check.is_some() { "ai" } else { "ast" },
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
    };
    let output = JsonOutput {
        findings: &result.findings,
        summary: &summary,
        stats: &stats,
    };
    write_json_pretty(w, &output)
}
