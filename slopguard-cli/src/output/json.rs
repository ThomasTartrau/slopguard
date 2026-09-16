use std::io::{self, Write};

use serde::Serialize;

use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::rule::{Category, Language, Rule, Severity};

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
    /// Diff-mode only: the ref the changed files were computed against.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_base: Option<String>,
    /// Diff-mode only: how many changed files were handed to the scanner.
    #[serde(skip_serializing_if = "Option::is_none")]
    files_changed: Option<usize>,
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
    serde_json::to_writer_pretty(&mut *w, &output).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
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
        diff_base: result.stats.diff_base.clone(),
        files_changed: result.stats.files_changed,
    };
    let output = JsonOutput {
        findings: &result.findings,
        summary: &summary,
        stats: &stats,
    };
    serde_json::to_writer_pretty(&mut *w, &output).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}
