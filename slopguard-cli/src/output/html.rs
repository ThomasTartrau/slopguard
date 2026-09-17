//! Standalone single-file HTML report: template expansion with server-rendered
//! rows and inline client-side filters.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use slopguard_core::finding::{Finding, ScanResult};
use slopguard_core::rule::{Language, Severity};

use crate::stats_cmd::StatsReport;

const TEMPLATE: &str = include_str!("../../templates/report.html");
/// Longest snippet kept verbatim in the report; longer matches are truncated
/// so a single huge match cannot blow up the file size.
const MAX_SNIPPET_CHARS: usize = 2000;

/// Metadata the report header shows that is not derivable from `ScanResult`.
pub struct HtmlMeta {
    /// Last segment of the first scanned path, used as the report title.
    pub project_name: String,
    /// Seconds since the Unix epoch, rendered as a UTC timestamp.
    pub generated_at_secs: u64,
    /// Whether a baseline was applied to this run.
    pub baseline_active: bool,
}

/// Render a standalone HTML report for `result` into `w`.
///
/// The document embeds its own styles and filter script: it opens from disk
/// with no network access and no companion files.
pub fn format_html(
    result: &ScanResult,
    report: &StatsReport,
    meta: &HtmlMeta,
    w: &mut impl Write,
) -> io::Result<()> {
    let severity_axis = [
        ("error", report.by_severity.error),
        ("warning", report.by_severity.warning),
    ];
    let category_axis = [
        ("slop", report.by_category.slop),
        ("security", report.by_category.security),
        ("correctness", report.by_category.correctness),
    ];
    let mut language_axis = vec![
        ("rust", report.by_language.rust),
        ("typescript", report.by_language.typescript),
    ];
    if report.by_language.other > 0 {
        language_axis.push(("other", report.by_language.other));
    }

    let badges = badges(result, meta);
    let sorted = sort_findings(&result.findings);

    let html = TEMPLATE
        .replace("{{PROJECT_NAME}}", &escape_html(&meta.project_name))
        .replace("{{GENERATED_AT}}", &utc_timestamp(meta.generated_at_secs))
        .replace("{{MODE_BADGES}}", &badges)
        .replace("{{TOTAL}}", &result.stats.total.to_string())
        .replace("{{ERRORS}}", &result.stats.errors.to_string())
        .replace("{{WARNINGS}}", &result.stats.warnings.to_string())
        .replace("{{FILES_SCANNED}}", &result.stats.files_scanned.to_string())
        .replace("{{BARS_SEVERITY}}", &bars(&severity_axis, severity_class))
        .replace("{{BARS_CATEGORY}}", &bars(&category_axis, |_| ""))
        .replace("{{BARS_LANGUAGE}}", &bars(&language_axis, |_| ""))
        .replace("{{OPTIONS_SEVERITY}}", &options(&severity_axis))
        .replace("{{OPTIONS_CATEGORY}}", &options(&category_axis))
        .replace("{{OPTIONS_LANGUAGE}}", &options(&language_axis))
        .replace("{{ROWS}}", &rows(&sorted));

    w.write_all(html.as_bytes())
}

/// The header badges describing how the run was scoped.
fn badges(result: &ScanResult, meta: &HtmlMeta) -> String {
    let mut out = String::new();
    if let (Some(base), Some(changed)) = (&result.stats.diff_base, result.stats.files_changed) {
        out.push_str(&format!(
            "<span class=\"badge\">diff vs {} ({changed} files changed)</span>",
            escape_html(base)
        ));
    }
    if meta.baseline_active {
        out.push_str(&format!(
            "<span class=\"badge\">baseline applied ({} findings filtered)</span>",
            result.stats.baseline_filtered
        ));
    }
    out
}

/// Escape the five characters that are unsafe in HTML text and in quoted
/// attribute values.
///
/// Single pass on purpose: chaining `replace` would re-escape the ampersands
/// the earlier replacements just introduced.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Derive the report title from the first scanned path: its last path segment,
/// resolving "." and "" against the current directory.
pub fn project_name(paths: &[PathBuf]) -> String {
    let Some(first) = paths.first() else {
        return "project".to_string();
    };
    let resolved = first.canonicalize().unwrap_or_else(|_| first.clone());
    resolved
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "project".to_string())
}

/// Format Unix `secs` as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// The workspace carries no date crate, so this is the civil-from-days
/// conversion done inline. UTC only, no timezone handling.
fn utc_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let shifted = if z >= 0 { z } else { z - 146_096 };
    let era = shifted / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };

    format!("{year:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// The bar modifier class for a severity label.
fn severity_class(label: &str) -> &'static str {
    match label {
        "error" => "error",
        "warning" => "warning",
        _ => "",
    }
}

/// One horizontal bar per row: label, count, and a width percentage relative
/// to the largest count in the group.
///
/// Zero-count rows still render, at width 0, so the report keeps the same
/// shape from run to run.
fn bars(rows: &[(&str, usize)], class_of: impl Fn(&str) -> &'static str) -> String {
    let max = rows.iter().map(|(_, count)| *count).max().unwrap_or(0);
    let mut out = String::with_capacity(rows.len() * 200);
    for &(label, count) in rows {
        let pct = count * 100 / max.max(1);
        let class = class_of(label);
        let escaped = escape_html(label);
        out.push_str(&format!(
            "<div class=\"bar-row\">\
             <span class=\"bar-label\">{escaped}</span>\
             <span class=\"bar-track\">\
             <span class=\"bar {class}\" style=\"width:{pct}%\"></span>\
             </span>\
             <span class=\"bar-count\">{count}</span>\
             </div>"
        ));
    }
    out
}

/// `<option>` list for a filter dropdown, only for axes with a nonzero count.
fn options(rows: &[(&str, usize)]) -> String {
    let mut out = String::new();
    for &(label, count) in rows.iter().filter(|(_, count)| *count > 0) {
        let escaped = escape_html(label);
        let option = format!("<option value=\"{escaped}\">{escaped} ({count})</option>");
        out.push_str(&option);
    }
    out
}

/// Errors sort before warnings so the report leads with what blocks CI.
fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
    }
}

/// Sort key placing errors before warnings, then by file path and position.
fn sort_key(f: &Finding) -> (u8, &Path, usize, usize) {
    (
        severity_rank(&f.severity),
        f.file.as_path(),
        f.line,
        f.column,
    )
}

/// Order the findings for display: errors first, then by file and position.
///
/// `ScanResult.findings` already arrives sorted by `(file, line, column)`, so
/// this is a stable re-sort by severity.
fn sort_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    sorted
}

/// Language slug for the row's `data-language` attribute.
fn language_slug(path: &Path) -> &'static str {
    match crate::language_for_path(path) {
        Some(Language::Rust) => "rust",
        Some(Language::TypeScript) => "typescript",
        None => "other",
    }
}

/// Keep a single huge match from dominating the report.
fn truncate_snippet(text: &str) -> String {
    if text.chars().count() > MAX_SNIPPET_CHARS {
        let mut kept: String = text.chars().take(MAX_SNIPPET_CHARS).collect();
        kept.push_str("\n...");
        kept
    } else {
        text.to_string()
    }
}

/// Render every finding as a data row plus its detail row.
fn rows(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return "<tr class=\"empty\"><td colspan=\"4\">No findings.</td></tr>".to_string();
    }

    let mut out = String::with_capacity(findings.len() * 512);
    for f in findings {
        let severity = f.severity.to_string();
        let category = f.category.to_string();
        let language = language_slug(&f.file);
        let file = escape_html(&f.file.display().to_string());
        let escalated_badge = if f.escalated {
            "<span class=\"esc\">escalated</span>"
        } else {
            ""
        };

        out.push_str(&format!(
            "<tr data-severity=\"{severity}\" data-category=\"{category}\" \
             data-language=\"{language}\" data-file=\"{file}\" \
             data-escalated=\"{escalated}\">\
             <td><span class=\"sev {severity}\">{severity}</span>{escalated_badge}</td>\
             <td><code>{rule}</code></td>\
             <td class=\"loc\">{file}:{line}:{column}</td>\
             <td>{message}</td></tr>",
            rule = escape_html(f.rule_id.as_str()),
            line = f.line,
            column = f.column,
            message = escape_html(&f.message),
            escalated = f.escalated
        ));

        out.push_str(&format!(
            "<tr class=\"detail\"><td colspan=\"4\"><pre><code>{snippet}</code></pre>",
            snippet = escape_html(&truncate_snippet(&f.matched_text))
        ));
        if let Some(note) = &f.note {
            out.push_str(&format!("<p class=\"note\">{}</p>", escape_html(note)));
        }
        if let Some(fix) = &f.fix {
            out.push_str(&format!("<p class=\"fix\">{}</p>", escape_html(fix)));
        }
        out.push_str("</td></tr>");
    }
    out
}

#[cfg(test)]
mod tests {
    use slopguard_core::finding::ScanStats;
    use slopguard_core::rule::Category;

    use crate::stats_cmd::compute_report;

    use super::*;

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
            escalated: false,
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

    fn meta() -> HtmlMeta {
        HtmlMeta {
            project_name: "demo".to_string(),
            generated_at_secs: 0,
            baseline_active: false,
        }
    }

    fn render(result: &ScanResult, meta: &HtmlMeta) -> String {
        let report = compute_report(result);
        let mut buf = Vec::new();
        format_html(result, &report, meta, &mut buf).expect("rendering should succeed");
        String::from_utf8(buf).expect("the report should be valid UTF-8")
    }

    #[test]
    fn escapes_angle_brackets_and_ampersands() {
        let out = escape_html("<a href=\"x\">&'");
        assert_eq!(out, "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert!(
            !out.contains("&amp;amp;"),
            "the ampersand should be escaped exactly once, got: {out}"
        );
    }

    #[test]
    fn utc_timestamp_epoch() {
        assert_eq!(utc_timestamp(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn utc_timestamp_known_date() {
        assert_eq!(utc_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn utc_timestamp_leap_day() {
        assert_eq!(utc_timestamp(1_709_164_800), "2024-02-29 00:00:00 UTC");
    }

    #[test]
    fn output_starts_with_doctype() {
        let result = result_of(vec![finding(
            "a",
            Severity::Error,
            Category::Correctness,
            "a.rs",
        )]);
        let out = render(&result, &meta());
        assert!(
            out.starts_with("<!DOCTYPE html>"),
            "the doctype should open the report"
        );
    }

    #[test]
    fn output_has_no_external_references() {
        let result = result_of(vec![finding(
            "a",
            Severity::Warning,
            Category::Slop,
            "a.rs",
        )]);
        let out = render(&result, &meta());
        for needle in ["http://", "https://", "src=\"//\"", "<link", "fetch("] {
            assert!(!out.contains(needle), "not self-contained: {needle}");
        }
    }

    #[test]
    fn every_placeholder_is_substituted() {
        let result = result_of(vec![finding(
            "a",
            Severity::Warning,
            Category::Slop,
            "a.rs",
        )]);
        let out = render(&result, &meta());
        assert!(
            !out.contains("{{"),
            "every template placeholder should be substituted"
        );
    }

    #[test]
    fn finding_message_is_escaped() {
        let mut f = finding("a", Severity::Error, Category::Security, "a.rs");
        f.message = "<script>alert(1)</script>".to_string();
        f.matched_text = "<script>alert(1)</script>".to_string();
        let out = render(&result_of(vec![f]), &meta());

        assert!(out.contains("&lt;script&gt;"));
        assert!(
            !out.contains("<script>alert"),
            "injected markup should never reach the document raw"
        );
    }

    #[test]
    fn rows_sorted_errors_first() {
        let result = result_of(vec![
            finding("warn-rule", Severity::Warning, Category::Slop, "a.rs"),
            finding("err-rule", Severity::Error, Category::Slop, "z.rs"),
        ]);
        let out = render(&result, &meta());

        let error_at = out.find("err-rule").expect("the error row should render");
        let warning_at = out
            .find("warn-rule")
            .expect("the warning row should render");
        assert!(error_at < warning_at, "errors should be listed first");
    }

    #[test]
    fn empty_result_renders_empty_state() {
        let out = render(&result_of(Vec::new()), &meta());
        assert!(out.starts_with("<!DOCTYPE html>"));
        assert!(out.contains("No findings."));
    }

    #[test]
    fn diff_badge_present_in_diff_mode() {
        let mut result = result_of(vec![finding("a", Severity::Error, Category::Slop, "a.rs")]);
        result.stats.diff_base = Some("main".to_string());
        result.stats.files_changed = Some(3);

        let out = render(&result, &meta());
        assert!(out.contains("diff vs main"));
        assert!(out.contains("3 files changed"));
    }

    #[test]
    fn baseline_badge_present_when_active() {
        let mut result = result_of(Vec::new());
        result.stats.baseline_filtered = 7;
        let meta = HtmlMeta {
            baseline_active: true,
            ..meta()
        };

        let out = render(&result, &meta);
        assert!(out.contains("baseline applied (7 findings filtered)"));
    }

    #[test]
    fn long_snippet_is_truncated() {
        let mut f = finding("a", Severity::Error, Category::Slop, "a.rs");
        f.matched_text = "x".repeat(5000);
        let out = render(&result_of(vec![f]), &meta());

        assert!(
            !out.contains(&"x".repeat(MAX_SNIPPET_CHARS + 1)),
            "the snippet should be capped at MAX_SNIPPET_CHARS"
        );
        assert!(
            out.contains("\n..."),
            "a truncated snippet should be marked as such"
        );
    }

    #[test]
    fn language_slug_maps_known_extensions() {
        assert_eq!(language_slug(Path::new("a.rs")), "rust");
        assert_eq!(language_slug(Path::new("a.tsx")), "typescript");
        assert_eq!(language_slug(Path::new("a.py")), "other");
    }
}
