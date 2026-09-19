//! Standalone single-file HTML report: template expansion with server-rendered
//! rows and inline client-side filters.

mod render;

use std::io::{self, Write};
use std::path::PathBuf;

use slopguard_core::finding::ScanResult;

use crate::stats_cmd::StatsReport;

use render::{bars, escape_html, options, rows, severity_class, sort_findings, utc_timestamp};

const TEMPLATE: &str = include_str!("../../../templates/report.html");

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

#[cfg(test)]
mod tests {
    use slopguard_core::finding::ScanStats;
    use slopguard_core::rule::{Category, Severity};

    use crate::stats_cmd::compute_report;

    use super::render::MAX_SNIPPET_CHARS;
    use super::*;
    use slopguard_core::finding::Finding;

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
}
