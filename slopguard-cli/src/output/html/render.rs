//! HTML fragment builders for the report: escaping, bars, dropdown options,
//! finding rows, and the sort order they render in.

use std::path::Path;

use slopguard_core::finding::Finding;
use slopguard_core::rule::{Language, Severity};

/// Longest snippet kept verbatim in the report; longer matches are truncated
/// so a single huge match cannot blow up the file size.
pub(super) const MAX_SNIPPET_CHARS: usize = 2000;

/// Escape the five characters that are unsafe in HTML text and in quoted
/// attribute values.
///
/// Single pass on purpose: chaining `replace` would re-escape the ampersands
/// the earlier replacements just introduced.
pub(super) fn escape_html(s: &str) -> String {
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

/// Format Unix `secs` as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// The workspace carries no date crate, so this is the civil-from-days
/// conversion done inline. UTC only, no timezone handling.
pub(super) fn utc_timestamp(secs: u64) -> String {
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
pub(super) fn severity_class(label: &str) -> &'static str {
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
pub(super) fn bars(rows: &[(&str, usize)], class_of: impl Fn(&str) -> &'static str) -> String {
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
pub(super) fn options(rows: &[(&str, usize)]) -> String {
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
pub(super) fn sort_findings(findings: &[Finding]) -> Vec<&Finding> {
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
pub(super) fn rows(findings: &[&Finding]) -> String {
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
    use super::*;

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
    fn language_slug_maps_known_extensions() {
        assert_eq!(language_slug(Path::new("a.rs")), "rust");
        assert_eq!(language_slug(Path::new("a.tsx")), "typescript");
        assert_eq!(language_slug(Path::new("a.py")), "other");
    }
}
