use std::collections::BTreeMap;
use std::fmt;
use std::fs::read_to_string;
use std::io::{self, Write};
use std::path::Path;

use slopguard_core::finding::{CacheStats, Finding, ScanResult};
use slopguard_core::rule::{Category, Rule, Severity};
use slopguard_core::sanitize::sanitize_control;

use crate::output::json::rule_kind;
use crate::output::plural;

const RED: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[36m";
const CYAN_BOLD: &str = "\x1b[1;36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub(crate) struct Colors {
    pub(crate) red: &'static str,
    pub(crate) yellow: &'static str,
    pub(crate) cyan: &'static str,
    pub(crate) cyan_bold: &'static str,
    pub(crate) bold: &'static str,
    pub(crate) reset: &'static str,
}

impl Colors {
    pub(crate) fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                red: RED,
                yellow: YELLOW,
                cyan: CYAN,
                cyan_bold: CYAN_BOLD,
                bold: BOLD,
                reset: RESET,
            }
        } else {
            Self {
                red: "",
                yellow: "",
                cyan: "",
                cyan_bold: "",
                bold: "",
                reset: "",
            }
        }
    }

    fn severity(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => self.red,
            Severity::Warning => self.yellow,
        }
    }
}

fn gutter_width(line: usize) -> usize {
    fmt::format(format_args!("{line}")).len()
}

fn write_finding(
    w: &mut impl Write,
    finding: &Finding,
    source_lines: &[&str],
    c: &Colors,
) -> io::Result<()> {
    let sev_color = c.severity(&finding.severity);
    let sev_label = &finding.severity;
    let escalated = if finding.escalated { "[escalated]" } else { "" };

    writeln!(
        w,
        "{sev_color}{sev_label}{escalated}{reset}[{id}]: {msg}",
        reset = c.reset,
        id = sanitize_control(finding.rule_id.as_str()),
        msg = sanitize_control(&finding.message)
    )?;

    let gw = gutter_width(finding.line);
    let padding = " ".repeat(gw);

    writeln!(
        w,
        "{padding} {cy}-->{r} {}:{}:{}",
        sanitize_control(&finding.file.display().to_string()),
        finding.line,
        finding.column,
        cy = c.cyan,
        r = c.reset
    )?;
    writeln!(w, "{padding} {cy}|{r}", cy = c.cyan, r = c.reset)?;

    if finding.line > 0 && finding.line <= source_lines.len() {
        let line_content = source_lines[finding.line - 1];
        writeln!(
            w,
            "{cb}{ln}{r} {cy}|{r} {printed}",
            printed = sanitize_control(line_content),
            cb = c.cyan_bold,
            ln = finding.line,
            cy = c.cyan,
            r = c.reset
        )?;

        let col_start = finding.column.saturating_sub(1);
        let col_end = if finding.end_line == finding.line {
            finding.end_column.saturating_sub(1)
        } else {
            line_content.len()
        };
        let underline_len = col_end.saturating_sub(col_start).max(1);
        let spaces = " ".repeat(col_start);
        let carets = "^".repeat(underline_len);
        writeln!(
            w,
            "{padding} {cy}|{r} {spaces}{sc}{carets}{r}",
            cy = c.cyan,
            r = c.reset,
            sc = sev_color
        )?;
    }

    writeln!(w, "{padding} {cy}|{r}", cy = c.cyan, r = c.reset)?;

    if let Some(note) = &finding.note {
        writeln!(
            w,
            "{padding} {cy}={r} {note}",
            note = sanitize_control(note),
            cy = c.cyan,
            r = c.reset
        )?;
    }

    writeln!(w)?;
    Ok(())
}

pub fn format_explain(rule: &Rule, w: &mut impl Write) -> io::Result<()> {
    let category = rule
        .category
        .as_ref()
        .unwrap_or(&Category::Correctness)
        .to_string();

    writeln!(w, "id:        {}", sanitize_control(rule.id.as_str()))?;
    writeln!(w, "language:  {}", rule.language)?;
    writeln!(w, "severity:  {}", rule.severity)?;
    writeln!(w, "category:  {category}")?;
    writeln!(w, "message:   {}", sanitize_control(&rule.message))?;
    if let Some(note) = &rule.note {
        writeln!(w, "note:      {}", sanitize_control(note))?;
    }
    if let Some(fix) = &rule.fix {
        writeln!(w, "fix:       {}", sanitize_control(fix))?;
    }
    writeln!(w, "type:      {}", rule_kind(rule))?;
    if let Some(metric) = &rule.metric {
        writeln!(w, "metric:    {metric}")?;
    }
    if let Some(threshold) = rule.threshold {
        writeln!(w, "threshold: {threshold}")?;
    }
    if let Some(ai_check) = &rule.ai_check {
        writeln!(w, "reason:    {}", ai_check.reason)?;
        if let Some(threshold) = ai_check.threshold {
            writeln!(w, "threshold: {threshold}")?;
        }
        if let Some(model) = &ai_check.model {
            writeln!(w, "model:     {}", sanitize_control(model))?;
        }
        writeln!(w)?;
        writeln!(w, "prompt:")?;
        for line in ai_check.prompt.lines() {
            writeln!(w, "  {}", sanitize_control(line))?;
        }
    }

    if let Some(tests) = &rule.tests {
        if !tests.should_match.is_empty() {
            writeln!(w)?;
            writeln!(w, "should_match:")?;
            for snippet in &tests.should_match {
                for line in snippet.lines() {
                    writeln!(w, "  {}", sanitize_control(line))?;
                }
            }
        }
        if !tests.should_not_match.is_empty() {
            writeln!(w)?;
            writeln!(w, "should_not_match:")?;
            for snippet in &tests.should_not_match {
                for line in snippet.lines() {
                    writeln!(w, "  {}", sanitize_control(line))?;
                }
            }
        }
    }

    Ok(())
}

fn write_cache_line(w: &mut impl Write, files_scanned: usize, cs: &CacheStats) -> io::Result<()> {
    writeln!(
        w,
        "Scanned {files_scanned} files ({cached} cached, {changed} changed)",
        cached = cs.cached,
        changed = cs.changed,
    )
}

pub fn format_text(result: &ScanResult, w: &mut impl Write, use_colors: bool) -> io::Result<()> {
    let c = Colors::new(use_colors);

    if let (Some(base), Some(changed)) = (&result.stats.diff_base, result.stats.files_changed) {
        writeln!(
            w,
            "Scanning {changed} changed files (base: {})",
            sanitize_control(base)
        )?;
        writeln!(w)?;
    }

    let mut files_cache: BTreeMap<&Path, Vec<String>> = BTreeMap::new();

    for finding in &result.findings {
        let source = files_cache.entry(&finding.file).or_insert_with(|| {
            read_to_string(&finding.file)
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect()
        });
        let source_lines: Vec<&str> = source.iter().map(String::as_str).collect();
        write_finding(w, finding, &source_lines, &c)?;
    }

    let errors_label = plural(result.stats.errors, "error", "errors");
    let warnings_label = plural(result.stats.warnings, "warning", "warnings");
    let files_label = plural(result.stats.files_scanned, "file", "files");

    if let Some(ref cs) = result.cache_stats {
        write_cache_line(w, result.stats.files_scanned, cs)?;
    }

    if result.stats.baseline_filtered > 0 {
        let label = plural(result.stats.baseline_filtered, "finding", "findings");
        writeln!(
            w,
            "{n} {label} filtered by baseline",
            n = result.stats.baseline_filtered
        )?;
    }

    let escalated = result.findings.iter().filter(|f| f.escalated).count();
    if escalated > 0 {
        let label = plural(escalated, "finding", "findings");
        writeln!(w, "{escalated} {label} escalated to error")?;
    }

    if result.stats.total > 0 {
        writeln!(
            w,
            "{b}summary{r}: {red}{errors}{r} {errors_label}, {yel}{warnings}{r} {warnings_label} in {files} {files_label}",
            b = c.bold, r = c.reset,
            red = c.red, yel = c.yellow,
            errors = result.stats.errors,
            warnings = result.stats.warnings,
            files = result.stats.files_scanned,
        )?;
    } else {
        writeln!(
            w,
            "0 errors, 0 warnings in {} {files_label}",
            result.stats.files_scanned,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::write;
    use std::path::{Path, PathBuf};

    use serde_json::{from_value, json};
    use slopguard_core::finding::{Finding, ScanResult, ScanStats};
    use slopguard_core::rule::{Category, Rule, Severity};
    use tempfile::tempdir;

    use super::{format_explain, format_text};

    const HOSTILE: &str = "\x1b[2J\x1b]0;x\x07";

    fn finding(file: &Path) -> Finding {
        Finding {
            rule_id: "demo-rule".into(),
            severity: Severity::Warning,
            category: Category::Slop,
            message: format!("message {HOSTILE}"),
            note: Some(format!("model reason {HOSTILE}")),
            fix: None,
            file: file.to_path_buf(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
            escalated: false,
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            stats: ScanStats {
                errors: 0,
                warnings: findings.len(),
                total: findings.len(),
                files_scanned: 1,
                baseline_filtered: 0,
                diff_base: None,
                files_changed: None,
            },
            findings,
            cache_stats: None,
        }
    }

    fn render(result: &ScanResult) -> String {
        let mut out = Vec::new();
        format_text(result, &mut out, false).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn assert_neutralized(out: &str) {
        assert!(!out.contains('\x1b'), "raw ESC in output: {out:?}");
        assert!(!out.contains('\x07'), "raw BEL in output: {out:?}");
        assert!(out.contains("\\x1b"), "escaped ESC missing: {out:?}");
    }

    #[test]
    fn text_output_neutralizes_message_note_and_path() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("dir\x1b[2J.rs");
        let out = render(&result(vec![finding(&file)]));

        assert_neutralized(&out);
        assert!(out.contains("model reason"));
    }

    #[test]
    fn text_output_neutralizes_matched_line() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.rs");
        write(&file, "let s = \"\x1b[31m\";\n").unwrap();
        let mut f = finding(&file);
        f.message = "plain".to_string();
        f.note = None;
        let out = render(&result(vec![f]));

        assert_neutralized(&out);
        assert!(out.contains("let s = \"\\x1b[31m\";"));
    }

    #[test]
    fn text_output_neutralizes_diff_base() {
        let mut r = result(Vec::new());
        r.stats.diff_base = Some(format!("main{HOSTILE}"));
        r.stats.files_changed = Some(0);

        assert_neutralized(&render(&r));
    }

    #[test]
    fn explain_output_neutralizes_rule_text() {
        let rule: Rule = from_value(json!({
            "id": "demo-rule",
            "language": "rust",
            "severity": "error",
            "message": format!("message {HOSTILE}"),
            "note": format!("note {HOSTILE}"),
            "fix": format!("fix {HOSTILE}"),
            "tests": {
                "should_match": [format!("let a = {HOSTILE};")],
                "should_not_match": [format!("let b = {HOSTILE};")],
            },
        }))
        .unwrap();
        let mut out = Vec::new();
        format_explain(&rule, &mut out).unwrap();

        assert_neutralized(&String::from_utf8(out).unwrap());
    }

    #[test]
    fn colors_stay_intact_when_enabled() {
        let file = PathBuf::from("missing.rs");
        let mut out = Vec::new();
        format_text(&result(vec![finding(&file)]), &mut out, true).unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("\x1b[1;33m"), "own color codes must remain");
        assert!(!out.contains("\x1b[2J"), "hostile sequence must be escaped");
    }
}
