use std::collections::BTreeMap;
use std::fmt;
use std::fs::read_to_string;
use std::io::{self, Write};
use std::path::Path;

use slopguard_core::finding::{CacheStats, Finding, ScanResult};
use slopguard_core::rule::{Category, Rule, Severity};

const RED: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[36m";
const CYAN_BOLD: &str = "\x1b[1;36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

struct Colors {
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    cyan_bold: &'static str,
    bold: &'static str,
    reset: &'static str,
}

impl Colors {
    fn new(enabled: bool) -> Self {
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
    let sev_label = match finding.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };

    writeln!(
        w,
        "{sev_color}{sev_label}{reset}[{id}]: {msg}",
        reset = c.reset,
        id = finding.rule_id,
        msg = finding.message
    )?;

    let gw = gutter_width(finding.line);
    let padding = " ".repeat(gw);

    writeln!(
        w,
        "{padding} {cy}-->{r} {}:{}:{}",
        finding.file.display(),
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
            "{cb}{ln}{r} {cy}|{r} {line_content}",
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
        writeln!(w, "{padding} {cy}={r} {note}", cy = c.cyan, r = c.reset)?;
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

    writeln!(w, "id:        {}", rule.id)?;
    writeln!(w, "language:  {}", rule.language)?;
    writeln!(w, "severity:  {}", rule.severity)?;
    writeln!(w, "category:  {category}")?;
    writeln!(w, "message:   {}", rule.message)?;
    if let Some(note) = &rule.note {
        writeln!(w, "note:      {note}")?;
    }
    if let Some(fix) = &rule.fix {
        writeln!(w, "fix:       {fix}")?;
    }
    writeln!(
        w,
        "type:      {}",
        if rule.ai_check.is_some() { "ai" } else { "ast" }
    )?;
    if let Some(ai_check) = &rule.ai_check {
        if let Some(model) = &ai_check.model {
            writeln!(w, "model:     {model}")?;
        }
        writeln!(w)?;
        writeln!(w, "prompt:")?;
        for line in ai_check.prompt.lines() {
            writeln!(w, "  {line}")?;
        }
    }

    if let Some(tests) = &rule.tests {
        if !tests.should_match.is_empty() {
            writeln!(w)?;
            writeln!(w, "should_match:")?;
            for snippet in &tests.should_match {
                for line in snippet.lines() {
                    writeln!(w, "  {line}")?;
                }
            }
        }
        if !tests.should_not_match.is_empty() {
            writeln!(w)?;
            writeln!(w, "should_not_match:")?;
            for snippet in &tests.should_not_match {
                for line in snippet.lines() {
                    writeln!(w, "  {line}")?;
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
        writeln!(w, "Scanning {changed} changed files (base: {base})")?;
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

    let errors_label = if result.stats.errors == 1 {
        "error"
    } else {
        "errors"
    };
    let warnings_label = if result.stats.warnings == 1 {
        "warning"
    } else {
        "warnings"
    };
    let files_label = if result.stats.files_scanned == 1 {
        "file"
    } else {
        "files"
    };

    if let Some(ref cs) = result.cache_stats {
        write_cache_line(w, result.stats.files_scanned, cs)?;
    }

    if result.stats.baseline_filtered > 0 {
        let label = if result.stats.baseline_filtered == 1 {
            "finding"
        } else {
            "findings"
        };
        writeln!(
            w,
            "{n} {label} filtered by baseline",
            n = result.stats.baseline_filtered
        )?;
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
