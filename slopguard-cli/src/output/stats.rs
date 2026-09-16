//! Rendering for the `stats` subcommand: aligned ASCII tables or JSON.

use std::io::{self, Write};

use crate::output::text::Colors;
use crate::stats_cmd::StatsReport;

const COUNT_HEADER: &str = "count";

/// Serialize the whole report as pretty JSON.
///
/// Every axis is a struct rather than a map, so each key is present even at
/// zero and CI can index into the output unconditionally.
pub fn format_stats_json(report: &StatsReport, w: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *w, report).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}

/// One table row: its label, its count, and the color the line is printed in.
struct Row {
    label: String,
    count: usize,
    color: &'static str,
}

fn row(label: &str, count: usize, color: &'static str) -> Row {
    Row {
        label: label.to_string(),
        count,
        color,
    }
}

fn digits(n: usize) -> usize {
    n.to_string().len()
}

/// Print one `label / count` table, sized to its widest entry.
///
/// An empty `rows` still prints the header and the separator, so the shape of
/// the report does not change when a section has nothing to show.
fn write_section(w: &mut impl Write, header: &str, rows: &[Row], c: &Colors) -> io::Result<()> {
    let header_w = header.len();
    let count_header_w = COUNT_HEADER.len();
    let label_w = rows
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(header_w)
        .max(header_w);
    let count_w = rows
        .iter()
        .map(|r| digits(r.count))
        .max()
        .unwrap_or(count_header_w)
        .max(count_header_w);

    writeln!(
        w,
        "{b}{header:<label_w$}  {count_header:>count_w$}{r}",
        b = c.bold,
        r = c.reset,
        count_header = COUNT_HEADER
    )?;
    writeln!(w, "{}  {}", "-".repeat(label_w), "-".repeat(count_w))?;
    for entry in rows {
        writeln!(
            w,
            "{color}{label:<label_w$}  {count:>count_w$}{r}",
            color = entry.color,
            label = entry.label,
            count = entry.count,
            r = c.reset
        )?;
    }
    writeln!(w)?;
    Ok(())
}

/// Render the report as aligned ASCII tables.
///
/// Every section is printed even when all of its counts are zero, so the
/// output keeps the same shape from run to run and stays easy to grep.
pub fn format_stats_text(
    report: &StatsReport,
    w: &mut impl Write,
    use_colors: bool,
) -> io::Result<()> {
    let c = Colors::new(use_colors);

    let findings_label = if report.total == 1 {
        "finding"
    } else {
        "findings"
    };
    let files_label = if report.files_scanned == 1 {
        "file"
    } else {
        "files"
    };
    writeln!(
        w,
        "{total} {findings_label} in {files} {files_label}",
        total = report.total,
        files = report.files_scanned
    )?;

    if report.baseline_filtered > 0 {
        let label = if report.baseline_filtered == 1 {
            "finding"
        } else {
            "findings"
        };
        writeln!(
            w,
            "{n} {label} filtered by baseline",
            n = report.baseline_filtered
        )?;
    }
    writeln!(w)?;

    let severity_rows = [
        row("error", report.by_severity.error, c.red),
        row("warning", report.by_severity.warning, c.yellow),
    ];
    write_section(w, "severity", &severity_rows, &c)?;

    let category_rows = [
        row("slop", report.by_category.slop, ""),
        row("security", report.by_category.security, ""),
        row("correctness", report.by_category.correctness, ""),
    ];
    write_section(w, "category", &category_rows, &c)?;

    let mut language_rows = vec![
        row("rust", report.by_language.rust, ""),
        row("typescript", report.by_language.typescript, ""),
    ];
    if report.by_language.other > 0 {
        language_rows.push(row("other", report.by_language.other, ""));
    }
    write_section(w, "language", &language_rows, &c)?;

    let mut rule_rows = Vec::with_capacity(report.top_rules.len());
    for entry in &report.top_rules {
        rule_rows.push(row(&entry.rule_id, entry.count, ""));
    }
    write_section(w, "rule", &rule_rows, &c)?;

    let mut file_rows = Vec::with_capacity(report.top_files.len());
    for entry in &report.top_files {
        file_rows.push(row(&entry.file, entry.count, ""));
    }
    write_section(w, "file", &file_rows, &c)?;

    Ok(())
}
