use std::io::{self, Write};

use serde::Serialize;

use slopguard_core::finding::{Finding, ScanResult};

#[derive(Serialize)]
struct JsonOutput<'a> {
    findings: &'a [Finding],
    summary: &'a ScanSummary,
}

#[derive(Serialize)]
struct ScanSummary {
    errors: usize,
    warnings: usize,
    total: usize,
}

pub fn format_json(result: &ScanResult, w: &mut impl Write) -> io::Result<()> {
    let summary = ScanSummary {
        errors: result.stats.errors,
        warnings: result.stats.warnings,
        total: result.stats.total,
    };
    let output = JsonOutput {
        findings: &result.findings,
        summary: &summary,
    };
    serde_json::to_writer_pretty(&mut *w, &output).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}
