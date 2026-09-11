use std::path::PathBuf;

use serde::Serialize;

use crate::rule::{Category, RuleId, Severity};

/// A single finding from scanning a source file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub matched_text: String,
}

/// Aggregate statistics from a scan run.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub errors: usize,
    pub warnings: usize,
    pub total: usize,
    pub files_scanned: usize,
}

/// The result of scanning one or more paths.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
}
