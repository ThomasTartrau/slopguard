use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rule::{Category, RuleId, Severity};

/// A single finding from scanning a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// LLM confidence in `[0.0, 1.0]` for findings confirmed by an AI rule.
    /// `None` for pure AST findings. Serialized in JSON/SARIF only; the text
    /// output ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Aggregate statistics from a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub errors: usize,
    pub warnings: usize,
    pub total: usize,
    pub files_scanned: usize,
    /// Number of findings dropped because they were present in the baseline.
    #[serde(default)]
    pub baseline_filtered: usize,
    /// The ref `--diff` scanned against ("HEAD" when `--base` was omitted).
    /// `None` for a normal full scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_base: Option<String>,
    /// Number of changed files handed to the scanner in diff mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_changed: Option<usize>,
}

/// Cache statistics for a scan run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub cached: usize,
    pub changed: usize,
}

/// The result of scanning one or more paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    #[serde(default)]
    pub cache_stats: Option<CacheStats>,
}
