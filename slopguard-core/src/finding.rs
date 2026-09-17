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
    /// True when severity escalation raised this finding from warning to error
    /// because its rule fired repeatedly in the same file. Always serialized so
    /// consumers can filter on `escalated == false` without a null check.
    #[serde(default)]
    pub escalated: bool,
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
    /// The git ref the scan was diffed against in `--diff` mode ("HEAD" when
    /// no `--base` was given). `None` for a normal full scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_base: Option<String>,
    /// Number of changed files selected by `--diff`. `None` for a full scan.
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
