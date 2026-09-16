//! Baseline support: capture the findings of an existing codebase once, then
//! suppress them on later scans so only newly introduced findings are
//! reported.
//!
//! Each baselined finding is identified by a hash of its rule id, its path
//! relative to the baseline file, its matched text, and a couple of trimmed
//! context lines. Line and column numbers are deliberately excluded so that
//! inserting code above a finding does not invalidate the baseline.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use thiserror::Error;

use crate::cache::sha256_hex;
use crate::finding::Finding;

/// Name of the baseline file looked up in the working directory and its
/// parents.
pub const BASELINE_FILE: &str = ".slopguard-baseline.json";

/// Format version, so a file written by a newer slopguard is rejected cleanly.
const BASELINE_VERSION: u32 = 1;

/// Number of context lines taken before and after the finding's line to
/// stabilize the hash without tying it to the line number.
const CONTEXT_LINES: usize = 2;

/// One baselined finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Stable hash: rule id + relative path + matched text + context lines.
    pub hash: String,
    /// Human-readable metadata, present only to keep the git diff reviewable.
    /// It takes no part in filtering.
    pub rule_id: String,
    pub file: String,
}

/// The on-disk baseline file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub findings: Vec<BaselineEntry>,
}

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("failed to read baseline '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse baseline '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported baseline version {found} in '{path}' (expected {expected})")]
    Version {
        path: String,
        found: u32,
        expected: u32,
    },
}

/// Normalize a finding's path so that `scan .`, `scan ./src` and
/// `scan /abs/path` all hash to the same string.
///
/// Both sides are canonicalized when possible; otherwise the raw paths are
/// used. The result always uses `/` separators so a baseline stays valid
/// across platforms.
pub fn relative_path(file: &Path, root: &Path) -> String {
    let relative = match (file.canonicalize(), root.canonicalize()) {
        (Ok(abs_file), Ok(abs_root)) => abs_file
            .strip_prefix(&abs_root)
            .map(Path::to_path_buf)
            .unwrap_or(abs_file),
        _ => file.strip_prefix(root).unwrap_or(file).to_path_buf(),
    };
    relative.to_string_lossy().replace('\\', "/")
}

/// The trimmed source lines surrounding `finding`, joined by newlines.
///
/// Returns an empty string when the line is out of bounds, so an unreadable or
/// shortened file never panics and still produces a hash.
fn context_snippet(lines: &[&str], finding: &Finding) -> String {
    if finding.line == 0 || finding.line > lines.len() {
        return String::new();
    }
    let index = finding.line - 1;
    let start = index.saturating_sub(CONTEXT_LINES);
    let end = (index + CONTEXT_LINES + 1).min(lines.len());
    lines[start..end]
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Stable identity hash of a finding.
///
/// `source` is the full content of the finding's file, used for context lines;
/// pass `None` when it cannot be read. Line and column numbers never take part
/// in the hash.
pub fn finding_hash(finding: &Finding, root: &Path, source: Option<&str>) -> String {
    let context = match source {
        Some(content) => {
            let lines: Vec<&str> = content.lines().collect();
            context_snippet(&lines, finding)
        }
        None => String::new(),
    };
    let input = format!(
        "{}\0{}\0{}\0{}",
        finding.rule_id,
        relative_path(&finding.file, root),
        finding.matched_text,
        context
    );
    sha256_hex(input.as_bytes())
}

/// Hash every finding, reading each source file at most once.
///
/// The returned hashes are in the same order as `findings`.
pub fn hash_findings(findings: &[Finding], root: &Path) -> Vec<String> {
    let mut contents: HashMap<PathBuf, Option<String>> = HashMap::new();
    findings
        .iter()
        .map(|finding| {
            let source = contents
                .entry(finding.file.clone())
                .or_insert_with(|| fs::read_to_string(&finding.file).ok());
            finding_hash(finding, root, source.as_deref())
        })
        .collect()
}

/// Build a baseline from a scan result.
///
/// Identical findings are not deduplicated: N occurrences produce N entries so
/// that filtering can use counting semantics. Entries are sorted by
/// `(file, rule_id, hash)` to keep the file stable between runs.
pub fn build(findings: &[Finding], root: &Path) -> Baseline {
    let mut entries: Vec<BaselineEntry> = hash_findings(findings, root)
        .into_iter()
        .zip(findings)
        .map(|(hash, finding)| BaselineEntry {
            hash,
            rule_id: finding.rule_id.to_string(),
            file: relative_path(&finding.file, root),
        })
        .collect();
    entries.sort_by(|a, b| (&a.file, &a.rule_id, &a.hash).cmp(&(&b.file, &b.rule_id, &b.hash)));
    Baseline {
        version: BASELINE_VERSION,
        findings: entries,
    }
}

/// Write a baseline as pretty-printed JSON with a trailing newline.
///
/// # Errors
///
/// Returns [`BaselineError::Io`] if the file cannot be serialized or written.
pub fn write(baseline: &Baseline, path: &Path) -> Result<(), BaselineError> {
    let json = to_string_pretty(baseline).map_err(|e| BaselineError::Io {
        path: path.display().to_string(),
        source: io::Error::other(e),
    })?;
    fs::write(path, format!("{json}\n")).map_err(|e| BaselineError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

/// Read and validate a baseline file.
///
/// # Errors
///
/// Returns [`BaselineError::Io`] if the file cannot be read,
/// [`BaselineError::Parse`] if it is not valid JSON, and
/// [`BaselineError::Version`] if it was written by an incompatible version.
pub fn load(path: &Path) -> Result<Baseline, BaselineError> {
    let content = fs::read_to_string(path).map_err(|e| BaselineError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let baseline: Baseline = from_str(&content).map_err(|e| BaselineError::Parse {
        path: path.display().to_string(),
        source: e,
    })?;
    if baseline.version != BASELINE_VERSION {
        return Err(BaselineError::Version {
            path: path.display().to_string(),
            found: baseline.version,
            expected: BASELINE_VERSION,
        });
    }
    Ok(baseline)
}

/// Walk up from `start` and return the first existing baseline file.
pub fn find_baseline_file(start: &Path) -> Option<PathBuf> {
    start.ancestors().find_map(|dir| {
        let candidate = dir.join(BASELINE_FILE);
        candidate.is_file().then_some(candidate)
    })
}

/// Best guess at the project root: the closest ancestor holding a
/// `slopguard.toml`, else the closest holding a `.git`, else `start` itself.
pub fn project_root(start: &Path) -> PathBuf {
    start
        .ancestors()
        .find(|dir| dir.join("slopguard.toml").is_file())
        .or_else(|| start.ancestors().find(|dir| dir.join(".git").exists()))
        .map(Path::to_path_buf)
        .unwrap_or_else(|| start.to_path_buf())
}

/// Drop the findings already recorded in `baseline` and return the remaining
/// ones along with how many were filtered.
///
/// Matching uses counting rather than set semantics: if the baseline holds 3
/// identical occurrences and the scan finds 4, the fourth is reported. Baseline
/// entries matching nothing (the code was fixed) are silently ignored.
pub fn filter(findings: Vec<Finding>, baseline: &Baseline, root: &Path) -> (Vec<Finding>, usize) {
    let mut remaining: HashMap<&str, usize> = HashMap::new();
    for entry in &baseline.findings {
        *remaining.entry(entry.hash.as_str()).or_insert(0) += 1;
    }

    let hashes = hash_findings(&findings, root);
    let mut kept = Vec::new();
    let mut filtered = 0;
    for (finding, hash) in findings.into_iter().zip(hashes) {
        match remaining.get_mut(hash.as_str()) {
            Some(count) if *count > 0 => {
                *count -= 1;
                filtered += 1;
            }
            _ => kept.push(finding),
        }
    }
    (kept, filtered)
}
