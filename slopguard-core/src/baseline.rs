use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cache::sha256_hex;
use crate::finding::Finding;
use crate::rule::RuleId;

const BASELINE_FILE: &str = ".slopguard-baseline.json";
const CONTEXT_LINES: usize = 2;

/// A snapshot of findings to ignore on future scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub findings: Vec<BaselineEntry>,
}

/// A single baseline entry: the rule and file it came from (for readable
/// diffs) plus the content hash used to match it against future findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: RuleId,
    pub file: PathBuf,
    pub hash: String,
}

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("baseline I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("baseline JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Path of `file` relative to `project_root`, falling back to `file` as-is
/// when either path cannot be canonicalized (e.g. it no longer exists).
fn relative_file(file: &Path, project_root: &Path) -> PathBuf {
    let canonical_root = project_root.canonicalize();
    let canonical_file = file.canonicalize();
    match (canonical_root, canonical_file) {
        (Ok(root), Ok(f)) => f
            .strip_prefix(&root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| file.to_path_buf()),
        _ => file.to_path_buf(),
    }
}

/// The (up to) 2 lines before and after `line` (1-indexed), trailing
/// whitespace stripped. Empty when the file cannot be read, so the hash
/// still stays stable on `rule_id`/file/`matched_text` alone.
fn surrounding_context(file: &Path, line: usize) -> String {
    let Ok(content) = fs::read_to_string(file) else {
        return String::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    if line == 0 || line > lines.len() {
        return String::new();
    }
    let idx = line - 1;
    let start = idx.saturating_sub(CONTEXT_LINES);
    let end = (idx + CONTEXT_LINES + 1).min(lines.len());
    lines[start..end]
        .iter()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A stable hash for `finding`, deliberately excluding the line number so
/// that unrelated edits elsewhere in the file do not invalidate it.
pub fn finding_hash(finding: &Finding, project_root: &Path) -> String {
    let relative = relative_file(&finding.file, project_root);
    let context = surrounding_context(&finding.file, finding.line);

    let mut data = Vec::new();
    data.extend_from_slice(finding.rule_id.as_str().as_bytes());
    data.push(0);
    data.extend_from_slice(relative.to_string_lossy().as_bytes());
    data.push(0);
    data.extend_from_slice(finding.matched_text.as_bytes());
    data.push(0);
    data.extend_from_slice(context.as_bytes());
    sha256_hex(&data)
}

/// Snapshot `findings` into a [`Baseline`].
pub fn capture(findings: &[Finding], project_root: &Path) -> Baseline {
    let entries = findings
        .iter()
        .map(|f| BaselineEntry {
            rule_id: f.rule_id.clone(),
            file: relative_file(&f.file, project_root),
            hash: finding_hash(f, project_root),
        })
        .collect();
    Baseline {
        version: 1,
        findings: entries,
    }
}

/// Write `baseline` as pretty JSON to `path`.
pub fn save(baseline: &Baseline, path: &Path) -> Result<(), BaselineError> {
    let mut data = Vec::new();
    serde_json::to_writer_pretty(&mut data, baseline)?;
    data.push(b'\n');
    fs::write(path, data)?;
    Ok(())
}

/// Read a [`Baseline`] from `path`. Errors on a missing file or invalid
/// JSON; a corrupted baseline must fail the scan, not be ignored.
pub fn load(path: &Path) -> Result<Baseline, BaselineError> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

/// Search `start_dir` and its parents for `.slopguard-baseline.json`.
pub fn find_baseline_file(start_dir: &Path) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join(BASELINE_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

/// Split `findings` into those not present in `baseline`. Returns the
/// remaining findings plus the count of findings filtered out.
pub fn filter_new(
    findings: Vec<Finding>,
    baseline: &Baseline,
    project_root: &Path,
) -> (Vec<Finding>, usize) {
    let known: HashSet<&str> = baseline.findings.iter().map(|e| e.hash.as_str()).collect();

    let mut filtered_count = 0;
    let remaining = findings
        .into_iter()
        .filter(|f| {
            if known.contains(finding_hash(f, project_root).as_str()) {
                filtered_count += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (remaining, filtered_count)
}

#[cfg(test)]
mod tests {
    use std::fs::write;

    use tempfile::tempdir;

    use super::*;
    use crate::rule::{Category, Severity};

    fn sample_finding(file: PathBuf, line: usize) -> Finding {
        Finding {
            rule_id: RuleId::from("test-unwrap"),
            severity: Severity::Error,
            category: Category::Correctness,
            message: ".unwrap() forbidden".to_string(),
            note: None,
            fix: None,
            file,
            line,
            column: 5,
            end_line: line,
            end_column: 20,
            matched_text: "foo().unwrap()".to_string(),
            confidence: None,
        }
    }

    #[test]
    fn capture_then_filter_removes_all() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {\n    foo().unwrap();\n}\n").unwrap();

        let findings = vec![sample_finding(file, 2)];
        let baseline = capture(&findings, dir.path());
        let (remaining, filtered) = filter_new(findings, &baseline, dir.path());

        assert_eq!(remaining.len(), 0);
        assert_eq!(filtered, 1);
    }

    #[test]
    fn unrelated_line_insertion_does_not_break_the_filter() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(
            &file,
            "// padding a\n// padding b\n// padding c\nfn main() {\n    foo().unwrap();\n}\n// padding d\n// padding e\n",
        )
        .unwrap();

        let findings = vec![sample_finding(file.clone(), 5)];
        let baseline = capture(&findings, dir.path());

        // Insert a line far above the match, outside its 2-line context
        // window; the finding's own line shifts but the context is unchanged.
        write(
            &file,
            "// a new comment\n// padding a\n// padding b\n// padding c\nfn main() {\n    foo().unwrap();\n}\n// padding d\n// padding e\n",
        )
        .unwrap();
        let shifted_findings = vec![sample_finding(file, 6)];

        let (remaining, filtered) = filter_new(shifted_findings, &baseline, dir.path());
        assert_eq!(remaining.len(), 0);
        assert_eq!(filtered, 1);
    }

    #[test]
    fn changed_matched_text_is_no_longer_filtered() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {\n    foo().unwrap();\n}\n").unwrap();

        let findings = vec![sample_finding(file.clone(), 2)];
        let baseline = capture(&findings, dir.path());

        write(&file, "fn main() {\n    bar().unwrap();\n}\n").unwrap();
        let mut changed = sample_finding(file, 2);
        changed.matched_text = "bar().unwrap()".to_string();

        let (remaining, filtered) = filter_new(vec![changed], &baseline, dir.path());
        assert_eq!(remaining.len(), 1);
        assert_eq!(filtered, 0);
    }

    #[test]
    fn changed_context_is_no_longer_filtered() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {\n    foo().unwrap();\n}\n").unwrap();

        let findings = vec![sample_finding(file.clone(), 2)];
        let baseline = capture(&findings, dir.path());

        write(
            &file,
            "fn main() {\n    if true {\n    foo().unwrap();\n    }\n}\n",
        )
        .unwrap();
        let changed = sample_finding(file, 3);

        let (remaining, filtered) = filter_new(vec![changed], &baseline, dir.path());
        assert_eq!(remaining.len(), 1);
        assert_eq!(filtered, 0);
    }

    #[test]
    fn fixed_finding_disappears_without_panic() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {\n    foo().unwrap();\n}\n").unwrap();

        let findings = vec![sample_finding(file, 2)];
        let baseline = capture(&findings, dir.path());

        let (remaining, filtered) = filter_new(Vec::new(), &baseline, dir.path());
        assert_eq!(remaining.len(), 0);
        assert_eq!(filtered, 0);
    }

    #[test]
    fn load_corrupted_json_is_an_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".slopguard-baseline.json");
        write(&path, "not valid json {{{").unwrap();

        let err = load(&path).unwrap_err();
        assert!(matches!(err, BaselineError::Json(_)), "{err:?}");
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {\n    foo().unwrap();\n}\n").unwrap();

        let findings = vec![sample_finding(file, 2)];
        let baseline = capture(&findings, dir.path());
        let path = dir.path().join(".slopguard-baseline.json");
        save(&baseline, &path).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].hash, baseline.findings[0].hash);
    }

    #[test]
    fn find_baseline_file_in_current_dir() {
        let dir = tempdir().unwrap();
        write(dir.path().join(BASELINE_FILE), "{}").unwrap();

        let found = find_baseline_file(dir.path());
        assert_eq!(found, Some(dir.path().join(BASELINE_FILE)));
    }

    #[test]
    fn find_baseline_file_in_parent_dir() {
        let dir = tempdir().unwrap();
        write(dir.path().join(BASELINE_FILE), "{}").unwrap();
        let child = dir.path().join("src").join("nested");
        std::fs::create_dir_all(&child).unwrap();

        let found = find_baseline_file(&child);
        assert_eq!(found, Some(dir.path().join(BASELINE_FILE)));
    }

    #[test]
    fn find_baseline_file_none_when_absent() {
        let dir = tempdir().unwrap();
        assert_eq!(find_baseline_file(dir.path()), None);
    }
}
