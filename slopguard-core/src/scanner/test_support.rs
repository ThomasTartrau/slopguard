//! Shared fixtures for the scanner test modules.

use std::path::Path;

use crate::config::Config;
use crate::finding::ScanResult;
use crate::rule::{parse_rule, Rule};

use super::scan;

pub(super) fn unwrap_rule() -> Rule {
    parse_rule(
        r#"
id: test-unwrap
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
    )
    .unwrap()
}

pub(super) fn unwrap_rule_skipping_test_code() -> Rule {
    parse_rule(
        r#"
id: test-unwrap
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
skip_test_code: true
"#,
    )
    .unwrap()
}

pub(super) fn metric_rule(body: &str) -> Rule {
    parse_rule(body).unwrap()
}

pub(super) fn file_lines_rule() -> Rule {
    metric_rule(
        r#"
id: test-file-lines
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "File is too long"
"#,
    )
}

pub(super) fn single_impl_trait_rule() -> Rule {
    parse_rule(
        r#"
id: no-single-impl-trait
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
message: "Trait with a single implementation in the project."
skip_test_code: true
"#,
    )
    .unwrap()
}

/// `n` lines of trivial Rust, one comment per line.
pub(super) fn rust_lines(n: usize) -> String {
    (0..n).map(|i| format!("// line {i}\n")).collect()
}

pub(super) fn scan_dir(dir: &Path, rules: &[Rule]) -> ScanResult {
    scan(&[dir.to_path_buf()], rules, &Config::default()).unwrap()
}
