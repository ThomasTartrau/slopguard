use std::fs::{create_dir, write};

use tempfile::tempdir;

use crate::rule::{load_builtin_rules, load_custom_rules, parse_rule};

use super::*;

#[test]
fn cross_file_rule_reports_no_tests() {
    let rule = parse_rule(
        r#"
id: no-single-impl-trait
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
message: "Trait with a single implementation in the project."
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert_eq!(result.status, RuleTestStatus::NoTests);
}

#[test]
fn test_rule_pass() {
    let rule = parse_rule(
        r#"
id: test-pass
language: rust
severity: error
message: "No unwrap"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
tests:
  should_match:
    - "fn f() { foo().unwrap(); }"
  should_not_match:
    - "fn f() { foo()?; }"
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert_eq!(result.rule_id, RuleId::from("test-pass"));
    assert_eq!(result.status, RuleTestStatus::Pass);
}

#[test]
fn test_rule_fail_should_match() {
    let rule = parse_rule(
        r#"
id: test-fail-match
language: rust
severity: error
message: "No unwrap"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
tests:
  should_match:
    - "fn f() { foo()?; }"
  should_not_match:
    - "fn f() { bar()?; }"
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert!(matches!(result.status, RuleTestStatus::Fail { .. }));
    if let RuleTestStatus::Fail { failures } = &result.status {
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, TestFailureKind::ShouldMatchDidNot);
    }
}

#[test]
fn test_rule_fail_should_not_match() {
    let rule = parse_rule(
        r#"
id: test-fail-not-match
language: rust
severity: error
message: "No unwrap"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
tests:
  should_match:
    - "fn f() { foo().unwrap(); }"
  should_not_match:
    - "fn f() { bar().unwrap(); }"
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert!(matches!(result.status, RuleTestStatus::Fail { .. }));
    if let RuleTestStatus::Fail { failures } = &result.status {
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, TestFailureKind::ShouldNotMatchDid);
    }
}

#[test]
fn test_rule_should_fix_pass() {
    let rule = parse_rule(
        r#"
id: test-fix-pass
language: rust
severity: warning
message: "Unnecessary clone"
rewrite: "$R"
autofix_safe: true
rule:
  pattern: $R.clone()
constraints:
  R:
    pattern: $X.to_string()
tests:
  should_match:
    - "fn f() { let s = name.to_string().clone(); }"
  should_fix:
    - before: "fn f() { let s = name.to_string().clone(); }"
      after: "fn f() { let s = name.to_string(); }"
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert_eq!(result.status, RuleTestStatus::Pass);
}

#[test]
fn test_rule_fail_should_fix() {
    let rule = parse_rule(
        r#"
id: test-fix-fail
language: rust
severity: warning
message: "Unnecessary clone"
rewrite: "$R"
autofix_safe: true
rule:
  pattern: $R.clone()
constraints:
  R:
    pattern: $X.to_string()
tests:
  should_fix:
    - before: "fn f() { let s = name.to_string().clone(); }"
      after: "fn f() { let s = WRONG; }"
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert!(matches!(result.status, RuleTestStatus::Fail { .. }));
    if let RuleTestStatus::Fail { failures } = &result.status {
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].kind,
            TestFailureKind::FixMismatch {
                actual: "fn f() { let s = name.to_string(); }".to_string()
            }
        );
    }
}

#[test]
fn test_rule_no_tests() {
    let rule = parse_rule(
        r#"
id: no-tests
language: rust
severity: error
message: "No unwrap"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
    )
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert_eq!(result.status, RuleTestStatus::NoTests);
}

#[test]
fn test_rules_summary() {
    let pass_rule = parse_rule(
        r#"
id: passes
language: rust
severity: error
message: "m"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
tests:
  should_match:
    - "fn f() { foo().unwrap(); }"
  should_not_match:
    - "fn f() { foo()?; }"
"#,
    )
    .unwrap();

    let fail_rule = parse_rule(
        r#"
id: fails
language: rust
severity: error
message: "m"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
tests:
  should_match:
    - "fn f() { foo()?; }"
  should_not_match:
    - "fn f() { bar()?; }"
"#,
    )
    .unwrap();

    let no_test_rule = parse_rule(
        r#"
id: notested
language: rust
severity: error
message: "m"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
    )
    .unwrap();

    let summary = test_rules(&[pass_rule, fail_rule, no_test_rule]).unwrap();
    assert_eq!(summary.total_tested, 2);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.no_tests, 1);
}

/// `n` lines of trivial Rust, as a whole-file test case.
fn rust_lines(n: usize) -> String {
    (0..n).map(|i| format!("fn f{i}() {{}}\n")).collect()
}

/// A whole-file snippet rendered as a YAML double-quoted scalar, so the
/// newlines survive without block-scalar indentation games.
fn yaml_scalar(source: &str) -> String {
    format!("{source:?}")
}

#[test]
fn metric_rule_test_pass_inline() {
    let rule = parse_rule(&format!(
        r#"
id: metric-pass
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 5
message: "m"
tests:
  should_match:
    - {}
  should_not_match:
    - {}
"#,
        yaml_scalar(&rust_lines(8)),
        yaml_scalar(&rust_lines(3))
    ))
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    assert_eq!(result.status, RuleTestStatus::Pass);
}

#[test]
fn metric_rule_test_fail_should_match() {
    let rule = parse_rule(&format!(
        r#"
id: metric-fail-match
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 20
message: "m"
tests:
  should_match:
    - {}
"#,
        yaml_scalar(&rust_lines(3))
    ))
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    match &result.status {
        RuleTestStatus::Fail { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].kind, TestFailureKind::ShouldMatchDidNot);
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn metric_rule_test_fail_should_not_match() {
    let rule = parse_rule(&format!(
        r#"
id: metric-fail-not-match
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 2
message: "m"
tests:
  should_not_match:
    - {}
"#,
        yaml_scalar(&rust_lines(6))
    ))
    .unwrap();

    let result = test_one_rule(&rule).unwrap();
    match &result.status {
        RuleTestStatus::Fail { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].kind, TestFailureKind::ShouldNotMatchDid);
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

/// A custom rule directory holding one metric rule plus its fixture.
fn fixture_rule_dir(threshold: usize) -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let fixtures = dir.path().join("fixtures");
    create_dir(&fixtures).unwrap();
    write(fixtures.join("big.rs"), rust_lines(20)).unwrap();
    write(fixtures.join("small.rs"), rust_lines(3)).unwrap();
    write(
        dir.path().join("metric.yml"),
        format!(
            r#"
id: custom-metric
language: rust
severity: warning
category: slop
metric: file_lines
threshold: {threshold}
message: "m"
tests:
  should_match_files:
    - "fixtures/big.rs"
  should_not_match_files:
    - "fixtures/small.rs"
"#
        ),
    )
    .unwrap();
    dir
}

#[test]
fn metric_rule_test_from_fixture_files() {
    let dir = fixture_rule_dir(10);
    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    let summary = test_rules(&rules).unwrap();
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 0);

    // A threshold above the large fixture makes should_match fail, and the
    // reported snippet is the fixture path, not its 20 lines of content.
    let dir = fixture_rule_dir(100);
    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    let summary = test_rules(&rules).unwrap();
    assert_eq!(summary.failed, 1);
    match &summary.results[0].status {
        RuleTestStatus::Fail { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].snippet, "fixtures/big.rs");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn metric_rule_missing_fixture_errors() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("metric.yml"),
        r#"
id: missing-fixture
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "m"
tests:
  should_match_files:
    - "fixtures/gone.rs"
"#,
    )
    .unwrap();
    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    let err = test_rules(&rules).unwrap_err();
    assert!(matches!(err, TestError::Fixture { .. }), "{err:?}");
}

#[test]
fn all_builtin_metric_rules_pass() {
    let rules: Vec<Rule> = load_builtin_rules()
        .unwrap()
        .into_iter()
        .filter(|r| r.is_metric())
        .collect();
    assert!(!rules.is_empty(), "there should be builtin metric rules");
    let summary = test_rules(&rules).unwrap();
    assert_eq!(summary.failed, 0, "{:?}", summary.results);
    assert_eq!(summary.no_tests, 0, "{:?}", summary.results);
}
