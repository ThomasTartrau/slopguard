use std::path::Path;

use ast_grep_config::{CombinedScan, RuleCollection};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use thiserror::Error;

use crate::metric::{self, Metric};
use crate::rule::{self, Rule, RuleId, RuleTests};
use crate::scanner::{compile_ast_grep_rule, AstGrepRule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTestStatus {
    Pass,
    Fail { failures: Vec<TestFailure> },
    NoTests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFailure {
    pub kind: TestFailureKind,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestFailureKind {
    ShouldMatchDidNot,
    ShouldNotMatchDid,
}

#[derive(Debug, Clone)]
pub struct RuleTestResult {
    pub rule_id: RuleId,
    pub status: RuleTestStatus,
}

#[derive(Debug)]
pub struct TestSummary {
    pub results: Vec<RuleTestResult>,
    pub total_tested: usize,
    pub passed: usize,
    pub failed: usize,
    pub no_tests: usize,
}

#[derive(Debug, Error)]
pub enum TestError {
    #[error("failed to compile rule '{id}': {reason}")]
    CompileError { id: RuleId, reason: String },

    #[error("rule '{id}': fixture '{path}': {reason}")]
    Fixture {
        id: RuleId,
        path: String,
        reason: String,
    },
}

fn lang_ext(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::Rust => "test.rs",
        SupportLang::TypeScript => "test.ts",
        SupportLang::Tsx => "test.tsx",
        _ => "test.rs",
    }
}

fn count_matches(
    source: &str,
    lang: SupportLang,
    collection: &RuleCollection<SupportLang>,
) -> usize {
    let root = lang.ast_grep(source);
    let applicable = collection.get_rule_from_lang(Path::new(lang_ext(lang)), lang);
    let combined = CombinedScan::new(applicable);
    let result = combined.scan(&root, false);
    result.matches.iter().map(|(_, m)| m.len()).sum()
}

/// The `(label, content)` pairs a metric rule is tested against: inline
/// whole-file snippets plus the contents of every referenced fixture.
///
/// The label is what a failure reports. For a fixture it is the path, which
/// keeps CLI output short: a 600-line fixture has no useful first line.
fn metric_cases(
    rule: &Rule,
    inline: &[String],
    fixtures: &[String],
) -> Result<Vec<(String, String)>, TestError> {
    let mut cases: Vec<(String, String)> = inline
        .iter()
        .map(|snippet| (snippet.clone(), snippet.clone()))
        .collect();
    for path in fixtures {
        let content = rule::read_fixture(rule, path).map_err(|e| TestError::Fixture {
            id: rule.id.clone(),
            path: path.clone(),
            reason: e.to_string(),
        })?;
        cases.push((path.clone(), content));
    }
    Ok(cases)
}

/// Run a metric rule's tests: every should-match case must exceed the
/// threshold, every should-not-match case must stay at or below it.
fn test_metric_rule(
    rule: &Rule,
    metric: Metric,
    threshold: f64,
    tests: &RuleTests,
) -> Result<RuleTestResult, TestError> {
    let lang = rule.language.ast_grep_langs()[0];
    let measure = |content: &str| {
        let root = lang.ast_grep(content);
        metric::compute(metric, &rule.language, &root, content)
    };

    let mut failures = Vec::new();

    for (label, content) in metric_cases(rule, &tests.should_match, &tests.should_match_files)? {
        if !metric::exceeds(measure(&content), threshold) {
            failures.push(TestFailure {
                kind: TestFailureKind::ShouldMatchDidNot,
                snippet: label,
            });
        }
    }

    for (label, content) in
        metric_cases(rule, &tests.should_not_match, &tests.should_not_match_files)?
    {
        if metric::exceeds(measure(&content), threshold) {
            failures.push(TestFailure {
                kind: TestFailureKind::ShouldNotMatchDid,
                snippet: label,
            });
        }
    }

    let status = if failures.is_empty() {
        RuleTestStatus::Pass
    } else {
        RuleTestStatus::Fail { failures }
    };

    Ok(RuleTestResult {
        rule_id: rule.id.clone(),
        status,
    })
}

fn test_one_rule(rule: &Rule) -> Result<RuleTestResult, TestError> {
    let tests = match &rule.tests {
        Some(t) => t,
        None => {
            return Ok(RuleTestResult {
                rule_id: rule.id.clone(),
                status: RuleTestStatus::NoTests,
            });
        }
    };

    if let Some((metric, threshold)) = rule.metric_spec() {
        return test_metric_rule(rule, metric, threshold, tests);
    }
    if rule.is_metric() {
        return Err(TestError::CompileError {
            id: rule.id.clone(),
            reason: "metric rule is missing a threshold".to_string(),
        });
    }

    let lang = rule.language.ast_grep_langs()[0];
    let ast_grep_rule = AstGrepRule {
        id: rule.id.as_str(),
        language: lang,
        severity: &rule.severity,
        message: &rule.message,
        note: rule.note.as_deref(),
        rule: &rule.rule,
        files: None,
        ignores: None,
    };
    let config = compile_ast_grep_rule(&ast_grep_rule).map_err(|e| TestError::CompileError {
        id: rule.id.clone(),
        reason: e.to_string(),
    })?;
    let collection =
        RuleCollection::try_new(vec![config]).map_err(|e| TestError::CompileError {
            id: rule.id.clone(),
            reason: e.to_string(),
        })?;

    let mut failures = Vec::new();

    for snippet in &tests.should_match {
        if count_matches(snippet, lang, &collection) == 0 {
            failures.push(TestFailure {
                kind: TestFailureKind::ShouldMatchDidNot,
                snippet: snippet.clone(),
            });
        }
    }

    for snippet in &tests.should_not_match {
        if count_matches(snippet, lang, &collection) > 0 {
            failures.push(TestFailure {
                kind: TestFailureKind::ShouldNotMatchDid,
                snippet: snippet.clone(),
            });
        }
    }

    let status = if failures.is_empty() {
        RuleTestStatus::Pass
    } else {
        RuleTestStatus::Fail { failures }
    };

    Ok(RuleTestResult {
        rule_id: rule.id.clone(),
        status,
    })
}

/// Test all rules' inline test cases. Returns a summary with per-rule results.
pub fn test_rules(rules: &[Rule]) -> Result<TestSummary, TestError> {
    let mut results = Vec::with_capacity(rules.len());
    let mut passed = 0;
    let mut failed = 0;
    let mut no_tests = 0;
    let mut total_tested = 0;

    for rule in rules {
        let result = test_one_rule(rule)?;
        match &result.status {
            RuleTestStatus::Pass => {
                passed += 1;
                total_tested += 1;
            }
            RuleTestStatus::Fail { .. } => {
                failed += 1;
                total_tested += 1;
            }
            RuleTestStatus::NoTests => {
                no_tests += 1;
            }
        }
        results.push(result);
    }

    Ok(TestSummary {
        results,
        total_tested,
        passed,
        failed,
        no_tests,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir, write};

    use tempfile::tempdir;

    use crate::rule::{load_builtin_rules, load_custom_rules, parse_rule};

    use super::*;

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
}
