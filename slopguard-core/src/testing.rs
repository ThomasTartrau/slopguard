use std::path::Path;

use ast_grep_config::{CombinedScan, RuleCollection};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use thiserror::Error;

use crate::rule::{Rule, RuleId};
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
    use crate::rule::parse_rule;

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
}
