use std::path::Path;

use ast_grep_config::{CombinedScan, RuleCollection};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use thiserror::Error;

use crate::fix::fix_snippet;
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
    /// A `should_fix` case's rewrite did not produce the expected `after`.
    FixMismatch {
        actual: String,
    },
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

/// Run a metric rule's tests: every should-match case must fire, every
/// should-not-match case must not. A metric fires only when the file reaches
/// `min_lines` (if set) and its value exceeds the threshold, matching the
/// scanner so a below-floor should-match case is a genuine failure.
fn test_metric_rule(
    rule: &Rule,
    metric: Metric,
    threshold: f64,
    tests: &RuleTests,
) -> Result<RuleTestResult, TestError> {
    let lang = rule.language.ast_grep_langs()[0];
    let fires = |content: &str| {
        if let Some(floor) = rule.min_lines {
            if content.lines().count() < floor {
                return false;
            }
        }
        let root = lang.ast_grep(content);
        // Fixtures are self-contained metric cases: count everything, so a
        // fixture that exercises the metric is not silently emptied by
        // `#[cfg(test)]` exclusion.
        metric::exceeds(
            metric::compute(metric, &rule.language, &root, content, None),
            threshold,
        )
    };

    let mut failures = Vec::new();

    for (label, content) in metric_cases(rule, &tests.should_match, &tests.should_match_files)? {
        if !fires(&content) {
            failures.push(TestFailure {
                kind: TestFailureKind::ShouldMatchDidNot,
                snippet: label,
            });
        }
    }

    for (label, content) in
        metric_cases(rule, &tests.should_not_match, &tests.should_not_match_files)?
    {
        if fires(&content) {
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
    // A cross-file or resolution rule needs a whole project (and its manifests)
    // to mean anything. A snippet can never exercise it, and compiling its
    // (null) `rule` to ast-grep would fail, so `slopguard test` reports it as
    // untested; its logic is covered by unit and integration tests instead.
    if rule.is_cross_file() || rule.is_resolution() {
        return Ok(RuleTestResult {
            rule_id: rule.id.clone(),
            status: RuleTestStatus::NoTests,
        });
    }

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
        constraints: (!rule.constraints.is_null()).then_some(&rule.constraints),
        fix: None,
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

    for case in &tests.should_fix {
        let actual = fix_snippet(rule, &case.before).map_err(|e| TestError::CompileError {
            id: rule.id.clone(),
            reason: e.to_string(),
        })?;
        if actual != case.after {
            failures.push(TestFailure {
                kind: TestFailureKind::FixMismatch { actual },
                snippet: case.before.clone(),
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
mod tests;
