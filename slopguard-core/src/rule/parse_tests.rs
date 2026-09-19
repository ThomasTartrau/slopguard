use super::*;

#[test]
fn parse_valid_rule_all_fields() {
    let yaml = r#"
id: test-rule
language: rust
severity: error
message: "Test message"
note: "Test note"
category: security
fix: "Use X instead"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
files:
  - "**/src/**/*.rs"
ignores:
  - "**/tests/**"
skip_test_code: true
tests:
  should_match:
    - "let x = foo().unwrap();"
  should_not_match:
    - "let x = foo()?;"
"#;
    let rule = parse_rule(yaml).unwrap();
    assert!(rule.skip_test_code);
    assert_eq!(rule.id, RuleId::from("test-rule"));
    assert_eq!(rule.language, Language::Rust);
    assert_eq!(rule.severity, Severity::Error);
    assert_eq!(rule.message, "Test message");
    assert_eq!(rule.note.as_deref(), Some("Test note"));
    assert_eq!(rule.category, Some(Category::Security));
    assert_eq!(rule.fix.as_deref(), Some("Use X instead"));
    assert!(!rule.rule.is_null());
    assert_eq!(rule.files.as_ref().unwrap().len(), 1);
    assert_eq!(rule.ignores.as_ref().unwrap().len(), 1);
    let tests = rule.tests.as_ref().unwrap();
    assert_eq!(tests.should_match.len(), 1);
    assert_eq!(tests.should_not_match.len(), 1);
}

#[test]
fn parse_rule_with_ai_check() {
    let yaml = r#"
id: ai-rule
language: rust
severity: warning
category: slop
message: "needs AI confirmation"
rule:
  kind: line_comment
  regex: 'SAFETY'
ai_check:
  prompt: "Is this SAFETY comment meaningful?\n{{code}}"
  model: "claude-haiku-4-5"
"#;
    let rule = parse_rule(yaml).unwrap();
    let ai = rule.ai_check.as_ref().expect("ai_check should be present");
    assert_eq!(ai.prompt, "Is this SAFETY comment meaningful?\n{{code}}");
    assert_eq!(ai.model.as_deref(), Some("claude-haiku-4-5"));
}

#[test]
fn parse_rule_ai_check_without_model() {
    let yaml = r#"
id: ai-rule-no-model
language: rust
severity: warning
category: slop
message: "needs AI confirmation"
rule:
  kind: line_comment
ai_check:
  prompt: "check {{filename}}"
"#;
    let rule = parse_rule(yaml).unwrap();
    let ai = rule.ai_check.as_ref().unwrap();
    assert_eq!(ai.prompt, "check {{filename}}");
    assert!(
        ai.model.is_none(),
        "model falls back to config when omitted"
    );
}

#[test]
fn ai_check_reason_defaults_to_static() {
    // A rule that does not set `reason` classifies with a static note: the
    // default must never escalate to the generative LLM.
    let yaml = r#"
id: ai-rule
language: rust
severity: warning
message: "m"
rule:
  kind: line_comment
ai_check:
  prompt: "check {{code}}"
"#;
    let ai = parse_rule(yaml).unwrap().ai_check.unwrap();
    assert_eq!(ai.reason, ReasonMode::Static);
    assert!(ai.threshold.is_none());
    assert!(ai.if_true.is_none());
    assert!(ai.if_false.is_none());
}

#[test]
fn ai_check_reason_generated_with_threshold_and_criteria() {
    let yaml = r#"
id: ai-rel
language: rust
severity: error
message: "m"
rule:
  kind: call_expression
ai_check:
  prompt: "audit {{code}}"
  reason: generated
  threshold: 0.6
  if_true: "external input reaches the call"
  if_false: "a constant or config value"
"#;
    let ai = parse_rule(yaml).unwrap().ai_check.unwrap();
    assert_eq!(ai.reason, ReasonMode::Generated);
    assert_eq!(ai.threshold, Some(0.6));
    assert_eq!(
        ai.if_true.as_deref(),
        Some("external input reaches the call")
    );
    assert_eq!(ai.if_false.as_deref(), Some("a constant or config value"));
}

#[test]
fn ai_check_unknown_reason_is_an_error() {
    let yaml = r#"
id: ai-bad
language: rust
severity: warning
message: "m"
rule:
  kind: line_comment
ai_check:
  prompt: "p"
  reason: sometimes
"#;
    assert!(
        parse_rule(yaml).is_err(),
        "an unknown reason mode must be rejected, not silently defaulted"
    );
}

#[test]
fn parse_minimal_rule() {
    let yaml = r#"
id: minimal-rule
language: rust
severity: warning
message: "Minimal"
rule:
  pattern: $X.unwrap()
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.id, RuleId::from("minimal-rule"));
    assert_eq!(rule.severity, Severity::Warning);
    assert!(rule.note.is_none());
    assert!(rule.category.is_none());
    assert!(rule.fix.is_none());
    assert!(rule.files.is_none());
    assert!(rule.ignores.is_none());
    assert!(!rule.skip_test_code);
    assert!(rule.tests.is_none());
    assert!(rule.enabled);
    assert!(rule.ai_check.is_none());
}

#[test]
fn reject_missing_id() {
    let yaml = r#"
language: rust
severity: error
message: "No id"
rule:
  pattern: $X
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("missing field"),
        "expected missing field error, got: {msg}"
    );
}

#[test]
fn reject_unsupported_language() {
    let yaml = r#"
id: bad-lang
language: python
severity: error
message: "Bad lang"
rule:
  pattern: $X
"#;
    let err = parse_rule(yaml).unwrap_err();
    assert!(matches!(err, RuleError::Parse(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("unknown variant"),
        "expected unknown variant error, got: {msg}"
    );
}

#[test]
fn reject_empty_rule() {
    let yaml = r#"
id: empty-rule
language: rust
severity: error
message: "Empty rule"
rule:
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("must not be empty"),
        "expected empty rule error, got: {msg}"
    );
}

#[test]
fn reject_malformed_yaml() {
    let yaml = "this is: [not: valid: yaml: {{{";
    let err = parse_rule(yaml).unwrap_err();
    assert!(matches!(err, RuleError::Parse(_)));
}

#[test]
fn category_from_rule_path() {
    let category = |p: &str| Category::from_rule_path(Path::new(p));
    assert_eq!(category("slop/no-slop-words.yml"), Some(Category::Slop));
    assert_eq!(category("security/no-debug.yml"), Some(Category::Security));
    assert_eq!(
        category("correctness/no-unwrap.yml"),
        Some(Category::Correctness)
    );
    assert_eq!(category("unknown/something.yml"), None);
    assert_eq!(category("rule.yml"), None);
}

#[test]
fn parse_metric_rule() {
    let yaml = r#"
id: max-lines
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "File exceeds 500 lines ($value lines)."
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.metric, Some(Metric::FileLines));
    assert_eq!(rule.threshold, Some(500.0));
    assert!(rule.is_metric());
    assert_eq!(rule.metric_spec(), Some((Metric::FileLines, 500.0)));
    assert!(rule.rule.is_null());
}

#[test]
fn reject_metric_with_rule() {
    let yaml = r#"
id: both
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "m"
rule:
  pattern: $X
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mutually exclusive"),
        "expected mutually exclusive error, got: {msg}"
    );
}

#[test]
fn reject_metric_without_threshold() {
    let yaml = r#"
id: no-threshold
language: rust
severity: warning
category: slop
metric: file_lines
message: "m"
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("threshold"),
        "expected threshold error, got: {msg}"
    );
}

#[test]
fn reject_fixture_files_on_ast_rule() {
    let yaml = r#"
id: ast-with-fixture
language: rust
severity: warning
category: slop
message: "m"
rule:
  pattern: $X
tests:
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("only supported for metric rules"),
        "expected fixture-on-ast-rule error, got: {msg}"
    );
}

#[test]
fn parse_metric_rule_with_fixture_files() {
    let yaml = r#"
id: metric-with-fixtures
language: rust
severity: warning
category: slop
metric: import_count
threshold: 40
message: "m"
tests:
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
  should_not_match_files:
    - "fixtures/metrics/rust_small.rs"
"#;
    let rule = parse_rule(yaml).unwrap();
    let tests = rule.tests.as_ref().unwrap();
    assert_eq!(
        tests.should_match_files,
        vec!["fixtures/metrics/rust_large.rs".to_string()]
    );
    assert_eq!(
        tests.should_not_match_files,
        vec!["fixtures/metrics/rust_small.rs".to_string()]
    );
}

#[test]
fn parse_cross_file_rule() {
    let yaml = r#"
id: no-single-impl-trait
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
message: "Trait with a single implementation in the project."
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.cross_file, Some(CrossFileKind::SingleImplTrait));
    assert_eq!(rule.cross_file_kind(), Some(CrossFileKind::SingleImplTrait));
    assert!(rule.rule.is_null());
    assert!(rule.is_cross_file());
    assert!(!rule.is_metric());
}

#[test]
fn reject_cross_file_with_rule() {
    let yaml = r#"
id: cross-and-rule
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
message: "m"
rule:
  pattern: $X
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mutually exclusive"),
        "expected mutually exclusive error, got: {msg}"
    );
}

#[test]
fn reject_cross_file_with_metric() {
    let yaml = r#"
id: cross-and-metric
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
metric: file_lines
threshold: 500
message: "m"
"#;
    let err = parse_rule(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mutually exclusive"),
        "expected mutually exclusive error, got: {msg}"
    );
}

#[test]
fn reject_unknown_cross_file_kind() {
    let yaml = r#"
id: unknown-cross-file
language: rust
severity: warning
category: slop
cross_file: no_such_kind
message: "m"
"#;
    let err = parse_rule(yaml).unwrap_err();
    assert!(matches!(err, RuleError::Parse(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("unknown variant"),
        "expected unknown variant error, got: {msg}"
    );
}
