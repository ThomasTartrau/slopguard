use std::fs::{create_dir, write};

use tempfile::tempdir;

use super::test_support::*;
use super::*;
use crate::config::Config;
use crate::rule::{load_builtin_rules, parse_rule, RuleId};

#[test]
fn scan_finds_unwrap_violation() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.findings.len(), 1);
    let f = &result.findings[0];
    assert_eq!(f.rule_id, RuleId::from("test-unwrap"));
    assert_eq!(f.severity, Severity::Error);
    assert_eq!(f.line, 2);
    assert!(f.matched_text.contains("unwrap()"));
}

#[test]
fn scan_clean_file_no_findings() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() { let x = foo(); }\n").unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn scan_unsupported_language_ignored() {
    let dir = tempdir().unwrap();
    write(dir.path().join("script.py"), "x.unwrap()\n").unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn scan_explicit_file_path() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("main.rs");
    write(&file, "fn main() { foo().unwrap(); }\n").unwrap();
    let result = scan(&[file], &[unwrap_rule()], &Config::default()).unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn rule_ignores_glob_respected() {
    let dir = tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    create_dir(&tests_dir).unwrap();
    write(
        tests_dir.join("test_main.rs"),
        "fn t() { foo().unwrap(); }\n",
    )
    .unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() { foo().unwrap(); }\n",
    )
    .unwrap();
    let rule = parse_rule(
        r#"
id: ign
language: rust
severity: error
category: correctness
message: x
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
ignores:
  - "**/tests/**"
"#,
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0]
        .file
        .to_string_lossy()
        .contains("main.rs"));
}

#[test]
fn config_ignores_respected() {
    let dir = tempdir().unwrap();
    let gen = dir.path().join("generated");
    create_dir(&gen).unwrap();
    write(gen.join("out.rs"), "fn g() { foo().unwrap(); }\n").unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() { foo().unwrap(); }\n",
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.scan.ignores = vec!["**/generated/**".to_string()];
    let result = scan(&[dir.path().to_path_buf()], &[unwrap_rule()], &cfg).unwrap();
    assert_eq!(result.stats.files_scanned, 1);
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn config_invalid_glob_is_an_error() {
    let dir = tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.scan.ignores = vec!["[".to_string()];
    let err = scan(&[dir.path().to_path_buf()], &[unwrap_rule()], &cfg).unwrap_err();
    assert!(matches!(err, ScanError::Glob(_)), "{err:?}");
}

#[test]
fn rule_without_kind_fails_to_compile() {
    let dir = tempdir().unwrap();
    let rule = parse_rule(
        r#"
id: no-kind
language: rust
severity: error
category: correctness
message: x
rule:
  regex: 'unwrap'
"#,
    )
    .unwrap();
    let err = scan(&[dir.path().to_path_buf()], &[rule], &Config::default()).unwrap_err();
    assert!(
        matches!(&err, ScanError::RuleCompile { id, .. } if *id == RuleId::from("no-kind")),
        "{err:?}"
    );
}

#[test]
fn stats_counting_accurate() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("a.rs"),
        "fn f() { foo().unwrap(); bar().unwrap(); }\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.stats.errors, 2);
    assert_eq!(result.stats.warnings, 0);
    assert_eq!(result.stats.total, 2);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn scan_empty_file() {
    let dir = tempdir().unwrap();
    write(dir.path().join("empty.rs"), "").unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn scan_complex_rule() {
    let rule = parse_rule(
        r#"
id: dbg
language: rust
severity: error
category: security
message: debug on secret
rule:
  kind: attribute_item
  all:
    - regex: 'derive\([^)]*Debug'
    - precedes:
        kind: struct_item
        has:
          kind: field_identifier
          regex: '^(api_key|password|secret)$'
          stopBy: end
"#,
    )
    .unwrap();
    let dir = tempdir().unwrap();
    write(
        dir.path().join("t.rs"),
        "#[derive(Debug)]\nstruct Config {\n    api_key: String,\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, RuleId::from("dbg"));
}

#[test]
fn typescript_rule_applies_to_tsx_files() {
    let rule = parse_rule(
        r#"
id: ts-any
language: typescript
severity: warning
category: slop
message: no any
rule:
  kind: predefined_type
  regex: '^any$'
"#,
    )
    .unwrap();
    let dir = tempdir().unwrap();
    write(dir.path().join("a.ts"), "let x: any = 1;\n").unwrap();
    write(dir.path().join("b.tsx"), "let y: any = 2;\n").unwrap();
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.stats.files_scanned, 2);
    assert_eq!(result.stats.warnings, 2);
}

#[test]
fn scan_with_disable_comment_filters_findings() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    // slopguard-disable-next-line\n    foo().unwrap();\n    bar().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(
        result.findings.len(),
        1,
        "only the non-disabled unwrap should remain"
    );
    assert_eq!(result.findings[0].line, 4);
}

#[test]
fn scan_with_disable_rule_id_filters_only_that_rule() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    // slopguard-disable-next-line test-unwrap\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn cfg_test_block_excluded_by_post_filter() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn prod() {\n    foo().unwrap();\n}\n\n#[cfg(test)]\nmod tests {\n    fn test_it() {\n        bar().unwrap();\n    }\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
    assert_eq!(
        result.findings.len(),
        1,
        "should only find the prod unwrap, not the one inside #[cfg(test)]"
    );
    assert_eq!(result.findings[0].line, 2);
}

#[test]
fn cfg_test_kept_without_skip_test_code() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn prod() {\n    foo().unwrap();\n}\n\n#[cfg(test)]\nmod tests {\n    fn test_it() {\n        bar().unwrap();\n    }\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(
        result.findings.len(),
        2,
        "rule without skip_test_code should find both"
    );
}

#[test]
fn integration_test_file_excluded_by_skip_test_code() {
    let dir = tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    std::fs::create_dir(&tests_dir).unwrap();
    write(
        tests_dir.join("it.rs"),
        "fn check() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
    assert_eq!(
        result.findings.len(),
        0,
        "unwrap inside a tests/ integration file should be skipped"
    );
}

#[test]
fn integration_test_file_kept_without_skip_test_code() {
    let dir = tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    std::fs::create_dir(&tests_dir).unwrap();
    write(
        tests_dir.join("it.rs"),
        "fn check() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(
        result.findings.len(),
        1,
        "rule without skip_test_code should still flag tests/ files"
    );
}

#[test]
fn test_crate_directory_excluded_by_skip_test_code() {
    let dir = tempdir().unwrap();
    let test_crate = dir
        .path()
        .join("crates")
        .join("integrations_tests")
        .join("src");
    std::fs::create_dir_all(&test_crate).unwrap();
    write(
        test_crate.join("api.rs"),
        "fn check() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
    assert_eq!(
        result.findings.len(),
        0,
        "unwrap inside a *_tests crate should be skipped"
    );
}

#[test]
fn test_crate_directory_kept_without_skip_test_code() {
    let dir = tempdir().unwrap();
    let test_crate = dir
        .path()
        .join("crates")
        .join("integrations_tests")
        .join("src");
    std::fs::create_dir_all(&test_crate).unwrap();
    write(
        test_crate.join("api.rs"),
        "fn check() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();
    let result = scan_dir(dir.path(), &[unwrap_rule()]);
    assert_eq!(
        result.findings.len(),
        1,
        "rule without skip_test_code should still flag *_tests crate files"
    );
}

#[test]
fn all_builtin_rules_compile() {
    let rules = load_builtin_rules().unwrap();
    assert!(
        rules.len() >= 55,
        "expected at least 55 rules, got {}",
        rules.len()
    );
    let compiled =
        compile_rules(&rules, TestPaths::default()).expect("all builtin rules should compile");
    let ast_rule_count = rules
        .iter()
        .filter(|r| !r.is_metric() && !r.is_cross_file() && !r.is_resolution())
        .count();
    assert_eq!(compiled.by_id.len(), ast_rule_count);
    assert!(
        !compiled.cross_file.is_empty(),
        "builtin rules should include cross-file rules"
    );
    assert!(
        !compiled.metrics.is_empty(),
        "builtin rules should include metric rules"
    );
}

#[test]
fn scan_files_only_scans_given_files() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.rs");
    let b = dir.path().join("b.rs");
    write(&a, "fn a() {\n    foo().unwrap();\n}\n").unwrap();
    write(&b, "fn b() {\n    bar().unwrap();\n}\n").unwrap();

    let result = scan_files(&[a], &[unwrap_rule()], &Config::default()).unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.stats.files_scanned, 1);
    assert!(result.findings[0].file.to_string_lossy().contains("a.rs"));
}

#[test]
fn scan_files_skips_unsupported_language() {
    let dir = tempdir().unwrap();
    let py = dir.path().join("script.py");
    write(&py, "x.unwrap()\n").unwrap();

    let result = scan_files(&[py], &[unwrap_rule()], &Config::default()).unwrap();
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 0);
}

#[test]
fn scan_files_skips_missing_file() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("gone.rs");

    let result = scan_files(&[missing], &[unwrap_rule()], &Config::default()).unwrap();
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 0);
}

#[test]
fn scan_files_respects_config_ignores() {
    let dir = tempdir().unwrap();
    let gen = dir.path().join("generated");
    create_dir(&gen).unwrap();
    let out = gen.join("out.rs");
    write(&out, "fn g() { foo().unwrap(); }\n").unwrap();

    let mut cfg = Config::default();
    cfg.scan.ignores = vec!["**/generated/**".to_string()];
    let result = scan_files(&[out], &[unwrap_rule()], &cfg).unwrap();
    assert_eq!(result.findings.len(), 0);
    assert_eq!(result.stats.files_scanned, 0);
}
