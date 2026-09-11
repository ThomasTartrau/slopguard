mod common;

use std::fs::{create_dir_all, write};

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

#[test]
fn test_passes_with_valid_rule() {
    let dir = tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    create_dir_all(&rules_dir).unwrap();

    write(
        rules_dir.join("good.yml"),
        r#"
id: test-good
language: rust
severity: error
category: correctness
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

    let config = format!(
        "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n[rules]\ncustom_dirs = [\"{}\"]\n",
        rules_dir.display()
    );
    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, config).unwrap();

    slopguard()
        .args(["test", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"))
        .stdout(predicate::str::contains("1 passed"))
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn test_fails_when_should_match_does_not_match() {
    let dir = tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    create_dir_all(&rules_dir).unwrap();

    write(
        rules_dir.join("bad.yml"),
        r#"
id: test-bad-match
language: rust
severity: error
category: correctness
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

    let config = format!(
        "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n[rules]\ncustom_dirs = [\"{}\"]\n",
        rules_dir.display()
    );
    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, config).unwrap();

    slopguard()
        .args(["test", "--config", config_path.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL"))
        .stdout(predicate::str::contains("should_match"));
}

#[test]
fn test_fails_when_should_not_match_matches() {
    let dir = tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    create_dir_all(&rules_dir).unwrap();

    write(
        rules_dir.join("bad.yml"),
        r#"
id: test-bad-not-match
language: rust
severity: error
category: correctness
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

    let config = format!(
        "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n[rules]\ncustom_dirs = [\"{}\"]\n",
        rules_dir.display()
    );
    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, config).unwrap();

    slopguard()
        .args(["test", "--config", config_path.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL"))
        .stdout(predicate::str::contains("should_not_match"));
}

#[test]
fn test_warns_on_rule_without_tests() {
    let dir = tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    create_dir_all(&rules_dir).unwrap();

    write(
        rules_dir.join("notested.yml"),
        r#"
id: no-tests-rule
language: rust
severity: error
category: correctness
message: "No unwrap"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
    )
    .unwrap();

    let config = format!(
        "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n[rules]\ncustom_dirs = [\"{}\"]\n",
        rules_dir.display()
    );
    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, config).unwrap();

    slopguard()
        .args(["test", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no tests"));
}

#[test]
fn test_runs_on_all_builtin_rules() {
    let output = slopguard().args(["test"]).output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("rules tested"),
        "should show a summary line, got:\n{stdout}"
    );
    assert!(
        stdout.contains("passed"),
        "should mention passed count, got:\n{stdout}"
    );
}
