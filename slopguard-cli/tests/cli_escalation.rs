mod common;

use std::fs::write;
use std::path::Path;
use std::process::Output;

use predicates::prelude::*;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

/// `[escalation]` on with the documented default threshold.
const ESCALATION_ON: &str = "[escalation]\nenabled = true\nthreshold = 5\n";

/// Every command pins `--rule no-todo-fixme` so the assertions can name exact
/// counts: the fixture is about repetition of one rule, not about coverage.
const ONLY_TODO: [&str; 2] = ["--rule", "no-todo-fixme"];

/// `n` repetitions of the same warning-severity rule (`no-todo-fixme`) inside
/// one function, so every finding shares a file and a rule id.
fn todo_file(n: usize) -> String {
    let mut out = String::from("fn main() {\n");
    for _ in 0..n {
        out.push_str("    // TODO: fix this\n");
    }
    out.push_str("}\n");
    out
}

/// A project with `n` TODO comments and the given `slopguard.toml` body.
fn project(n_todos: usize, config: &str) -> TempDir {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), todo_file(n_todos)).unwrap();
    write(dir.path().join("slopguard.toml"), config).unwrap();
    dir
}

/// Build the argument list for a run: `base`, the rule pin, then `extra`.
fn args_for(base: &[&str], extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = base.iter().map(|a| (*a).to_string()).collect();
    args.extend(ONLY_TODO.iter().map(|a| (*a).to_string()));
    args.extend(extra.iter().map(|a| (*a).to_string()));
    args
}

/// Run slopguard in `dir`, from the project directory so the generated
/// `slopguard.toml` is the one that applies.
fn run(dir: &Path, base: &[&str], extra: &[&str]) -> Output {
    let args = args_for(base, extra);
    slopguard().current_dir(dir).args(&args).output().unwrap()
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("output should be valid JSON")
}

fn scan_json(dir: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let output = run(dir, &["scan", ".", "--format", "json"], extra);
    let json = parse_json(&output);
    (output.status.code(), json)
}

/// The findings of the `no-todo-fixme` rule, which is the only rule the
/// fixture triggers.
fn todo_findings(json: &Value) -> Vec<&Value> {
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .filter(|f| f["rule_id"] == "no-todo-fixme")
        .collect()
}

fn escalated_count(json: &Value) -> usize {
    todo_findings(json)
        .iter()
        .filter(|f| f["escalated"] == Value::Bool(true))
        .count()
}

#[test]
fn escalates_at_threshold() {
    let dir = project(5, ESCALATION_ON);

    let (code, json) = scan_json(dir.path(), &[]);
    let findings = todo_findings(&json);
    assert_eq!(findings.len(), 5);
    for f in &findings {
        assert_eq!(f["severity"], "error");
        assert_eq!(f["escalated"], Value::Bool(true));
    }
    assert_eq!(json["stats"]["errors"].as_u64(), Some(5));
    assert_eq!(json["stats"]["warnings"].as_u64(), Some(0));
    assert_eq!(code, Some(1));
}

#[test]
fn below_threshold_stays_warning() {
    let dir = project(4, ESCALATION_ON);

    let (_, json) = scan_json(dir.path(), &[]);
    let findings = todo_findings(&json);
    assert_eq!(findings.len(), 4);
    for f in &findings {
        assert_eq!(f["severity"], "warning");
        assert_eq!(f["escalated"], Value::Bool(false));
    }
    assert_eq!(escalated_count(&json), 0);
}

#[test]
fn no_escalation_flag_disables_it() {
    let dir = project(5, ESCALATION_ON);

    let (_, json) = scan_json(dir.path(), &["--no-escalation"]);
    assert_eq!(escalated_count(&json), 0);
    for f in todo_findings(&json) {
        assert_eq!(f["severity"], "warning");
    }
}

#[test]
fn disabled_by_default() {
    let dir = project(10, "[rulesets]\ncorrectness = true\n");

    let (_, json) = scan_json(dir.path(), &[]);
    assert_eq!(todo_findings(&json).len(), 10);
    assert_eq!(escalated_count(&json), 0);
}

#[test]
fn per_rule_override_applies() {
    let config = format!("{ESCALATION_ON}\n[escalation.rules]\nno-todo-fixme = 3\n");
    let dir = project(3, &config);

    let (_, json) = scan_json(dir.path(), &[]);
    let findings = todo_findings(&json);
    assert_eq!(findings.len(), 3);
    assert_eq!(escalated_count(&json), 3);
    for f in &findings {
        assert_eq!(f["severity"], "error");
    }
}

#[test]
fn text_output_marks_escalated() {
    let dir = project(5, ESCALATION_ON);
    let args = args_for(&["scan", ".", "--no-colors"], &[]);

    slopguard()
        .current_dir(dir.path())
        .args(&args)
        .assert()
        .stdout(predicate::str::contains("error[escalated][no-todo-fixme]"))
        .stdout(predicate::str::contains("escalated to error"));
}

#[test]
fn sarif_marks_escalated() {
    let dir = project(5, ESCALATION_ON);

    let output = run(dir.path(), &["scan", ".", "--format", "sarif"], &[]);
    let json = parse_json(&output);

    let first = &json["runs"][0]["results"][0];
    assert_eq!(first["level"], "error");
    assert_eq!(first["properties"]["escalated"], Value::Bool(true));
}

#[test]
fn severity_threshold_error_fails_on_escalated_warnings() {
    let dir = project(5, ESCALATION_ON);
    let base = ["scan", ".", "--severity-threshold", "error"];

    let escalating = run(dir.path(), &base, &[]);
    assert_eq!(escalating.status.code(), Some(1));

    let plain = run(dir.path(), &base, &["--no-escalation"]);
    assert_eq!(plain.status.code(), Some(0));
}

#[test]
fn stats_counts_escalated_as_errors() {
    let dir = project(5, ESCALATION_ON);
    let base = ["stats", ".", "--format", "json"];

    let json = parse_json(&run(dir.path(), &base, &[]));
    assert_eq!(json["by_severity"]["error"].as_u64(), Some(5));
    assert_eq!(json["by_severity"]["warning"].as_u64(), Some(0));

    let json = parse_json(&run(dir.path(), &base, &["--no-escalation"]));
    assert_eq!(json["by_severity"]["error"].as_u64(), Some(0));
    assert_eq!(json["by_severity"]["warning"].as_u64(), Some(5));
}

#[test]
fn escalation_is_not_cached() {
    let dir = project(5, ESCALATION_ON);

    // First run populates the file cache with the raw (un-escalated) findings.
    let (_, first) = scan_json(dir.path(), &[]);
    assert_eq!(escalated_count(&first), 5);

    // Second run reads them back from the cache and must escalate again.
    let (_, second) = scan_json(dir.path(), &[]);
    assert_eq!(escalated_count(&second), 5);
    for f in todo_findings(&second) {
        assert_eq!(f["severity"], "error");
    }
}
