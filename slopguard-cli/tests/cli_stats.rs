mod common;

use std::fs::write;
use std::path::Path;

use predicates::prelude::*;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

/// Two violations, so the report exercises plural labels and a non-trivial
/// per-rule tally.
const BAD_RS: &str = "fn main() {\n    foo().unwrap();\n    bar().unwrap();\n}\n";
const BAD_TS: &str = "function f(x: any) { return x; }\n";

fn project_with(name: &str, content: &str) -> TempDir {
    let dir = tempdir().unwrap();
    write(dir.path().join(name), content).unwrap();
    dir
}

/// A project with known violations and a baseline already captured.
fn baselined_project() -> TempDir {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    dir
}

fn stats_json(dir: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let mut args = vec!["stats", ".", "--format", "json"];
    args.extend_from_slice(extra);
    let output = slopguard().current_dir(dir).args(&args).output().unwrap();
    let json: Value =
        serde_json::from_slice(&output.stdout).expect("stats output should be valid JSON");
    (output.status.code(), json)
}

fn scan_json(dir: &Path) -> Value {
    let output = slopguard()
        .current_dir(dir)
        .args(["scan", ".", "--format", "json"])
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).expect("scan output should be valid JSON")
}

#[test]
fn stats_json_has_all_axes() {
    let dir = project_with("bad.rs", BAD_RS);

    let (code, json) = stats_json(dir.path(), &[]);
    assert_eq!(code, Some(0));

    assert!(json["by_severity"]["warning"].is_u64());
    assert!(json["by_severity"]["error"].is_u64());

    let by_category = json["by_category"]
        .as_object()
        .expect("by_category should be an object");
    for key in ["slop", "security", "correctness"] {
        assert!(
            by_category.get(key).is_some_and(Value::is_u64),
            "by_category.{key} should always be present as a number"
        );
    }

    assert!(json["by_language"]["rust"].as_u64().unwrap() >= 1);
}

#[test]
fn stats_top_rules_capped() {
    let dir = project_with("bad.rs", BAD_RS);

    let (_, json) = stats_json(dir.path(), &[]);
    let top_rules = json["top_rules"]
        .as_array()
        .expect("top_rules should be an array");
    assert!(top_rules.len() <= 10, "top_rules should be capped at 10");
    for entry in top_rules {
        assert!(entry["rule_id"].is_string());
        assert!(entry["count"].is_u64());
    }
}

#[test]
fn stats_top_files_capped() {
    let dir = project_with("bad.rs", BAD_RS);

    let (_, json) = stats_json(dir.path(), &[]);
    let top_files = json["top_files"]
        .as_array()
        .expect("top_files should be an array");
    assert!(top_files.len() <= 5, "top_files should be capped at 5");
    for entry in top_files {
        assert!(entry["file"].is_string());
        assert!(entry["count"].is_u64());
    }
}

#[test]
fn stats_counts_match_findings() {
    let dir = project_with("bad.rs", BAD_RS);

    let scan = scan_json(dir.path());
    let (_, stats) = stats_json(dir.path(), &[]);

    assert_eq!(stats["by_severity"]["error"], scan["stats"]["errors"]);
    assert_eq!(stats["total"], scan["stats"]["total"]);
}

#[test]
fn stats_clean_project_zeroed() {
    let dir = project_with("main.rs", "fn main() {}\n");

    let (code, json) = stats_json(dir.path(), &[]);
    assert_eq!(code, Some(0));
    assert_eq!(json["total"], 0);

    for key in ["slop", "security", "correctness"] {
        assert_eq!(json["by_category"][key], 0, "by_category.{key} should be 0");
    }
    let top_rules = json["top_rules"]
        .as_array()
        .expect("top_rules should be an array");
    assert!(top_rules.is_empty(), "a clean project has no top rules");
}

#[test]
fn stats_typescript_counted() {
    let dir = project_with("bad.ts", BAD_TS);

    let (code, json) = stats_json(dir.path(), &[]);
    assert_eq!(code, Some(0));
    assert!(json["by_language"]["typescript"].as_u64().unwrap() >= 1);
}

#[test]
fn stats_text_output() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("findings in"))
        .stdout(predicate::str::contains("severity"))
        .stdout(predicate::str::contains("error"))
        .stdout(predicate::str::contains("warning"))
        .stdout(predicate::str::contains("category"))
        .stdout(predicate::str::contains("slop"))
        .stdout(predicate::str::contains("language"))
        .stdout(predicate::str::contains("rust"))
        .stdout(predicate::str::contains("rule"))
        .stdout(predicate::str::contains("file"));
}

#[test]
fn stats_text_has_no_ansi_with_no_colors() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{1b}[").not());
}

#[test]
fn stats_respects_baseline() {
    let dir = baselined_project();

    let (code, json) = stats_json(dir.path(), &[]);
    assert_eq!(code, Some(0));
    assert_eq!(json["total"], 0);
    assert!(
        json["baseline_filtered"].as_u64().unwrap() >= 1,
        "the baselined findings should be counted as filtered"
    );

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("filtered by baseline"));
}

#[test]
fn stats_no_baseline_flag() {
    let dir = baselined_project();

    let (code, json) = stats_json(dir.path(), &["--no-baseline"]);
    assert_eq!(code, Some(0));
    assert!(
        json["total"].as_u64().unwrap() >= 1,
        "--no-baseline should count the baselined findings"
    );
}

#[test]
fn stats_sarif_rejected() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--format", "sarif"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SARIF"));
}

#[test]
fn stats_exits_zero_with_findings() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", "."])
        .assert()
        .success();
}

#[test]
fn stats_unknown_rule_errors() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--rule", "nope"])
        .assert()
        .code(2);
}

#[test]
fn stats_with_no_ai() {
    let dir = project_with("bad.rs", BAD_RS);

    let (code, json) = stats_json(dir.path(), &["--no-ai"]);
    assert_eq!(code, Some(0));
    assert!(json["total"].is_u64());
}
