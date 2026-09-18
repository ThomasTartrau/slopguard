mod common;

use std::fs::{create_dir_all, read_to_string, write};
use std::path::Path;

use predicates::prelude::*;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const BAD: &str = "fn main() {\n    foo().unwrap();\n}\n";

/// A project with one known violation and a baseline already captured.
fn baselined_project() -> TempDir {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    dir
}

fn scan_json(dir: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let mut cmd = slopguard();
    cmd.current_dir(dir).args(["scan", ".", "--format", "json"]);
    cmd.args(extra);
    let output = cmd.output().unwrap();
    let json: Value =
        serde_json::from_slice(&output.stdout).expect("scan output should be valid JSON");
    (output.status.code(), json)
}

#[test]
fn baseline_then_scan_reports_nothing() {
    let dir = baselined_project();

    let (code, json) = scan_json(dir.path(), &[]);
    assert_eq!(code, Some(0));
    assert_eq!(json["stats"]["total"], 0);
}

#[test]
fn no_baseline_flag_reports_everything() {
    let dir = baselined_project();

    let (code, json) = scan_json(dir.path(), &["--no-baseline"]);
    assert_eq!(code, Some(1));
    assert!(
        json["stats"]["total"].as_u64().unwrap() > 0,
        "--no-baseline should report the baselined findings"
    );
}

#[test]
fn baseline_file_contains_findings() {
    let dir = baselined_project();

    let content = read_to_string(dir.path().join(".slopguard-baseline.json")).unwrap();
    let json: Value = serde_json::from_str(&content).expect("baseline should be valid JSON");

    assert_eq!(json["version"], 1);
    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");
    assert!(!findings.is_empty(), "baseline should record the violation");
    for entry in findings {
        assert!(entry["hash"].is_string());
        assert!(entry["rule_id"].is_string());
        assert!(entry["file"].is_string());
    }
}

#[test]
fn baseline_filtered_count_in_json() {
    let dir = baselined_project();

    let content = read_to_string(dir.path().join(".slopguard-baseline.json")).unwrap();
    let baseline: Value = serde_json::from_str(&content).unwrap();
    let baselined = baseline["findings"].as_array().unwrap().len() as u64;

    let (_, json) = scan_json(dir.path(), &[]);
    assert_eq!(json["stats"]["baseline_filtered"], baselined);
}

#[test]
fn baseline_filtered_line_in_text_output() {
    let dir = baselined_project();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("filtered by baseline"));
}

#[test]
fn new_finding_is_reported() {
    let dir = baselined_project();
    write(
        dir.path().join("other.rs"),
        "fn other() {\n    bar().unwrap();\n}\n",
    )
    .unwrap();

    let (code, json) = scan_json(dir.path(), &[]);
    assert_eq!(code, Some(1));

    let findings = json["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "the new violation should be reported");
    for finding in findings {
        let file = finding["file"].as_str().unwrap();
        assert!(
            file.ends_with("other.rs"),
            "only the new file should be reported, got {file}"
        );
    }
}

#[test]
fn baseline_survives_line_shift() {
    // The violation needs real code on both sides, so that shifting it leaves
    // its context window untouched and only its line number moves.
    const PADDED: &str = "fn helper() {}\n\nfn main() {\n    foo().unwrap();\n}\n\nfn other() {}\n";

    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), PADDED).unwrap();
    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    write(
        dir.path().join("bad.rs"),
        format!("fn a() {{}}\nfn b() {{}}\nfn c() {{}}\nfn d() {{}}\nfn e() {{}}\n{PADDED}"),
    )
    .unwrap();

    let (code, json) = scan_json(dir.path(), &["--no-cache"]);
    assert_eq!(code, Some(0));
    assert_eq!(json["stats"]["total"], 0);
    assert_eq!(json["stats"]["baseline_filtered"], 1);
}

#[test]
fn fixed_code_is_silently_ignored() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();
    write(
        dir.path().join("other.rs"),
        "fn other() {\n    bar().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    write(dir.path().join("other.rs"), "fn other() {}\n").unwrap();

    let output = slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-colors"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("baseline"),
        "a stale baseline entry should not warn: {stderr}"
    );
}

#[test]
fn explicit_baseline_path() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "-o", "custom.json", "."])
        .assert()
        .success();
    assert!(dir.path().join("custom.json").is_file());

    let (code, json) = scan_json(dir.path(), &["--baseline", "custom.json"]);
    assert_eq!(code, Some(0));
    assert_eq!(json["stats"]["total"], 0);
}

#[test]
fn missing_explicit_baseline_errors() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--baseline", "nope.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("baseline"));
}

#[test]
fn corrupt_baseline_errors() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();
    write(dir.path().join(".slopguard-baseline.json"), "not json").unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("baseline"));
}

#[test]
fn baseline_found_in_parent_dir() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    create_dir_all(&src).unwrap();
    write(src.join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();
    assert!(dir.path().join(".slopguard-baseline.json").is_file());

    // Run from the subdirectory: the baseline must still be found upward.
    let (code, json) = scan_json(&src, &[]);
    assert_eq!(code, Some(0));
    assert_eq!(json["stats"]["total"], 0);
}

#[test]
fn baseline_exits_zero_with_findings() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("findings to"));
}

#[test]
fn baseline_empty_project() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    let content = read_to_string(dir.path().join(".slopguard-baseline.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["version"], 1);
    assert!(json["findings"].as_array().unwrap().is_empty());

    let (code, _) = scan_json(dir.path(), &[]);
    assert_eq!(code, Some(0));
}

#[test]
fn no_baseline_and_baseline_conflict() {
    let dir = tempdir().unwrap();
    write(dir.path().join("bad.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-baseline", "--baseline", "x.json"])
        .assert()
        .code(2);
}
