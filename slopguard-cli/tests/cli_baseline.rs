mod common;

use std::fs::write;

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

#[test]
fn baseline_writes_findings_file() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote"));

    let baseline_path = dir.path().join(".slopguard-baseline.json");
    assert!(baseline_path.exists());

    let content = std::fs::read_to_string(&baseline_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");
    assert!(
        !findings.is_empty(),
        "baseline should capture at least one finding"
    );
}

#[test]
fn scan_after_baseline_filters_known_findings() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    let output = slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    assert_eq!(json["summary"]["total"].as_u64(), Some(0));
    assert!(json["summary"]["baseline_filtered"].as_u64().unwrap() > 0);
}

#[test]
fn scan_no_baseline_ignores_existing_baseline() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    let output = slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-baseline", "--format", "json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    assert!(json["summary"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn scan_baseline_flag_points_to_custom_path() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let baseline_dir = tempdir().unwrap();
    let baseline_path = baseline_dir.path().join("custom-baseline.json");

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    std::fs::rename(dir.path().join(".slopguard-baseline.json"), &baseline_path).unwrap();

    let output = slopguard()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    assert_eq!(json["summary"]["total"].as_u64(), Some(0));
}

#[test]
fn text_output_shows_baseline_filtered_line() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("findings filtered by baseline"));
}

#[test]
fn text_output_hides_baseline_filtered_line_when_nothing_filtered() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--no-colors"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("filtered by baseline"),
        "should not mention baseline filtering when there is no baseline, got: {stdout}"
    );
}
