mod common;

use std::fs::write;

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

#[test]
fn list_shows_active_rules() {
    let output = slopguard().args(["list"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("no-unwrap-in-prod"),
        "should list no-unwrap-in-prod"
    );
    assert!(stdout.contains("rust"), "should show language column");
    assert!(
        stdout.contains("error") || stdout.contains("warning"),
        "should show severity column"
    );
    assert!(
        stdout.contains("correctness") || stdout.contains("security") || stdout.contains("slop"),
        "should show category column"
    );
}

#[test]
fn list_all_shows_disabled_rules() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, "[rules]\ndisable = [\"no-unwrap-in-prod\"]\n").unwrap();

    let output = slopguard()
        .args(["list", "--all", "--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("no-unwrap-in-prod"),
        "--all should still show disabled rules"
    );
    assert!(
        stdout.contains("disabled"),
        "disabled rules should be marked as disabled"
    );
}

#[test]
fn list_category_filter() {
    slopguard()
        .args(["list", "--category", "security"])
        .assert()
        .success()
        .stdout(predicate::str::contains("security"))
        .stdout(predicate::str::contains("no-debug-on-secrets"));

    let output = slopguard()
        .args(["list", "--category", "security"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("no-unwrap-in-prod"),
        "should not show correctness rules when filtering by security"
    );
}

#[test]
fn list_language_filter() {
    slopguard()
        .args(["list", "--language", "typescript"])
        .assert()
        .success()
        .stdout(predicate::str::contains("typescript"));

    let output = slopguard()
        .args(["list", "--language", "typescript"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("no-unwrap-in-prod"),
        "should not show Rust rules when filtering by TypeScript"
    );
    assert!(
        stdout.contains("no-any-typescript"),
        "should show TypeScript rules"
    );
}

#[test]
fn list_json_output_is_an_array() {
    let output = slopguard()
        .args(["list", "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let entries = json.as_array().expect("list JSON must be an array");
    assert!(!entries.is_empty(), "there should be active rules");
    for entry in entries {
        assert!(entry["id"].is_string(), "missing id in {entry}");
        assert!(entry["language"].is_string(), "missing language in {entry}");
        assert!(entry["severity"].is_string(), "missing severity in {entry}");
        assert!(entry["category"].is_string(), "missing category in {entry}");
        assert!(entry["type"].is_string(), "missing type in {entry}");
        assert!(entry["status"].is_string(), "missing status in {entry}");
    }
}

#[test]
fn list_json_contains_metric_rules() {
    let output = slopguard()
        .args(["list", "--format", "json"])
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = json.as_array().unwrap();

    assert!(
        entries.iter().any(|e| e["type"] == "metric"),
        "at least one rule should be a metric rule"
    );
    let max_file_lines = entries
        .iter()
        .find(|e| e["id"] == "max-file-lines")
        .expect("max-file-lines should be listed");
    assert_eq!(max_file_lines["type"], "metric");
}

#[test]
fn list_text_shows_metric_type() {
    let output = slopguard().args(["list"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("max-file-lines"),
        "should list max-file-lines, got:\n{stdout}"
    );
    assert!(
        stdout.contains("metric"),
        "should show the metric type column value, got:\n{stdout}"
    );
}

#[test]
fn list_rejects_sarif_format() {
    slopguard()
        .args(["list", "--format", "sarif"])
        .assert()
        .failure();
}
