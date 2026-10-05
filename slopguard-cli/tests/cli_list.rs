mod common;

use std::fs::{create_dir, write};
use std::path::{Path, PathBuf};

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
fn list_shows_resolution_rule() {
    let text = slopguard().args(["list"]).output().unwrap();
    assert!(text.status.success());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(
        stdout.contains("unresolved-import"),
        "should list unresolved-import, got:\n{stdout}"
    );
    assert!(
        stdout.contains("resolution"),
        "should show the resolution type column value, got:\n{stdout}"
    );

    let json_out = slopguard()
        .args(["list", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    let entries = json.as_array().unwrap();
    let resolution_count = entries.iter().filter(|e| e["type"] == "resolution").count();
    assert!(
        resolution_count > 0,
        "at least one rule should be a resolution rule, got {resolution_count}"
    );
    let entry = entries
        .iter()
        .find(|e| e["id"] == "unresolved-import")
        .expect("unresolved-import should be listed");
    assert_eq!(entry["type"], "resolution");
}

#[test]
fn list_rejects_sarif_format() {
    slopguard()
        .args(["list", "--format", "sarif"])
        .assert()
        .failure();
}

#[test]
fn list_shows_cross_file_rule() {
    let text = slopguard().args(["list"]).output().unwrap();
    assert!(text.status.success());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(
        stdout.contains("no-single-impl-trait"),
        "should list no-single-impl-trait, got:\n{stdout}"
    );
    assert!(
        stdout.contains("cross-file"),
        "should show the cross-file type column value, got:\n{stdout}"
    );

    let json_out = slopguard()
        .args(["list", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    let entries = json.as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["id"] == "no-single-impl-trait")
        .expect("no-single-impl-trait should be listed");
    assert_eq!(entry["type"], "cross-file");
}

/// A config loading two external rules from a local `custom_dirs`: `team-on`
/// (force-enabled) and `team-off` (`enabled: false`). Returns the config path.
fn external_rules_config(dir: &Path) -> PathBuf {
    let rules_dir = dir.join("custom-rules");
    create_dir(&rules_dir).unwrap();
    for (id, enabled) in [("team-on", "true"), ("team-off", "false")] {
        write(
            rules_dir.join(format!("{id}.yml")),
            format!(
                "id: {id}\nlanguage: rust\nseverity: warning\ncategory: slop\n\
                 message: \"Demo.\"\nenabled: {enabled}\nrule:\n  pattern: $R.clone()\n"
            ),
        )
        .unwrap();
    }
    let config_path = dir.join("slopguard.toml");
    let custom_dir = rules_dir.to_str().unwrap().replace('\\', "/");
    write(
        &config_path,
        format!("[rules]\nenable = [\"team-on\"]\ncustom_dirs = [\"{custom_dir}\"]\n"),
    )
    .unwrap();
    config_path
}

#[test]
fn list_shows_external_rule_with_source_and_status() {
    let dir = tempdir().unwrap();
    let config_path = external_rules_config(dir.path());

    let output = slopguard()
        .args([
            "list",
            "--format",
            "json",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = json.as_array().unwrap();

    let on = entries
        .iter()
        .find(|e| e["id"] == "team-on")
        .expect("team-on should be listed");
    assert_eq!(on["status"], "enabled");
    assert!(on["source"].as_str().unwrap().contains("custom-rules"));

    let builtin = entries
        .iter()
        .find(|e| e["id"] == "no-unwrap-in-prod")
        .unwrap();
    assert_eq!(builtin["source"], "builtin");

    let text = slopguard()
        .args(["list", "--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(
        stdout.contains("source"),
        "missing source header:\n{stdout}"
    );
    let line = stdout.lines().find(|l| l.starts_with("team-on")).unwrap();
    assert!(line.contains("enabled") && line.contains("custom-rules"));
}

#[test]
fn list_all_shows_disabled_external_rule_with_source() {
    let dir = tempdir().unwrap();
    let config_path = external_rules_config(dir.path());

    let output = slopguard()
        .args([
            "list",
            "--all",
            "--format",
            "json",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let off = json
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "team-off")
        .expect("--all should list the external rule disabled in its YAML");

    assert_eq!(off["status"], "disabled");
    assert!(off["source"].as_str().unwrap().contains("custom-rules"));
}
