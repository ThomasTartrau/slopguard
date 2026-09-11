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
