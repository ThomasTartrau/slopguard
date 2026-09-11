mod common;

use std::fs::{read_to_string, write};

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

#[test]
fn init_creates_default_config() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("slopguard.toml"));

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.contains("[rulesets]"),
        "should contain [rulesets] section"
    );
    assert!(
        content.contains("slop = true"),
        "should enable slop by default"
    );
    assert!(
        content.contains("security = true"),
        "should enable security by default"
    );
    assert!(
        content.contains("correctness = true"),
        "should enable correctness by default"
    );
    assert!(
        content.contains("# ai.enabled = false") || content.contains("# enabled = false"),
        "ai.enabled should be commented out, got:\n{content}"
    );
}

#[test]
fn init_fails_if_config_exists() {
    let dir = tempdir().unwrap();
    write(dir.path().join("slopguard.toml"), "# existing").unwrap();

    slopguard()
        .args(["init"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_force_overwrites_existing() {
    let dir = tempdir().unwrap();
    write(dir.path().join("slopguard.toml"), "# old content").unwrap();

    slopguard()
        .args(["init", "--force"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("slopguard.toml"));

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.contains("[rulesets]"),
        "should contain default config after --force"
    );
    assert!(
        !content.contains("# old content"),
        "old content should be replaced"
    );
}
