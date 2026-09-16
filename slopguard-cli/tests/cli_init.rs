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

#[test]
fn init_strict_enables_opt_in_rules() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "strict"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("slopguard.toml"));

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.contains("enable = ["),
        "strict should emit an enable list, got:\n{content}"
    );
    assert!(
        content.contains("\"pub-fn-needs-tracing\","),
        "strict should enable pub-fn-needs-tracing, got:\n{content}"
    );
    assert!(
        content.contains("\"test-needs-timeout\","),
        "strict should enable test-needs-timeout, got:\n{content}"
    );
    assert!(
        content.contains("disable = []"),
        "strict should disable nothing, got:\n{content}"
    );
}

#[test]
fn init_relaxed_disables_slop() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "relaxed"])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.contains("slop = false"),
        "relaxed should turn the slop ruleset off, got:\n{content}"
    );
    assert!(
        !content.contains("slop = true"),
        "relaxed must not mention slop = true anywhere, got:\n{content}"
    );
}

#[test]
fn init_ai_enables_ai() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "ai"])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.contains("[ai]"),
        "ai preset should emit a live [ai] section, got:\n{content}"
    );
    assert!(
        content.contains("enabled = true"),
        "ai preset should enable the AI pass, got:\n{content}"
    );
    assert!(
        content.contains("claude-haiku-4-5"),
        "ai preset should pin the default model, got:\n{content}"
    );
}

#[test]
fn init_preset_without_value_lists_presets() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("default"))
        .stdout(predicate::str::contains("strict"))
        .stdout(predicate::str::contains("relaxed"))
        .stdout(predicate::str::contains("ai"));

    assert!(
        !dir.path().join("slopguard.toml").exists(),
        "listing presets must not write a config file"
    );
}

#[test]
fn init_bare_preset_does_not_overwrite_with_force() {
    let dir = tempdir().unwrap();
    write(dir.path().join("slopguard.toml"), "# existing").unwrap();

    slopguard()
        .args(["init", "--preset", "--force"])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert_eq!(
        content, "# existing",
        "listing presets must not overwrite an existing config"
    );
}

#[test]
fn init_writes_generated_by_header() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "strict"])
        .current_dir(dir.path())
        .assert()
        .success();

    let content = read_to_string(dir.path().join("slopguard.toml")).unwrap();
    assert!(
        content.starts_with("# Generated by: slopguard init --preset strict"),
        "generated file should open with its provenance header, got:\n{content}"
    );
}

#[test]
fn init_default_preset_matches_bare_init() {
    let explicit = tempdir().unwrap();
    let implicit = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "default"])
        .current_dir(explicit.path())
        .assert()
        .success();
    slopguard()
        .args(["init"])
        .current_dir(implicit.path())
        .assert()
        .success();

    let explicit_content = read_to_string(explicit.path().join("slopguard.toml")).unwrap();
    let implicit_content = read_to_string(implicit.path().join("slopguard.toml")).unwrap();
    assert_eq!(
        explicit_content, implicit_content,
        "--preset default should match a bare init byte for byte"
    );
}

#[test]
fn relaxed_config_silences_slop_findings() {
    let dir = tempdir().unwrap();

    slopguard()
        .args(["init", "--preset", "relaxed"])
        .current_dir(dir.path())
        .assert()
        .success();

    // An em dash comment (slop) plus an unwrap (correctness error).
    let source = format!(
        "fn main() {{\n    // note {} here\n    let x = foo().unwrap();\n}}\n",
        '\u{2014}'
    );
    write(dir.path().join("bad.rs"), source).unwrap();

    let output = slopguard()
        .args([
            "scan",
            ".",
            "--config",
            "slopguard.toml",
            "--format",
            "json",
            "--no-cache",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    assert!(
        findings.iter().any(|f| f["rule_id"] == "no-unwrap-in-prod"),
        "correctness errors should still fire under relaxed, got: {json}"
    );
    assert!(
        findings.iter().all(|f| f["category"] != "slop"),
        "relaxed should report no slop findings, got: {json}"
    );
}
