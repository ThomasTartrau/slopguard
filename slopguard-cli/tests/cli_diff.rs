mod common;

use std::fs::write;
use std::path::Path;
use std::process::Command;

use predicates::prelude::*;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const BAD: &str = "fn main() {\n    foo().unwrap();\n}\n";
const CLEAN: &str = "fn main() {}\n";

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit(dir: &Path, message: &str) {
    git(
        dir,
        &[
            "-c",
            "user.email=t@e.st",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
}

/// A git project on `main` with a committed violation (`old.rs`) and a clean
/// committed file (`good.rs`).
fn git_project() -> TempDir {
    let dir = tempdir().unwrap();
    git(dir.path(), &["-c", "init.defaultBranch=main", "init"]);
    write(dir.path().join("old.rs"), BAD).unwrap();
    write(dir.path().join("good.rs"), CLEAN).unwrap();
    git(dir.path(), &["add", "."]);
    commit(dir.path(), "initial");
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
fn diff_scans_only_changed_files() {
    let dir = git_project();
    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);

    let (_code, json) = scan_json(dir.path(), &["--diff"]);
    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");
    assert!(!findings.is_empty(), "the staged violation should be found");
    for finding in findings {
        let file = finding["file"].as_str().unwrap();
        assert!(
            file.ends_with("new.rs"),
            "only the changed file should be scanned, got {file}"
        );
    }
}

#[test]
fn diff_base_in_json_stats() {
    let dir = git_project();
    git(dir.path(), &["checkout", "-b", "feature"]);
    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);
    commit(dir.path(), "feature");

    let (_code, json) = scan_json(dir.path(), &["--diff", "--base", "main"]);
    assert_eq!(json["stats"]["diff_base"], "main");
}

#[test]
fn diff_files_changed_in_json_stats() {
    let dir = git_project();
    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);

    let (_code, json) = scan_json(dir.path(), &["--diff"]);
    assert_eq!(
        json["stats"]["files_changed"].as_u64(),
        Some(1),
        "one file was staged"
    );
}

#[test]
fn diff_text_header() {
    let dir = git_project();
    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff", "--no-colors"])
        .assert()
        .stdout(
            predicate::str::contains("Scanning ")
                .and(predicate::str::contains("changed files (base: HEAD)")),
        );
}

#[test]
fn diff_outside_git_repo_errors() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), CLEAN).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a git repository"));
}

#[test]
fn diff_deleted_file_not_scanned() {
    let dir = git_project();
    git(dir.path(), &["rm", "old.rs"]);

    let (code, json) = scan_json(dir.path(), &["--diff"]);
    assert_eq!(code, Some(0), "a deleted violation is not a finding");
    assert_eq!(json["stats"]["total"], 0);
}

#[test]
fn diff_renamed_file_scanned() {
    let dir = git_project();
    git(dir.path(), &["mv", "old.rs", "renamed.rs"]);

    let (_code, json) = scan_json(dir.path(), &["--diff"]);
    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");
    assert!(
        findings
            .iter()
            .any(|f| f["file"].as_str().unwrap_or_default().ends_with("renamed.rs")),
        "the renamed file should be scanned under its new name: {findings:?}"
    );
}

#[test]
fn diff_respects_severity_threshold() {
    let dir = git_project();
    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);

    let (code, json) = scan_json(dir.path(), &["--diff", "--severity-threshold", "error"]);
    assert!(
        json["stats"]["errors"].as_u64().unwrap_or(0) > 0,
        "unwrap() in the changed file is an error-severity finding"
    );
    assert_eq!(
        code,
        Some(1),
        "--severity-threshold should behave as in a full scan"
    );
}

#[test]
fn diff_no_changes_exits_zero() {
    let dir = git_project();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scanning 0 changed files"));
}
