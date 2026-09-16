mod common;

use std::fs::write;
use std::path::Path;
use std::process::{Command, Output};

use predicates::prelude::*;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const BAD: &str = "fn main() {\n    foo().unwrap();\n}\n";

fn git(dir: &Path, args: &[&str]) -> Output {
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
    output
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

fn commit(dir: &Path, msg: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", msg]);
}

/// A repo whose committed `old.rs` already violates a rule, plus an
/// uncommitted `new.rs` that also does.
fn repo_with_changes() -> TempDir {
    let dir = tempdir().unwrap();
    init_repo(dir.path());
    write(dir.path().join("old.rs"), BAD).unwrap();
    commit(dir.path(), "old");

    write(dir.path().join("new.rs"), BAD).unwrap();
    git(dir.path(), &["add", "new.rs"]);
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

fn finding_files(json: &Value) -> Vec<String> {
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .map(|f| f["file"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn diff_json_reports_base() {
    let dir = repo_with_changes();
    commit(dir.path(), "new");
    git(dir.path(), &["checkout", "-q", "-b", "feature"]);
    write(dir.path().join("feature.rs"), BAD).unwrap();
    commit(dir.path(), "feature");

    let (_code, json) = scan_json(dir.path(), &["--diff", "--base", "main"]);
    assert_eq!(json["stats"]["diff_base"], "main");
}

#[test]
fn diff_without_base_defaults_to_head() {
    let dir = repo_with_changes();

    let (_code, json) = scan_json(dir.path(), &["--diff"]);
    assert_eq!(json["stats"]["diff_base"], "HEAD");
    assert!(
        json["stats"]["files_changed"].as_u64().is_some(),
        "files_changed should be reported in diff mode"
    );
}

#[test]
fn diff_only_scans_changed_files() {
    let dir = repo_with_changes();

    let (_code, json) = scan_json(dir.path(), &["--diff"]);
    let files = finding_files(&json);
    assert!(!files.is_empty(), "the changed file should be scanned");
    for file in &files {
        assert!(file.ends_with("new.rs"), "unexpected file: {file}");
    }
}

#[test]
fn full_scan_still_reports_everything() {
    let dir = repo_with_changes();

    let (_code, json) = scan_json(dir.path(), &[]);
    let files = finding_files(&json);
    assert!(
        files.iter().any(|f| f.ends_with("old.rs")),
        "full scan should report old.rs: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("new.rs")),
        "full scan should report new.rs: {files:?}"
    );
    assert!(
        json["stats"]["diff_base"].is_null(),
        "a full scan must not emit diff_base"
    );
    assert!(
        json["stats"]["files_changed"].is_null(),
        "a full scan must not emit files_changed"
    );
}

#[test]
fn diff_text_header() {
    let dir = repo_with_changes();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff", "--no-colors"])
        .assert()
        .stdout(predicate::str::contains(
            "Scanning 1 changed files (base: HEAD)",
        ));
}

#[test]
fn diff_outside_git_repo_errors() {
    let dir = tempdir().unwrap();
    write(dir.path().join("a.rs"), BAD).unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not inside a git repository"));
}

#[test]
fn diff_unknown_base_errors() {
    let dir = repo_with_changes();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff", "--base", "nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown git ref 'nope'"));
}

#[test]
fn base_without_diff_is_rejected() {
    let dir = repo_with_changes();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--base", "main"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--diff"));
}

#[test]
fn diff_with_no_changes_exits_zero() {
    let dir = tempdir().unwrap();
    init_repo(dir.path());
    write(dir.path().join("bad.rs"), BAD).unwrap();
    commit(dir.path(), "init");

    let (code, json) = scan_json(dir.path(), &["--diff"]);
    assert_eq!(code, Some(0), "a clean working tree has nothing to report");
    assert_eq!(json["stats"]["files_changed"], 0);

    slopguard()
        .current_dir(dir.path())
        .args(["scan", ".", "--diff", "--no-colors"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scanning 0 changed files"));
}

#[test]
fn diff_respects_severity_threshold() {
    let dir = tempdir().unwrap();
    init_repo(dir.path());
    write(dir.path().join("placeholder.rs"), "fn main() {}\n").unwrap();
    commit(dir.path(), "init");

    // A warning-only change: with an error threshold the scan still exits 0.
    let warn = dir.path().join("warn.rs");
    write(&warn, "fn main() {\n    let x = 1;\n}\n").unwrap();
    git(dir.path(), &["add", "warn.rs"]);

    slopguard()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--diff",
            "--severity-threshold",
            "error",
            "--no-colors",
        ])
        .assert()
        .success();
}

#[test]
fn diff_deleted_file_is_not_scanned() {
    let dir = tempdir().unwrap();
    init_repo(dir.path());
    write(dir.path().join("gone.rs"), BAD).unwrap();
    commit(dir.path(), "init");
    git(dir.path(), &["rm", "-q", "gone.rs"]);

    let (code, json) = scan_json(dir.path(), &["--diff"]);
    assert_eq!(code, Some(0), "a deleted file has nothing left to scan");
    let files = finding_files(&json);
    assert!(
        !files.iter().any(|f| f.ends_with("gone.rs")),
        "deleted file should not be scanned: {files:?}"
    );
}

#[test]
fn diff_combines_with_no_ai_and_no_cache() {
    let dir = repo_with_changes();

    let (_code, json) = scan_json(dir.path(), &["--diff", "--no-ai", "--no-cache"]);
    assert_eq!(json["stats"]["diff_base"], "HEAD");
}
