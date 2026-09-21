mod common;

use std::fs::{read_to_string, write};
use std::path::Path;
use std::process::Command;

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

/// Initialise a git repo and commit `CLONE_SRC` as `app.rs`, then dirty it.
fn dirty_repo_with_clone(dir: &Path) {
    let git = |args: &[&str]| {
        let ok = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "t@example.com"]);
    git(&["config", "user.name", "T"]);
    git(&["config", "commit.gpgsign", "false"]);
    write(dir.join("app.rs"), "fn f() {}\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]);
    // Uncommitted change carrying the fixable clone.
    write(dir.join("app.rs"), CLONE_SRC).unwrap();
}

/// A production file carrying one autofixable unnecessary clone.
const CLONE_SRC: &str = "fn f() -> String {\n    let s = name.to_string().clone();\n    s\n}\n";

#[test]
fn help_exposes_fix_and_dry_run() {
    slopguard()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--fix"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn dry_run_prints_diff_and_leaves_file_untouched() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    write(&file, CLONE_SRC).unwrap();

    slopguard()
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--dry-run",
            file.to_str().unwrap(),
        ])
        .assert()
        .success()
        // the removed `.clone()` shows up on a deletion line of the diff
        .stdout(predicate::str::contains("name.to_string().clone()"))
        .stdout(predicate::str::contains("Would apply"));

    // The file on disk is unchanged by a dry run.
    assert_eq!(read_to_string(&file).unwrap(), CLONE_SRC);
}

#[test]
fn fix_rewrites_file_and_clears_the_finding() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    write(&file, CLONE_SRC).unwrap();

    // The clone is the only finding, so --fix clears the tree: exit 0.
    slopguard()
        .args(["scan", "--no-ai", "--fix", file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied 1 fix"));

    let fixed = read_to_string(&file).unwrap();
    assert_eq!(
        fixed, "fn f() -> String {\n    let s = name.to_string();\n    s\n}\n",
        "the .clone() should be gone"
    );

    // A fresh scan finds nothing left.
    let output = slopguard()
        .args([
            "scan",
            "--no-ai",
            "--format",
            "json",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["findings"].as_array().unwrap().len(),
        0,
        "no finding should remain after --fix"
    );
}

#[test]
fn fix_exits_one_when_unfixable_findings_remain() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    // One autofixable clone plus one finding no rule can rewrite (`.unwrap()`).
    write(
        &file,
        "fn f() -> String {\n    let s = name.to_string().clone();\n    other().unwrap();\n    s\n}\n",
    )
    .unwrap();

    slopguard()
        .args(["scan", "--no-ai", "--fix", file.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Applied 1 fix"))
        .stdout(predicate::str::contains("finding(s) remaining"));

    // The clone was still rewritten even though other findings remain.
    let fixed = read_to_string(&file).unwrap();
    assert!(!fixed.contains(".clone()"), "the clone should be rewritten");
    assert!(
        fixed.contains("other().unwrap()"),
        "the unwrap is untouched"
    );
}

#[test]
fn fix_refuses_dirty_tree_without_allow_dirty() {
    let dir = tempdir().unwrap();
    dirty_repo_with_clone(dir.path());

    slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-ai", "--fix", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("uncommitted change"));

    // The file was not rewritten.
    assert_eq!(
        read_to_string(dir.path().join("app.rs")).unwrap(),
        CLONE_SRC
    );
}

#[test]
fn fix_allow_dirty_rewrites_a_dirty_tree() {
    let dir = tempdir().unwrap();
    dirty_repo_with_clone(dir.path());

    slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-ai", "--fix", "--allow-dirty", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied 1 fix"));

    assert!(!read_to_string(dir.path().join("app.rs"))
        .unwrap()
        .contains(".clone()"));
}

#[test]
fn fix_accepts_a_bare_filename_in_a_clean_repo() {
    // A bare filename has an empty parent; the dirty-tree probe must still find
    // the repo (regression: `git -C ""` failed to spawn).
    let dir = tempdir().unwrap();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "t@example.com"]);
    git(&["config", "user.name", "T"]);
    git(&["config", "commit.gpgsign", "false"]);
    write(dir.path().join("app.rs"), CLONE_SRC).unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]); // clean tree, clone committed

    slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-ai", "--fix", "app.rs"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied 1 fix"));

    assert!(!read_to_string(dir.path().join("app.rs"))
        .unwrap()
        .contains(".clone()"));
}

#[test]
fn dry_run_previews_dirty_tree_without_allow_dirty() {
    let dir = tempdir().unwrap();
    dirty_repo_with_clone(dir.path());

    // --dry-run is never blocked by the dirty guard.
    slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-ai", "--fix", "--dry-run", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would apply"));

    assert_eq!(
        read_to_string(dir.path().join("app.rs")).unwrap(),
        CLONE_SRC
    );
}
