mod common;

use std::fs::{create_dir, create_dir_all, read_to_string, write};
use std::path::Path;
use std::process::Command;

use assert_cmd::Command as SlopguardCommand;
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

    // The clone is the only finding, so --fix clears the tree: exit 0. Not a git
    // repository, so --allow-dirty is required to rewrite.
    slopguard()
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--allow-dirty",
            file.to_str().unwrap(),
        ])
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
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--allow-dirty",
            file.to_str().unwrap(),
        ])
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

#[test]
fn fix_refuses_outside_git_repository_without_allow_dirty() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    write(&file, CLONE_SRC).unwrap();

    slopguard()
        .args(["scan", "--no-ai", "--fix", file.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not inside a git repository"))
        .stderr(predicate::str::contains("--allow-dirty"));

    // Nothing was rewritten.
    assert_eq!(read_to_string(&file).unwrap(), CLONE_SRC);
}

#[test]
fn fix_outside_git_with_allow_dirty_rewrites() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    write(&file, CLONE_SRC).unwrap();

    slopguard()
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--allow-dirty",
            file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied 1 fix"));

    assert!(!read_to_string(&file).unwrap().contains(".clone()"));
}

/// All builtin rulesets off, so the only rules are the fixture's own.
const RULESETS_OFF: &str = "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n";

/// A custom (external) rule marking its clone rewrite as autofix-safe.
const TEAM_CLONE_RULE: &str = r#"
id: team-clone
language: rust
severity: warning
category: slop
message: "Unnecessary clone."
rewrite: "$R"
autofix_safe: true
rule:
  pattern: $R.clone()
"#;

/// A slopguard command run from `project` with the user config isolated in
/// `home`, so the developer's own `~/.config/slopguard` cannot leak in.
fn slopguard_in(project: &Path, home: &Path) -> SlopguardCommand {
    let mut cmd = slopguard();
    cmd.current_dir(project)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("SLOPGUARD_CACHE_DIR");
    cmd
}

/// A project loading `TEAM_CLONE_RULE` from an in-repo `custom_dirs`, with
/// `extra` appended to its `slopguard.toml`.
fn external_rule_project(project: &Path, extra: &str) {
    write(project.join("app.rs"), CLONE_SRC).unwrap();
    let rules_dir = project.join("custom-rules");
    create_dir(&rules_dir).unwrap();
    write(rules_dir.join("team-clone.yml"), TEAM_CLONE_RULE).unwrap();
    write(
        project.join("slopguard.toml"),
        format!("{RULESETS_OFF}\n[rules]\ncustom_dirs = [\"./custom-rules\"]\n{extra}"),
    )
    .unwrap();
}

/// Write `content` as the user config under `home`.
fn write_user_config(home: &Path, content: &str) {
    let dir = home.join(".config").join("slopguard");
    create_dir_all(&dir).unwrap();
    write(dir.join("config.toml"), content).unwrap();
}

#[test]
fn fix_ignores_autofix_safe_from_external_rule() {
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    external_rule_project(project.path(), "");

    // The external rule still detects the clone (exit 1), but its rewrite is
    // not trusted without `fix.allow_external`.
    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-ai", "--fix", "--allow-dirty", "."])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Applied 0 fix"));

    assert_eq!(
        read_to_string(project.path().join("app.rs")).unwrap(),
        CLONE_SRC
    );
}

#[test]
fn fix_applies_external_rule_allowed_in_user_config() {
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    external_rule_project(project.path(), "");
    write_user_config(home.path(), "[fix]\nallow_external = [\"team-clone\"]\n");

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-ai", "--fix", "--allow-dirty", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied 1 fix"));

    assert_eq!(
        read_to_string(project.path().join("app.rs")).unwrap(),
        "fn f() -> String {\n    let s = name.to_string();\n    s\n}\n"
    );
}

#[test]
fn fix_repo_config_cannot_allow_external_rule() {
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    external_rule_project(
        project.path(),
        "\n[fix]\nallow_external = [\"team-clone\"]\n",
    );

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-ai", "--fix", "--allow-dirty", "."])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("ignored 'fix.allow_external'"))
        .stdout(predicate::str::contains("Applied 0 fix"));

    assert_eq!(
        read_to_string(project.path().join("app.rs")).unwrap(),
        CLONE_SRC
    );
}

#[test]
fn fix_with_unknown_rule_filter_fails_before_rewriting() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    write(&file, CLONE_SRC).unwrap();

    slopguard()
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--allow-dirty",
            "--rule",
            "no-such-rule",
            file.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"));

    assert_eq!(read_to_string(&file).unwrap(), CLONE_SRC);
}

#[test]
fn dry_run_diff_neutralizes_control_characters() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("app.rs");
    // The ESC sits on a context line of the diff, next to the fixable clone.
    write(
        &file,
        "// \x1b[31mred\x1b[0m\nfn f() -> String {\n    let s = name.to_string().clone();\n    s\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .args([
            "scan",
            "--no-ai",
            "--fix",
            "--dry-run",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        !output.stdout.contains(&0x1b),
        "dry-run diff must not contain a raw ESC byte"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\\x1b[31mred"), "got:\n{stdout}");
}
