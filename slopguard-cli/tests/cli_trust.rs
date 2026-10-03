mod common;

use std::fs::{create_dir, create_dir_all, write};
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

/// All builtin rulesets off, so the only rules are the fixture's own.
const RULESETS_OFF: &str = "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n";

/// A slopguard command run from `project` with the user config isolated in
/// `home`, so the developer's own `~/.config/slopguard` cannot leak in.
fn slopguard_in(project: &Path, home: &Path) -> Command {
    let mut cmd = slopguard();
    cmd.current_dir(project)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("SLOPGUARD_CACHE_DIR")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("TYPESAFE_API_KEY")
        .env_remove("OPENROUTER_API_KEY");
    cmd
}

/// A project whose `slopguard.toml` enables AI and loads an in-repo custom
/// `ai_check` rule matching the source file.
fn ai_project(project: &Path) {
    write(
        project.join("main.rs"),
        "fn main() {\n    // SAFETY: trust me\n    let _x = 1;\n}\n",
    )
    .unwrap();
    let rules_dir = project.join("custom-rules");
    create_dir(&rules_dir).unwrap();
    write(
        rules_dir.join("ai.yml"),
        r#"
id: ai-safety-demo
language: rust
severity: warning
category: slop
message: "AI: SAFETY comment may be meaningless"
rule:
  kind: line_comment
  regex: 'SAFETY'
ai_check:
  prompt: "Is this SAFETY comment meaningful?\n{{code}}"
"#,
    )
    .unwrap();
    write(
        project.join("slopguard.toml"),
        format!(
            "{RULESETS_OFF}\n[rules]\ncustom_dirs = [\"./custom-rules\"]\n\n\
             [ai]\nenabled = true\nprovider = \"api\"\nvendor = \"anthropic\"\n\
             api_key = \"repo-secret-key\"\n"
        ),
    )
    .unwrap();
}

/// A project nested in `parent` whose `slopguard.toml` loads rules from a
/// sibling directory, outside the repository.
fn outside_dir_project(parent: &Path) -> PathBuf {
    let project = parent.join("proj");
    create_dir_all(&project).unwrap();
    create_dir_all(parent.join("outside")).unwrap();
    write(project.join("main.rs"), "fn main() {}\n").unwrap();
    write(
        project.join("slopguard.toml"),
        format!("{RULESETS_OFF}\n[rules]\ncustom_dirs = [\"../outside\"]\n"),
    )
    .unwrap();
    project
}

#[test]
fn repo_config_ai_keys_are_ignored_with_a_warning() {
    // WHY: the scanned repo is untrusted input. Its `[ai]` table must not turn
    // the AI pass on (nor reach for a key): it is dropped with a warning, so
    // the AI rule is skipped as "AI is disabled", not "missing API key".
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    ai_project(project.path());

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::contains("ignored 'ai.enabled'"))
        .stderr(predicate::str::contains("ignored 'ai.api_key'"))
        .stderr(predicate::str::contains("AI is disabled"))
        .stderr(predicate::str::contains("ANTHROPIC_API_KEY").not())
        // The secret value is never echoed.
        .stderr(predicate::str::contains("repo-secret-key").not());
}

#[test]
fn trust_repo_config_honors_repo_ai_keys() {
    // With the flag, the repo's `[ai]` is kept: no key is reported as ignored.
    // WHY --no-ai: the trusted config carries a fake key, and the test must
    // never reach the provider over the network.
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    ai_project(project.path());

    slopguard_in(project.path(), home.path())
        .args([
            "scan",
            "--no-ai",
            "--no-cache",
            "--no-colors",
            "--trust-repo-config",
            ".",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("ignored").not());
}

#[test]
fn repo_custom_dir_outside_repo_fails_with_config_error() {
    let parent = tempdir().unwrap();
    let home = tempdir().unwrap();
    let project = outside_dir_project(parent.path());

    slopguard_in(&project, home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("rules.custom_dirs"))
        .stderr(predicate::str::contains("outside the repository root"));
}

#[test]
fn trust_repo_config_accepts_custom_dir_outside_repo() {
    let parent = tempdir().unwrap();
    let home = tempdir().unwrap();
    let project = outside_dir_project(parent.path());

    slopguard_in(&project, home.path())
        .args([
            "scan",
            "--no-cache",
            "--no-colors",
            "--trust-repo-config",
            ".",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("outside the repository root").not())
        .stderr(predicate::str::contains("ignored").not());
}

// `dirs::config_dir` honors XDG_CONFIG_HOME on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn global_config_zero_concurrency_fails_with_config_error() {
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    write(project.path().join("main.rs"), "fn main() {}\n").unwrap();
    let global = home.path().join(".config").join("slopguard");
    create_dir_all(&global).unwrap();
    write(global.join("config.toml"), "[ai]\nconcurrency = 0\n").unwrap();

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "[ai].concurrency must be between 1 and 64, got 0",
        ));
}
