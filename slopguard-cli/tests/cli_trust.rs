mod common;

use std::fs::{create_dir, create_dir_all, read_to_string, write};
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

/// Write `content` as the user config under the isolated `home`.
// `dirs::config_dir` honors XDG_CONFIG_HOME on Linux only.
#[cfg(target_os = "linux")]
fn write_user_config(home: &Path, content: &str) {
    let global = home.join(".config").join("slopguard");
    create_dir_all(&global).unwrap();
    write(global.join("config.toml"), content).unwrap();
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
            "{RULESETS_OFF}\n[rules]\nenable = [\"ai-safety-demo\"]\ncustom_dirs = [\"./custom-rules\"]\n\n\
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

// `dirs::config_dir` honors XDG_CONFIG_HOME on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn repo_config_ai_keys_are_ignored_with_a_warning() {
    // WHY: the scanned repo is untrusted input. Its `[ai]` table must not turn
    // the AI pass on (nor reach for a key): it is dropped with a warning, so
    // the AI rule is skipped as "AI is disabled", not "missing API key".
    // The user config lets the in-repo (external) AI rule reach the AI phase.
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    ai_project(project.path());
    write_user_config(home.path(), "[ai]\nallow_external_rules = true\n");

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::contains(
            "warning: ignored 'ai.api_key', 'ai.enabled', 'ai.provider', 'ai.vendor' in slopguard.toml",
        ))
        .stderr(predicate::str::contains("AI is disabled"))
        .stderr(predicate::str::contains("external AI rules skipped").not())
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

#[test]
fn external_ai_rule_is_skipped_by_default() {
    // WHY: an in-repo `ai_check` rule is external: its prompt was never
    // reviewed by the user, so it must not send code to a provider unless the
    // user config sets `ai.allow_external_rules`.
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    ai_project(project.path());

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::contains(
            "warning: 1 external AI rules skipped (set ai.allow_external_rules = true in the user config to allow them)",
        ))
        .stderr(predicate::str::contains("AI is disabled").not());
}

#[test]
fn repo_config_cannot_allow_external_ai_rules() {
    // `allow_external_rules` lives under the reserved `[ai]` table: the repo
    // cannot grant its own rules access to the provider.
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    ai_project(project.path());
    let config_path = project.path().join("slopguard.toml");
    let mut config = read_to_string(&config_path).unwrap();
    config.push_str("allow_external_rules = true\n");
    write(&config_path, config).unwrap();

    slopguard_in(project.path(), home.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .assert()
        .success()
        .stderr(predicate::str::contains("'ai.allow_external_rules'"))
        .stderr(predicate::str::contains("1 external AI rules skipped"));
}

#[test]
fn default_scan_cache_lives_outside_the_project() {
    // WHY: a cache inside the scanned repo could be committed with forged
    // entries that silence findings. The default cache is per-user.
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    let cache_home = home.path().join("cache-home");
    write(project.path().join("main.rs"), "fn main() {}\n").unwrap();
    write(project.path().join("slopguard.toml"), RULESETS_OFF).unwrap();

    slopguard_in(project.path(), home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .args(["scan", "--no-colors", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"));

    assert!(
        !project.path().join(".slopguard-cache").exists(),
        "no cache directory is created in the scanned project"
    );
    #[cfg(target_os = "linux")]
    {
        use std::fs::read_dir;

        let user_cache = cache_home.join("slopguard");
        assert!(user_cache.join("cache.key").is_file());
        let projects: Vec<_> = read_dir(user_cache.join("projects"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(projects.len(), 1, "got: {projects:?}");
        assert!(projects[0].join("rules.hash").is_file());
    }
}
