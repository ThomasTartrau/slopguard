mod common;

use std::fs::{create_dir_all, write};
use std::path::Path;
use std::process::Command as StdCommand;

use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const IMPORTED_RULE: &str = r#"
id: imported-demo-rule
language: rust
severity: warning
message: "imported rule fired"
rule:
  pattern: banned_call()
tests:
  should_match:
    - "banned_call();"
  should_not_match:
    - "allowed_call();"
"#;

/// Overrides the protocols git may use for sources (https and ssh only by
/// default), so the tests can serve rules from a `file://` remote.
const ALLOW_PROTOCOL_ENV: &str = "SLOPGUARD_GIT_ALLOW_PROTOCOL";
const TEST_PROTOCOLS: &str = "file:https:ssh";

fn git(dir: &Path, args: &[&str]) {
    let status = StdCommand::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {args:?} failed");
}

/// Create a git repository holding one rule YAML and return a `file://` URL.
fn make_remote(dir: &Path) {
    git(dir, &["init", "--quiet"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
    write(dir.join("imported-demo-rule.yml"), IMPORTED_RULE).unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "--quiet", "-m", "rules"]);
}

/// A project with a `[[rules.sources]]` git source, an isolated cache dir, and
/// a clean source file. Returns (project, cache, remote) kept alive by caller.
fn source_project() -> (TempDir, TempDir, TempDir) {
    let remote = tempdir().unwrap();
    make_remote(remote.path());
    let url = format!("file://{}", remote.path().display());

    let project = tempdir().unwrap();
    write(
        project.path().join("slopguard.toml"),
        format!("[[rules.sources]]\ngit = \"{url}\"\n"),
    )
    .unwrap();
    create_dir_all(project.path().join("src")).unwrap();
    write(
        project.path().join("src/main.rs"),
        "fn main() {\n    allowed_call();\n}\n",
    )
    .unwrap();

    let cache = tempdir().unwrap();
    (project, cache, remote)
}

#[test]
fn list_json_exposes_imported_rule_provenance() {
    let (project, cache, _remote) = source_project();

    let output = slopguard()
        .args(["list", "--format", "json"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = json.as_array().expect("list json is an array");

    let non_builtin: Vec<&Value> = entries
        .iter()
        .filter(|e| e["source"].as_str() != Some("builtin"))
        .collect();
    assert!(
        !non_builtin.is_empty(),
        "expected at least one non-builtin rule, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let imported = entries
        .iter()
        .find(|e| e["id"].as_str() == Some("imported-demo-rule"))
        .expect("imported rule should appear in list");
    assert!(
        imported["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("file://")),
        "imported rule source should be its git url, got: {:?}",
        imported["source"]
    );
}

#[test]
fn test_command_validates_imported_rules() {
    let (project, cache, _remote) = source_project();

    let output = slopguard()
        .args(["test"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "test should pass; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("imported-demo-rule"),
        "test output should mention the imported rule; got:\n{stdout}"
    );
}

#[test]
fn scan_offline_reuses_cache_without_network() {
    let (project, cache, remote) = source_project();

    // First run online populates the cache from the remote.
    let warm = slopguard()
        .args(["list"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();
    assert!(warm.status.success(), "warm-up list failed");

    // Drop the remote so a fetch would fail: offline must not touch it.
    drop(remote);

    let output = slopguard()
        .args(["scan", ".", "--offline"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The clean file matches no rule, so a successful offline scan exits 0.
    assert!(
        output.status.success(),
        "offline scan should succeed from cache; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("offline:") && !stderr.to_lowercase().contains("network"),
        "offline scan must not report a network error; stderr:\n{stderr}"
    );
}

#[test]
fn floating_ref_prints_unpinned_warning() {
    let (project, cache, _remote) = source_project();

    let output = slopguard()
        .args(["list"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "list failed; stderr:\n{stderr}");
    assert!(
        stderr.contains("warning: unpinned rule source 'file://"),
        "a source without a sha ref must be reported as unpinned; stderr:\n{stderr}"
    );
}

#[test]
fn unreachable_remote_on_refresh_fails_the_scan() {
    let (project, cache, remote) = source_project();

    let warm = slopguard()
        .args(["list"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();
    assert!(warm.status.success(), "warm-up list failed");

    // The remote disappears: an online scan must not silently keep the stale
    // cached rules.
    drop(remote);

    let output = slopguard()
        .args(["scan", "."])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env(ALLOW_PROTOCOL_ENV, TEST_PROTOCOLS)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failed refresh must fail the scan; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("git fetch HEAD failed for source"),
        "the error should name the failed fetch; stderr:\n{stderr}"
    );
}

#[test]
fn file_protocol_source_is_refused_by_default() {
    let (project, cache, _remote) = source_project();

    let output = slopguard()
        .args(["list"])
        .current_dir(project.path())
        .env("SLOPGUARD_SOURCES_CACHE", cache.path())
        .env_remove(ALLOW_PROTOCOL_ENV)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a file:// source must be refused under the default https:ssh; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("git fetch HEAD failed for source"),
        "the refusal should come from the fetch; stderr:\n{stderr}"
    );
}
