use std::fs::{create_dir_all, write};
use std::path::Path;
use std::process::Command;

use tempfile::tempdir;

use super::*;
use crate::config::RuleSource;

fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git should run")
}

/// Create a git repository at `dir` with `files` (relative path -> contents),
/// committed on the default branch. Returns a `file://` URL usable as a remote
/// that supports shallow fetch.
fn make_remote(dir: &Path, files: &[(&str, &str)]) -> String {
    git(dir, &["init", "--quiet"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
    for (rel, content) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            create_dir_all(parent).unwrap();
        }
        write(&path, content).unwrap();
    }
    git(dir, &["add", "."]);
    git(dir, &["commit", "--quiet", "-m", "rules"]);
    format!("file://{}", dir.display())
}

const A_RULE: &str = r#"
id: source-rule
language: rust
severity: warning
message: "from a source"
rule:
  pattern: foo()
tests:
  should_match:
    - "foo();"
  should_not_match:
    - "bar();"
"#;

#[test]
fn resolves_a_git_source_and_exposes_its_rules() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);

    let cache = tempdir().unwrap();
    let opts = SourceOptions {
        cache_root: cache.path().to_path_buf(),
        offline: false,
    };
    let source = RuleSource {
        git: Some(url.clone()),
        git_ref: None,
        path: None,
    };

    let resolved = resolve_sources(&[source], &opts).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].origin, RuleOrigin::Git { url });
    assert!(
        resolved[0].dir.join("source-rule.yml").is_file(),
        "the fetched rule file should be present in the cache"
    );
}

#[test]
fn git_source_subpath_narrows_to_a_subdirectory() {
    let remote = tempdir().unwrap();
    let url = make_remote(
        remote.path(),
        &[
            ("rules/source-rule.yml", A_RULE),
            ("README.md", "# not a rule"),
        ],
    );

    let cache = tempdir().unwrap();
    let opts = SourceOptions {
        cache_root: cache.path().to_path_buf(),
        offline: false,
    };
    let source = RuleSource {
        git: Some(url),
        git_ref: None,
        path: Some(PathBuf::from("rules")),
    };

    let resolved = resolve_sources(&[source], &opts).unwrap();
    assert!(resolved[0].dir.ends_with("rules"));
    assert!(resolved[0].dir.join("source-rule.yml").is_file());
}

#[test]
fn cache_is_reused_offline_after_a_first_fetch() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);

    let cache = tempdir().unwrap();
    let source = RuleSource {
        git: Some(url.clone()),
        git_ref: None,
        path: None,
    };

    // First run online populates the cache.
    let online = SourceOptions {
        cache_root: cache.path().to_path_buf(),
        offline: false,
    };
    resolve_sources(std::slice::from_ref(&source), &online).unwrap();

    // Second run offline must succeed from the cache alone, no network.
    let offline = SourceOptions {
        cache_root: cache.path().to_path_buf(),
        offline: true,
    };
    let resolved = resolve_sources(&[source], &offline).unwrap();
    assert!(resolved[0].dir.join("source-rule.yml").is_file());
}

#[test]
fn offline_without_cache_is_an_error() {
    let cache = tempdir().unwrap();
    let opts = SourceOptions {
        cache_root: cache.path().to_path_buf(),
        offline: true,
    };
    let source = RuleSource {
        git: Some("file:///nonexistent/repo.git".to_string()),
        git_ref: None,
        path: None,
    };

    let err = resolve_sources(&[source], &opts).unwrap_err();
    assert!(
        matches!(err, SourceError::OfflineNoCache { .. }),
        "expected OfflineNoCache, got: {err:?}"
    );
}

#[test]
fn local_source_resolves_to_its_path_with_local_origin() {
    let dir = tempdir().unwrap();
    write(dir.path().join("source-rule.yml"), A_RULE).unwrap();

    let source = RuleSource {
        git: None,
        git_ref: None,
        path: Some(dir.path().to_path_buf()),
    };
    let resolved = resolve_sources(&[source], &SourceOptions::default()).unwrap();
    assert_eq!(resolved[0].dir, dir.path());
    assert_eq!(
        resolved[0].origin,
        RuleOrigin::Local {
            path: dir.path().to_path_buf()
        }
    );
}

#[test]
fn missing_local_source_is_an_error() {
    let source = RuleSource {
        git: None,
        git_ref: None,
        path: Some(PathBuf::from("/nonexistent/rules-dir")),
    };
    let err = resolve_sources(&[source], &SourceOptions::default()).unwrap_err();
    assert!(
        matches!(err, SourceError::LocalMissing { .. }),
        "expected LocalMissing, got: {err:?}"
    );
}

#[test]
fn fetch_url_injects_token_only_for_https() {
    std::env::set_var(GIT_TOKEN_ENV, "secret");
    assert_eq!(
        fetch_url("https://gitlab.com/org/repo.git"),
        "https://oauth2:secret@gitlab.com/org/repo.git"
    );
    // Non-https URLs are left untouched (git resolves ssh/file itself).
    assert_eq!(
        fetch_url("git@gitlab.com:org/repo.git"),
        "git@gitlab.com:org/repo.git"
    );
    std::env::set_var(GIT_TOKEN_ENV, "");
    assert_eq!(
        fetch_url("https://gitlab.com/org/repo.git"),
        "https://gitlab.com/org/repo.git"
    );
    std::env::remove_var(GIT_TOKEN_ENV);
}
