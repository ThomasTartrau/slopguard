use std::env::{remove_var, set_var};
use std::fs::{create_dir_all, read_dir, remove_dir_all, write};
use std::path::Path;
use std::process::Command;
use std::slice::from_ref;

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

/// Options for a test resolve: `file://` remotes allowed, no token.
fn test_opts(cache_root: &Path, offline: bool) -> SourceOptions {
    SourceOptions {
        cache_root: cache_root.to_path_buf(),
        offline,
        git_token: None,
        allowed_protocols: "file:https:ssh".to_string(),
    }
}

/// The commit sha checked out at `dir`.
fn head_sha(dir: &Path) -> String {
    let output = git(dir, &["rev-parse", "HEAD"]);
    String::from_utf8_lossy(&output.stdout).trim().to_string()
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
    let opts = test_opts(cache.path(), false);
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
    let opts = test_opts(cache.path(), false);
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
    let online = test_opts(cache.path(), false);
    resolve_sources(from_ref(&source), &online).unwrap();

    // Second run offline must succeed from the cache alone, no network.
    let offline = test_opts(cache.path(), true);
    let resolved = resolve_sources(&[source], &offline).unwrap();
    assert!(resolved[0].dir.join("source-rule.yml").is_file());
}

#[test]
fn offline_without_cache_is_an_error() {
    let cache = tempdir().unwrap();
    let opts = test_opts(cache.path(), true);
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
fn git_url_starting_with_dash_is_rejected() {
    let scratch = tempdir().unwrap();
    let marker = scratch.path().join("pwned");
    let cache = tempdir().unwrap();
    let source = RuleSource {
        git: Some(format!("--upload-pack=touch {}", marker.display())),
        git_ref: None,
        path: None,
    };

    let err = resolve_sources(&[source], &test_opts(cache.path(), false)).unwrap_err();
    assert!(
        matches!(err, SourceError::InvalidArgument { what: "url", .. }),
        "expected InvalidArgument for the url, got: {err:?}"
    );
    assert!(!marker.exists(), "the injected command must never run");
    assert_eq!(
        read_dir(cache.path()).unwrap().count(),
        0,
        "no cache directory is created before validation"
    );
}

#[test]
fn git_ref_starting_with_dash_is_rejected() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);
    let scratch = tempdir().unwrap();
    let marker = scratch.path().join("pwned");
    let cache = tempdir().unwrap();
    let source = RuleSource {
        git: Some(url),
        git_ref: Some(format!("--upload-pack=touch {}", marker.display())),
        path: None,
    };

    let err = resolve_sources(&[source], &test_opts(cache.path(), false)).unwrap_err();
    assert!(
        matches!(err, SourceError::InvalidArgument { what: "ref", .. }),
        "expected InvalidArgument for the ref, got: {err:?}"
    );
    assert!(!marker.exists(), "the injected command must never run");
}

#[test]
fn token_is_injected_only_for_the_trusted_host() {
    let token = GitToken {
        token: "secret".to_string(),
        host: "GitLab.com".to_string(),
    };
    let token = Some(&token);

    assert_eq!(
        fetch_url("https://gitlab.com/org/repo.git", token),
        "https://oauth2:secret@gitlab.com/org/repo.git"
    );
    // Host comparison ignores case and the port.
    assert_eq!(
        fetch_url("https://GITLAB.com:8443/org/repo.git", token),
        "https://oauth2:secret@GITLAB.com:8443/org/repo.git"
    );

    let unchanged = [
        // Another host.
        "https://evil.example/org/repo.git",
        // Userinfo trick: the real host is evil.example.
        "https://gitlab.com@evil.example/org/repo.git",
        // Existing userinfo is never overwritten.
        "https://user@gitlab.com/org/repo.git",
        // A host that only starts like the trusted one.
        "https://gitlab.com.evil.example/org/repo.git",
        // Non-https transports resolve credentials themselves.
        "http://gitlab.com/org/repo.git",
        "ssh://git@gitlab.com/org/repo.git",
        "git@gitlab.com:org/repo.git",
    ];
    for url in unchanged {
        assert_eq!(fetch_url(url, token), url, "token leaked into {url}");
    }

    // No token configured: nothing injected.
    assert_eq!(
        fetch_url("https://gitlab.com/org/repo.git", None),
        "https://gitlab.com/org/repo.git"
    );
}

#[test]
fn url_host_takes_the_part_after_the_last_at() {
    assert_eq!(url_host("https://trusted.com@evil.com/x"), Some("evil.com"));
    assert_eq!(url_host("https://a:b@host.com:443/x"), Some("host.com"));
    assert_eq!(url_host("https://host.com"), Some("host.com"));
    assert_eq!(url_host("git@host.com:org/repo.git"), None);
}

#[test]
fn source_git_token_requires_a_host() {
    set_var(GIT_TOKEN_ENV, "secret");
    remove_var(GIT_TOKEN_HOST_ENV);
    assert_eq!(git_token_from_env(None), None, "no token without a host");
    assert_eq!(git_token_from_env(Some("")), None, "empty host is no host");
    assert_eq!(
        git_token_from_env(Some("gitlab.com")),
        Some(GitToken {
            token: "secret".to_string(),
            host: "gitlab.com".to_string(),
        })
    );

    set_var(GIT_TOKEN_HOST_ENV, "git.example.com");
    assert_eq!(
        git_token_from_env(Some("gitlab.com")).map(|t| t.host),
        Some("git.example.com".to_string()),
        "the env host wins over the config host"
    );

    set_var(GIT_TOKEN_ENV, "");
    assert_eq!(git_token_from_env(Some("gitlab.com")), None);
    remove_var(GIT_TOKEN_ENV);
    remove_var(GIT_TOKEN_HOST_ENV);
}

#[test]
fn source_token_is_redacted_from_debug_output() {
    let token = GitToken {
        token: "secret".to_string(),
        host: "gitlab.com".to_string(),
    };
    let debug = format!("{token:?}");
    assert!(!debug.contains("secret"), "token leaked: {debug}");
    assert!(debug.contains("gitlab.com"));
}

#[test]
fn file_protocol_is_refused_by_default() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);
    let cache = tempdir().unwrap();
    let opts = SourceOptions {
        allowed_protocols: DEFAULT_ALLOWED_PROTOCOLS.to_string(),
        ..test_opts(cache.path(), false)
    };
    let source = RuleSource {
        git: Some(url),
        git_ref: None,
        path: None,
    };

    let err = resolve_sources(&[source], &opts).unwrap_err();
    assert!(
        matches!(err, SourceError::Git { .. }),
        "file:// must be refused under https:ssh, got: {err:?}"
    );
}

#[test]
fn refresh_failure_fails_the_scan() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);
    let cache = tempdir().unwrap();
    let source = RuleSource {
        git: Some(url),
        git_ref: None,
        path: None,
    };
    let opts = test_opts(cache.path(), false);
    resolve_sources(from_ref(&source), &opts).unwrap();

    // The remote disappears: refreshing the cached clone online must fail
    // instead of silently reusing stale rules.
    remove_dir_all(remote.path()).unwrap();
    let err = resolve_sources(from_ref(&source), &opts).unwrap_err();
    assert!(
        matches!(err, SourceError::Git { .. }),
        "expected a Git error on refresh, got: {err:?}"
    );

    // Offline mode still reuses the cache without any fetch.
    let resolved = resolve_sources(&[source], &test_opts(cache.path(), true)).unwrap();
    assert!(resolved[0].dir.join("source-rule.yml").is_file());
}

#[test]
fn pinned_sha_already_cached_skips_the_fetch() {
    let remote = tempdir().unwrap();
    let url = make_remote(remote.path(), &[("source-rule.yml", A_RULE)]);
    git(
        remote.path(),
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let sha = head_sha(remote.path());
    let cache = tempdir().unwrap();
    let source = RuleSource {
        git: Some(url),
        git_ref: Some(sha.clone()),
        path: None,
    };
    let opts = test_opts(cache.path(), false);
    let first = resolve_sources(from_ref(&source), &opts).unwrap();
    assert_eq!(head_sha(&first[0].dir), sha);

    // With the remote gone, any fetch would fail: success proves the pinned
    // checkout was reused without touching the network.
    remove_dir_all(remote.path()).unwrap();
    let second = resolve_sources(&[source], &opts).unwrap();
    assert!(second[0].dir.join("source-rule.yml").is_file());
}

#[test]
fn is_pinned_sha_accepts_only_full_hex_shas() {
    assert!(is_pinned_sha("0123456789abcdef0123456789ABCDEF01234567"));
    assert!(!is_pinned_sha("0123456"), "abbreviated sha");
    assert!(!is_pinned_sha("main"));
    assert!(!is_pinned_sha("v1.2.3"));
    assert!(!is_pinned_sha("g123456789abcdef0123456789abcdef01234567"));
}

#[test]
fn unpinned_source_warns() {
    let sources = [
        RuleSource {
            git: Some("https://gitlab.com/org/rules.git".to_string()),
            git_ref: Some("main".to_string()),
            path: None,
        },
        RuleSource {
            git: Some("https://user:hunter2@gitlab.com/org/other.git".to_string()),
            git_ref: None,
            path: None,
        },
    ];
    let warnings = unpinned_source_warnings(&sources);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("unpinned rule source 'https://gitlab.com/org/rules.git'"));
    assert!(warnings[0].contains("'main'"));
    assert!(warnings[1].contains("unpinned"));
    assert!(
        !warnings[1].contains("hunter2"),
        "credentials leaked: {}",
        warnings[1]
    );
    assert!(warnings.iter().all(|w| w.is_ascii()));
}

#[test]
fn pinned_sha_does_not_warn() {
    let sources = [
        RuleSource {
            git: Some("https://gitlab.com/org/rules.git".to_string()),
            git_ref: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            path: None,
        },
        // A local source has no ref to pin.
        RuleSource {
            git: None,
            git_ref: None,
            path: Some(PathBuf::from("rules")),
        },
    ];
    assert!(unpinned_source_warnings(&sources).is_empty());
}
