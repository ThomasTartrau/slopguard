//! Git integration for diff-aware scanning: resolve the files changed against
//! a ref so `scan --diff` only looks at touched code.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("'{path}' is not inside a git repository (--diff requires one)")]
    NotARepository { path: String },

    #[error("failed to run git: {source}")]
    Spawn {
        #[source]
        source: std::io::Error,
    },

    #[error("unknown git ref '{base}': {stderr}")]
    BadRef { base: String, stderr: String },

    #[error("git {args} failed: {stderr}")]
    Command { args: String, stderr: String },
}

/// The well-known SHA of git's empty tree, used to diff a repository that has
/// no commit yet.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Added, Copied, Modified, Renamed. Deletions (D) are excluded: there is no
/// file left to scan. Renames are reported under their new name.
const DIFF_FILTER: &str = "--diff-filter=ACMR";

fn run_git(dir: &Path, args: &[&str]) -> Result<Output, GitError> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|source| GitError::Spawn { source })
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

/// Absolute path of the repository root containing `dir`.
pub fn repo_root(dir: &Path) -> Result<PathBuf, GitError> {
    let output = run_git(dir, &["rev-parse", "--show-toplevel"])?;
    if !output.status.success() {
        return Err(GitError::NotARepository {
            path: dir.display().to_string(),
        });
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

/// Files added, modified, copied or renamed relative to `base` (or to `HEAD`
/// when `base` is `None`, covering both staged and unstaged changes).
///
/// Paths are returned absolute, sorted and deduplicated. Deleted files are
/// excluded; renamed files appear under their new name. Untracked files are
/// not included: they are neither staged nor tracked, so `git diff` does not
/// see them.
pub fn changed_files(dir: &Path, base: Option<&str>) -> Result<Vec<PathBuf>, GitError> {
    let root = repo_root(dir)?;

    if let Some(b) = base {
        let probe = run_git(
            dir,
            &["rev-parse", "--verify", "--quiet", &format!("{b}^{{commit}}")],
        )?;
        if !probe.status.success() {
            let stderr = stderr_of(&probe);
            return Err(GitError::BadRef {
                base: b.to_string(),
                stderr: if stderr.is_empty() {
                    "no such ref".to_string()
                } else {
                    stderr
                },
            });
        }
    }

    let rev = match base {
        Some(b) => format!("{b}...HEAD"),
        None => {
            let head = run_git(dir, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
            if head.status.success() {
                "HEAD".to_string()
            } else {
                EMPTY_TREE.to_string()
            }
        }
    };

    // `-z` keeps paths NUL-separated, so non-ASCII names and spaces survive
    // whatever `core.quotepath` is set to.
    let output = run_git(dir, &["diff", "--name-only", "-z", DIFF_FILTER, &rev])?;
    if !output.status.success() {
        return Err(GitError::Command {
            args: format!("diff --name-only {rev}"),
            stderr: stderr_of(&output),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files: Vec<PathBuf> = stdout
        .split('\0')
        .filter(|name| !name.is_empty())
        // git prints paths relative to the repository root, not to `dir`.
        .map(|name| root.join(name))
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, write};

    use tempfile::tempdir;

    use super::*;

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

    fn names(files: &[PathBuf]) -> Vec<String> {
        files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .map(String::from)
            .collect()
    }

    #[test]
    fn not_a_git_repo_is_an_error() {
        let dir = tempdir().unwrap();
        match changed_files(dir.path(), None) {
            Err(GitError::NotARepository { .. }) => {}
            other => panic!("expected NotARepository, got {other:?}"),
        }
    }

    #[test]
    fn staged_and_unstaged_files_are_reported() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        commit(dir.path(), "init");

        write(dir.path().join("a.rs"), "fn a() { let x = 1; }\n").unwrap();
        write(dir.path().join("b.rs"), "fn b() {}\n").unwrap();
        git(dir.path(), &["add", "b.rs"]);

        let files = changed_files(dir.path(), None).unwrap();
        assert!(files.iter().all(|p| p.is_absolute()), "{files:?}");
        let names = names(&files);
        assert!(names.contains(&"a.rs".to_string()), "{names:?}");
        assert!(names.contains(&"b.rs".to_string()), "{names:?}");
    }

    #[test]
    fn deleted_file_is_excluded() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        write(dir.path().join("b.rs"), "fn b() {}\n").unwrap();
        commit(dir.path(), "init");

        git(dir.path(), &["rm", "-q", "b.rs"]);

        let files = changed_files(dir.path(), None).unwrap();
        let names = names(&files);
        assert!(!names.contains(&"b.rs".to_string()), "{names:?}");
    }

    #[test]
    fn renamed_file_reported_under_new_name() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        commit(dir.path(), "init");

        git(dir.path(), &["mv", "a.rs", "b.rs"]);

        let files = changed_files(dir.path(), None).unwrap();
        let names = names(&files);
        assert!(names.contains(&"b.rs".to_string()), "{names:?}");
        assert!(!names.contains(&"a.rs".to_string()), "{names:?}");
    }

    #[test]
    fn base_ref_uses_merge_base() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("base.rs"), "fn base() {}\n").unwrap();
        commit(dir.path(), "base");

        git(dir.path(), &["checkout", "-q", "-b", "feature"]);
        write(dir.path().join("feature.rs"), "fn feature() {}\n").unwrap();
        commit(dir.path(), "feature");

        let files = changed_files(dir.path(), Some("main")).unwrap();
        assert_eq!(names(&files), vec!["feature.rs".to_string()]);
    }

    #[test]
    fn unknown_base_ref_is_an_error() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        commit(dir.path(), "init");

        match changed_files(dir.path(), Some("no-such-ref")) {
            Err(GitError::BadRef { base, .. }) => assert_eq!(base, "no-such-ref"),
            other => panic!("expected BadRef, got {other:?}"),
        }
    }

    #[test]
    fn repository_without_commit_reports_staged_files() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        git(dir.path(), &["add", "a.rs"]);

        let files = changed_files(dir.path(), None).unwrap();
        assert_eq!(names(&files), vec!["a.rs".to_string()]);
    }

    #[test]
    fn paths_are_absolute_when_run_from_a_subdirectory() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        let src = dir.path().join("src");
        create_dir_all(&src).unwrap();
        write(src.join("lib.rs"), "fn a() {}\n").unwrap();
        commit(dir.path(), "init");

        write(src.join("lib.rs"), "fn a() { let x = 1; }\n").unwrap();

        let files = changed_files(&src, None).unwrap();
        assert_eq!(files.len(), 1, "{files:?}");
        assert!(files[0].is_absolute(), "{files:?}");
        assert!(files[0].is_file(), "{files:?}");
    }
}
