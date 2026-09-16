//! Git integration: the set of files changed against a ref, for `scan --diff`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git executable not found in PATH: {0}")]
    NotFound(#[source] io::Error),

    #[error("not a git repository: {path} (--diff requires a git working tree)")]
    NotARepository { path: String },

    #[error("git {args} failed: {stderr}")]
    CommandFailed { args: String, stderr: String },
}

/// Run `git` in `cwd` and return its raw stdout.
///
/// Stdout is returned as bytes: `git diff -z` emits NUL-separated paths that
/// are not necessarily valid UTF-8.
fn run_git(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(GitError::NotFound)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.contains("not a git repository") {
            return Err(GitError::NotARepository {
                path: cwd.display().to_string(),
            });
        }
        return Err(GitError::CommandFailed {
            args: args.join(" "),
            stderr,
        });
    }

    Ok(output.stdout)
}

/// Return the root of the git working tree containing `cwd`.
///
/// Inside a linked worktree this is the worktree path, not the main checkout.
pub fn repo_root(cwd: &Path) -> Result<PathBuf, GitError> {
    let stdout = run_git(cwd, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(String::from_utf8_lossy(&stdout).trim()))
}

/// List the files changed relative to `base` (defaults to `HEAD`).
///
/// Returned paths are absolute (resolved against the repository root, since
/// git reports paths relative to it). Deleted files are excluded; renames are
/// reported under their new name only. Untracked files are NOT included: they
/// have no diff entry until they are staged.
pub fn changed_files(cwd: &Path, base: Option<&str>) -> Result<Vec<PathBuf>, GitError> {
    let root = repo_root(cwd)?;

    // Three-dot: diff against the merge base, so commits landed on the base
    // branch since the branch point do not resurface as "changed here".
    // A bare `HEAD` covers both staged and unstaged working tree changes.
    let spec = match base {
        Some(base) => format!("{base}...HEAD"),
        None => "HEAD".to_string(),
    };

    let stdout = run_git(
        cwd,
        &[
            "-c",
            "core.quotePath=false",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            &spec,
        ],
    )?;

    let mut paths: Vec<PathBuf> = stdout
        .split(|b| *b == b'\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| root.join(&*String::from_utf8_lossy(entry)))
        .collect();

    paths.sort();
    paths.dedup();
    paths.retain(|p| p.is_file());
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::fs::write;

    use tempfile::{tempdir, TempDir};

    use super::*;

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

    /// A repository with one committed file (`base.rs`) on `main`.
    fn init_repo() -> TempDir {
        let dir = tempdir().unwrap();
        git(dir.path(), &["-c", "init.defaultBranch=main", "init"]);
        write(dir.path().join("base.rs"), "fn base() {}\n").unwrap();
        git(dir.path(), &["add", "base.rs"]);
        commit(dir.path(), "initial");
        dir
    }

    #[test]
    fn repo_root_returns_toplevel() {
        let dir = init_repo();
        let root = repo_root(dir.path()).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn changed_files_lists_staged_file() {
        let dir = init_repo();
        write(dir.path().join("new.rs"), "fn new_thing() {}\n").unwrap();
        git(dir.path(), &["add", "new.rs"]);

        let changed = changed_files(dir.path(), None).unwrap();
        assert_eq!(changed.len(), 1, "only the staged file changed: {changed:?}");
        assert!(changed[0].is_absolute(), "paths should be absolute");
        assert!(changed[0].ends_with("new.rs"));
    }

    #[test]
    fn changed_files_ignores_deleted() {
        let dir = init_repo();
        git(dir.path(), &["rm", "base.rs"]);

        let changed = changed_files(dir.path(), None).unwrap();
        assert!(
            !changed.iter().any(|p| p.ends_with("base.rs")),
            "deleted files should be excluded: {changed:?}"
        );
    }

    #[test]
    fn changed_files_with_base_ref() {
        let dir = init_repo();
        git(dir.path(), &["checkout", "-b", "feature"]);
        write(dir.path().join("feature.rs"), "fn feature() {}\n").unwrap();
        git(dir.path(), &["add", "feature.rs"]);
        commit(dir.path(), "feature");

        let changed = changed_files(dir.path(), Some("main")).unwrap();
        assert_eq!(changed.len(), 1, "only the branch file changed: {changed:?}");
        assert!(changed[0].ends_with("feature.rs"));
    }

    #[test]
    fn changed_files_renamed_returns_new_name() {
        let dir = init_repo();
        git(dir.path(), &["mv", "base.rs", "renamed.rs"]);

        let changed = changed_files(dir.path(), None).unwrap();
        assert!(
            changed.iter().any(|p| p.ends_with("renamed.rs")),
            "the new name should be scanned: {changed:?}"
        );
        assert!(
            !changed.iter().any(|p| p.ends_with("base.rs")),
            "the old name is gone: {changed:?}"
        );
    }

    #[test]
    fn not_a_git_repo_is_an_error() {
        let dir = tempdir().unwrap();
        let err = changed_files(dir.path(), None).unwrap_err();
        assert!(
            matches!(err, GitError::NotARepository { .. }),
            "expected NotARepository, got {err:?}"
        );
    }
}
