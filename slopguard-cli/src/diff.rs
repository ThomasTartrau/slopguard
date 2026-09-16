//! Resolve which files `scan --diff` should scan.

use std::path::{Path, PathBuf};

use slopguard_core::git;

use crate::AppError;

/// The changed files to scan, plus what they were diffed against.
pub struct DiffScope {
    pub paths: Vec<PathBuf>,
    pub base: String,
    pub files_changed: usize,
}

/// Ask git for the files changed against `base` and narrow them to the
/// requested scan paths.
///
/// `base` is `None` for a plain `--diff` (staged plus unstaged changes against
/// `HEAD`).
pub fn resolve_diff_scope(
    cwd: &Path,
    base: Option<&str>,
    scan_paths: &[PathBuf],
) -> Result<DiffScope, AppError> {
    let changed = git::changed_files(cwd, base)?;
    let paths = restrict_to_paths(changed, scan_paths);
    Ok(DiffScope {
        base: base.unwrap_or("HEAD").to_string(),
        files_changed: paths.len(),
        paths,
    })
}

/// Keep only the changed files that live under one of `scan_paths`.
///
/// `paths` defaults to `"."`, so this is what makes `slopguard scan --diff`
/// run from a subdirectory scan only that subtree rather than the whole repo.
/// When no scan path can be canonicalized (they do not exist on disk), the
/// changed list is returned untouched rather than silently emptied.
fn restrict_to_paths(changed: Vec<PathBuf>, scan_paths: &[PathBuf]) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = scan_paths
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect();
    if roots.is_empty() {
        return changed;
    }

    changed
        .into_iter()
        .filter(|path| {
            let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
            // `starts_with` is component-wise and true for an equal path, so
            // this covers both a scan directory and an explicit file path.
            roots.iter().any(|root| resolved.starts_with(root))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn restrict_keeps_files_under_the_requested_dir() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let docs = dir.path().join("docs");
        create_dir_all(&src).unwrap();
        create_dir_all(&docs).unwrap();
        let kept = src.join("main.rs");
        let dropped = docs.join("guide.md");
        write(&kept, "fn main() {}\n").unwrap();
        write(&dropped, "# guide\n").unwrap();

        let result = restrict_to_paths(vec![kept.clone(), dropped], &[src]);
        assert_eq!(result.len(), 1);
        assert!(result[0].ends_with("main.rs"));
    }

    #[test]
    fn restrict_matches_an_exact_file_path() {
        let dir = tempdir().unwrap();
        let wanted = dir.path().join("wanted.rs");
        let other = dir.path().join("other.rs");
        write(&wanted, "fn wanted() {}\n").unwrap();
        write(&other, "fn other() {}\n").unwrap();

        let result = restrict_to_paths(vec![wanted.clone(), other], &[wanted.clone()]);
        assert_eq!(result.len(), 1);
        assert!(result[0].ends_with("wanted.rs"));
    }

    #[test]
    fn restrict_returns_everything_when_no_scan_path_resolves() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() {}\n").unwrap();

        let result = restrict_to_paths(vec![file.clone()], &[dir.path().join("does-not-exist")]);
        assert_eq!(result, vec![file]);
    }
}
