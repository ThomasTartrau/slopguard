//! The project-level pass: which files feed the cross-file index, and which of
//! its findings a scan reports.
//!
//! A partial scan (`--diff`, or explicit files as the pre-commit hook passes
//! them) still builds the index from the whole project the files belong to, so
//! its verdicts match a full scan. It only reports the findings located in the
//! files it was asked about.

use std::collections::{BTreeSet, HashSet};
use std::env;
use std::path::{Path, PathBuf};

use ast_grep_language::SupportLang;
use globset::GlobSet;

use crate::cross_file::{FileSymbols, SymbolIndex};
use crate::finding::Finding;

use super::engine::{BoxedEngine, ProjectContext, RuleContext};
use super::{walk_files, CompiledRules};

/// The files a scan must also read to complete the cross-file index: every
/// parseable file of the projects its explicit file targets belong to, minus
/// the ones already scanned. A directory target is its own project, already
/// covered by the walk, so only file targets widen the index. Empty when no
/// cross-file rule is active.
pub(super) fn index_only_files(
    compiled: &CompiledRules,
    targets: &[PathBuf],
    scanned: &[(PathBuf, SupportLang)],
    ignores: &GlobSet,
) -> Vec<(PathBuf, SupportLang)> {
    if compiled.cross_file.is_empty() {
        return Vec::new();
    }
    let roots: BTreeSet<PathBuf> = targets
        .iter()
        .filter(|target| target.is_file())
        .filter_map(|file| project_of(file))
        .collect();
    if roots.is_empty() {
        return Vec::new();
    }
    let seen: HashSet<PathBuf> = scanned
        .iter()
        .filter_map(|(path, _)| path.canonicalize().ok())
        .collect();
    let roots: Vec<PathBuf> = roots.into_iter().collect();
    walk_files(&roots, ignores)
        .into_iter()
        .filter(|(path, _)| path.canonicalize().is_ok_and(|c| !seen.contains(&c)))
        .collect()
}

/// The project an explicit file belongs to: its nearest ancestor holding a
/// `slopguard.toml` or a `.git`. Spelled `.` when that is the working
/// directory, so the walk yields the same paths as `slopguard scan .`. `None`
/// outside any project: widening to an arbitrary parent (`/tmp`) would walk
/// unrelated files.
fn project_of(file: &Path) -> Option<PathBuf> {
    let file = file.canonicalize().ok()?;
    let root = file
        .ancestors()
        .skip(1)
        .find(|dir| dir.join("slopguard.toml").is_file() || dir.join(".git").exists())?;
    let is_cwd = env::current_dir()
        .and_then(|cwd| cwd.canonicalize())
        .is_ok_and(|cwd| cwd == root);
    Some(if is_cwd {
        PathBuf::from(".")
    } else {
        root.to_path_buf()
    })
}

/// Run the project-level engines over the index built from every contribution
/// and append the findings located in a `reported` file.
pub(super) fn append_cross_file(
    findings: &mut Vec<Finding>,
    project: &[BoxedEngine],
    contributions: &[(PathBuf, FileSymbols)],
    reported: &HashSet<&Path>,
) {
    if project.is_empty() {
        return;
    }
    let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
    let ctx = RuleContext::Project(ProjectContext { index: &index });
    for engine in project {
        findings.extend(
            engine
                .evaluate(&ctx)
                .into_iter()
                .filter(|finding| reported.contains(finding.file.as_path())),
        );
    }
}
