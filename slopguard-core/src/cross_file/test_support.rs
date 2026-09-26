//! Test-support crates: workspace crates that other crates only pull in as
//! dev-dependencies (`cargo-test-support`, `tests-common`). Their code is test
//! code even though it lives under a plain `src/`, so their helpers count when
//! a test delegates its assertions.

use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;
use std::iter::once;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use super::crate_root;

/// Dependency tables whose crates end up in the shipped build.
const NORMAL_TABLES: &[&str] = &["dependencies", "build-dependencies"];

/// The canonical directories of the workspace's test-support crates.
#[derive(Debug, Default)]
pub(super) struct SupportCrates {
    roots: HashSet<PathBuf>,
}

impl SupportCrates {
    /// Scan the manifests of every crate that owns one of `files` and keep the
    /// local path dependencies declared only under `[dev-dependencies]`. A crate
    /// that is also a normal or build dependency somewhere ships in production
    /// code, so it is not test support.
    pub(super) fn detect<'a>(files: impl IntoIterator<Item = &'a Path>) -> Self {
        let crate_dirs: HashSet<PathBuf> = files
            .into_iter()
            .filter_map(crate_root)
            .filter_map(|dir| dir.canonicalize().ok())
            .collect();
        let mut manifests: HashMap<PathBuf, Option<Table>> = HashMap::new();
        let mut normal: HashSet<PathBuf> = HashSet::new();
        let mut dev: HashSet<PathBuf> = HashSet::new();
        for dir in &crate_dirs {
            let Some(manifest) = read_manifest(&dir.join("Cargo.toml")) else {
                continue;
            };
            let ws_dir = workspace_dir(dir, &mut manifests);
            let workspace = ws_dir
                .as_deref()
                .and_then(|d| Some((d, manifests.get(d)?.as_ref()?)));
            let resolve = |name: &str, spec: &Value| path_dependency(dir, name, spec, workspace);
            for (table, is_dev) in dependency_tables(&manifest) {
                let target = if is_dev { &mut dev } else { &mut normal };
                target.extend(table.iter().filter_map(|(name, spec)| resolve(name, spec)));
            }
        }
        Self {
            roots: dev.difference(&normal).cloned().collect(),
        }
    }

    /// Whether `path` belongs to one of the detected test-support crates.
    pub(super) fn contains(&self, path: &Path) -> bool {
        !self.roots.is_empty()
            && crate_root(path)
                .and_then(|dir| dir.canonicalize().ok())
                .is_some_and(|dir| self.roots.contains(&dir))
    }
}

fn read_manifest(path: &Path) -> Option<Table> {
    read_to_string(path).ok()?.parse::<Table>().ok()
}

/// Every dependency table of a manifest, flagged `true` for dev-dependencies:
/// the top-level tables and their `[target.'cfg(..)'.*]` variants.
fn dependency_tables(manifest: &Table) -> Vec<(&Table, bool)> {
    let targets = manifest
        .get("target")
        .and_then(Value::as_table)
        .into_iter()
        .flat_map(|t| t.values().filter_map(Value::as_table));
    once(manifest)
        .chain(targets)
        .flat_map(|scope| {
            NORMAL_TABLES
                .iter()
                .map(|key| (*key, false))
                .chain([("dev-dependencies", true)])
                .filter_map(|(key, is_dev)| Some((scope.get(key)?.as_table()?, is_dev)))
        })
        .collect()
}

/// The directory of the workspace governing the crate at `dir`: the nearest
/// directory at or above it whose `Cargo.toml` declares a `[workspace]` table.
/// Every manifest read on the way up is memoized in `manifests`, so sibling
/// crates do not re-read their shared ancestors.
fn workspace_dir(dir: &Path, manifests: &mut HashMap<PathBuf, Option<Table>>) -> Option<PathBuf> {
    dir.ancestors()
        .find(|ancestor| {
            manifests
                .entry(ancestor.to_path_buf())
                .or_insert_with(|| read_manifest(&ancestor.join("Cargo.toml")))
                .as_ref()
                .is_some_and(|manifest| manifest.contains_key("workspace"))
        })
        .map(Path::to_path_buf)
}

/// The canonical directory a dependency entry points at, when it is a local
/// path dependency: `foo = { path = "../foo" }`, or `foo.workspace = true`
/// resolved through `[workspace.dependencies]`.
fn path_dependency(
    dir: &Path,
    name: &str,
    spec: &Value,
    workspace: Option<(&Path, &Table)>,
) -> Option<PathBuf> {
    let spec = spec.as_table()?;
    if let Some(path) = spec.get("path").and_then(Value::as_str) {
        return dir.join(path).canonicalize().ok();
    }
    if spec.get("workspace").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let (ws_dir, ws) = workspace?;
    let path = ws
        .get("workspace")?
        .get("dependencies")?
        .get(name)?
        .get("path")?
        .as_str()?;
    ws_dir.join(path).canonicalize().ok()
}
