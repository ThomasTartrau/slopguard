//! Manifest reading and caching, shared by the per-language resolvers. Reads a
//! source file's governing `Cargo.toml`, `package.json` and `tsconfig.json` from
//! disk and exposes their declared dependencies and path aliases. Reads only
//! manifests already on disk: no network, no `cargo`/`npm` invocation.

use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;
use std::path::{absolute, Path, PathBuf};

use serde_json::Value as JsonValue;
use toml::Table;

/// Normalize a Cargo dependency key or crate name to its `use` form: hyphens
/// become underscores (`ast-grep-core` -> `ast_grep_core`).
fn normalize_crate(name: &str) -> String {
    name.replace('-', "_")
}

/// Walk up from `start` (inclusive) looking for `filename`, returning the first
/// match. Used to find the manifest that governs a source file.
fn find_up(start: &Path, filename: &str) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        let candidate = current.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = current.parent();
    }
    None
}

/// A workspace root: the directory of the manifest declaring `[workspace]` and
/// its parsed table. Looked up lazily, only when a dependency inherits from it.
type WorkspaceRoot = Option<(PathBuf, Table)>;

/// The normalized `[lib] name` declared in `table`, if any.
fn table_lib_name(table: &Table) -> Option<String> {
    table
        .get("lib")
        .and_then(|v| v.as_table())
        .and_then(|lib| lib.get("name"))
        .and_then(|v| v.as_str())
        .map(normalize_crate)
}

/// The normalized `[lib] name` of the crate whose manifest lives in `dir`, or
/// `None` when the manifest is unreadable or declares no library name.
fn lib_name(dir: &Path) -> Option<String> {
    let text = read_to_string(dir.join("Cargo.toml")).ok()?;
    let table = text.parse::<Table>().ok()?;
    table_lib_name(&table)
}

/// The nearest manifest declaring a `[workspace]`: `table` itself (located in
/// `manifest_dir`) or the first ancestor directory whose `Cargo.toml` has one.
fn workspace_root(manifest_dir: &Path, table: &Table) -> WorkspaceRoot {
    if table.get("workspace").is_some_and(|v| v.is_table()) {
        return Some((manifest_dir.to_path_buf(), table.clone()));
    }
    manifest_dir.ancestors().skip(1).find_map(|dir| {
        let text = read_to_string(dir.join("Cargo.toml")).ok()?;
        let parsed = text.parse::<Table>().ok()?;
        parsed
            .get("workspace")
            .is_some_and(|v| v.is_table())
            .then(|| (dir.to_path_buf(), parsed))
    })
}

/// The `[lib] name` of a path dependency declared as `spec` in a manifest
/// located in `base_dir`. A renamed dependency (`package =`) is skipped: its key
/// stays the import name.
fn path_dependency_lib_name(spec: &Table, base_dir: &Path) -> Option<String> {
    if spec.contains_key("package") {
        return None;
    }
    let path = spec.get("path").and_then(|v| v.as_str())?;
    lib_name(&base_dir.join(path))
}

/// The `[lib] name` of the path dependency `key` declared in the workspace
/// root's `[workspace.dependencies]`, resolved against that root.
fn inherited_lib_name(root: &WorkspaceRoot, key: &str) -> Option<String> {
    let (root_dir, root_table) = root.as_ref()?;
    let entry = root_table
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_table())?;
    path_dependency_lib_name(entry, root_dir)
}

/// Where a manifest's dependency names are being collected from: its parsed
/// table, its directory, and the lazily resolved workspace root.
struct DepSource<'a> {
    manifest: &'a Table,
    dir: &'a Path,
    workspace: Option<WorkspaceRoot>,
}

/// Add the names a dependency table makes importable: each key normalized, plus
/// the `[lib] name` of path dependencies, including those inherited through
/// `workspace = true` (resolved against the workspace root that declares them).
fn add_dependencies(deps: &Table, source: &mut DepSource<'_>, names: &mut HashSet<String>) {
    for (key, value) in deps {
        names.insert(normalize_crate(key));
        let Some(spec) = value.as_table() else {
            continue;
        };
        if spec.contains_key("package") {
            continue;
        }
        if spec.contains_key("path") {
            names.extend(path_dependency_lib_name(spec, source.dir));
        } else if spec.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
            let (manifest, dir) = (source.manifest, source.dir);
            let root = source
                .workspace
                .get_or_insert_with(|| workspace_root(dir, manifest));
            names.extend(inherited_lib_name(root, key));
        }
    }
}

/// Add the dependencies of a table's `[dependencies]`, `[dev-dependencies]` and
/// `[build-dependencies]` sub-tables.
fn add_dep_tables(parent: &Table, source: &mut DepSource<'_>, names: &mut HashSet<String>) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = parent.get(key).and_then(|v| v.as_table()) {
            add_dependencies(table, source, names);
        }
    }
}

/// Collect every dependency name a parsed `Cargo.toml` (located in
/// `manifest_dir`) makes usable: the plain, dev and build dependencies,
/// `[workspace.dependencies]`, `[target.*]` variants, the package's own name,
/// its `[lib] name`, and the `[lib] name` of each path dependency.
fn collect_cargo_deps(table: &Table, manifest_dir: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut source = DepSource {
        manifest: table,
        dir: manifest_dir,
        workspace: None,
    };
    add_dep_tables(table, &mut source, &mut names);

    if let Some(deps) = table
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        add_dependencies(deps, &mut source, &mut names);
    }

    if let Some(targets) = table.get("target").and_then(|v| v.as_table()) {
        for target in targets.values().filter_map(|v| v.as_table()) {
            add_dep_tables(target, &mut source, &mut names);
        }
    }

    if let Some(name) = table
        .get("package")
        .and_then(|v| v.as_table())
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
    {
        names.insert(normalize_crate(name));
    }

    names.extend(table_lib_name(table));

    names
}

/// Collect the dependency names declared in a parsed `package.json`.
fn collect_package_json_deps(value: &JsonValue) -> HashSet<String> {
    let mut names = HashSet::new();
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = value.get(key).and_then(|v| v.as_object()) {
            names.extend(obj.keys().cloned());
        }
    }
    names
}

/// Strip `//` and `/* */` comments and trailing commas from JSONC (tsconfig) so
/// `serde_json` can parse it. Best-effort: string contents are preserved.
fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for next in chars.by_ref() {
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
            }
            _ => out.push(c),
        }
    }
    let chars: Vec<char> = out.chars().collect();
    let mut cleaned = String::with_capacity(out.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace()).copied();
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        cleaned.push(c);
    }
    cleaned
}

/// The alias prefixes declared in a tsconfig's `compilerOptions.paths`. A
/// wildcard alias `@app/*` is stored as prefix `@app/` with `wildcard = true`;
/// an exact alias `@app` is stored as `@app` with `wildcard = false`.
fn collect_ts_aliases(value: &JsonValue) -> Vec<(String, bool)> {
    let Some(paths) = value
        .get("compilerOptions")
        .and_then(|o| o.get("paths"))
        .and_then(|p| p.as_object())
    else {
        return Vec::new();
    };
    paths
        .keys()
        .map(|key| match key.strip_suffix('*') {
            Some(prefix) => (prefix.to_string(), true),
            None => (key.clone(), false),
        })
        .collect()
}

/// Reads and memoizes the manifests governing scanned files. Single-threaded:
/// the resolution pass runs after the parallel per-file scan. Keyed by the
/// file's directory, so files in the same directory reuse a parsed manifest.
#[derive(Default)]
pub struct ManifestResolver {
    /// Source directory -> the `Cargo.toml` governing it (`None` when none is
    /// reachable or readable).
    cargo: HashMap<PathBuf, Option<PathBuf>>,
    /// `Cargo.toml` path -> its collected dependency names, so the directories
    /// of one crate share a single read of its manifest and path dependencies.
    cargo_by_manifest: HashMap<PathBuf, HashSet<String>>,
    package_json: HashMap<PathBuf, Option<HashSet<String>>>,
    ts_aliases: HashMap<PathBuf, Vec<(String, bool)>>,
}

impl ManifestResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// The Cargo dependency names governing `dir`, or `None` when no reachable
    /// `Cargo.toml` could be read (nothing can be asserted about imports).
    pub(super) fn cargo_deps(&mut self, dir: &Path) -> Option<&HashSet<String>> {
        if !self.cargo.contains_key(dir) {
            let manifest = find_up(dir, "Cargo.toml").and_then(|path| {
                if self.cargo_by_manifest.contains_key(&path) {
                    return Some(path);
                }
                let table = read_to_string(&path).ok()?.parse::<Table>().ok()?;
                // Absolute, so the walk up to a workspace root declared above
                // the current directory succeeds when `dir` is relative.
                let manifest_dir = path.parent().unwrap_or_else(|| Path::new("."));
                let manifest_dir =
                    absolute(manifest_dir).unwrap_or_else(|_| manifest_dir.to_path_buf());
                let deps = collect_cargo_deps(&table, &manifest_dir);
                self.cargo_by_manifest.insert(path.clone(), deps);
                Some(path)
            });
            self.cargo.insert(dir.to_path_buf(), manifest);
        }
        let manifest = self.cargo.get(dir)?.as_ref()?;
        self.cargo_by_manifest.get(manifest)
    }

    /// The `package.json` dependency names governing `dir`, or `None` when no
    /// reachable `package.json` could be read.
    pub(super) fn package_json_deps(&mut self, dir: &Path) -> Option<&HashSet<String>> {
        if !self.package_json.contains_key(dir) {
            let deps = find_up(dir, "package.json")
                .and_then(|path| read_to_string(&path).ok())
                .and_then(|text| serde_json::from_str::<JsonValue>(&text).ok())
                .map(|value| collect_package_json_deps(&value));
            self.package_json.insert(dir.to_path_buf(), deps);
        }
        self.package_json.get(dir).and_then(|entry| entry.as_ref())
    }

    fn ts_aliases(&mut self, dir: &Path) -> &[(String, bool)] {
        if !self.ts_aliases.contains_key(dir) {
            let aliases = find_up(dir, "tsconfig.json")
                .and_then(|path| read_to_string(&path).ok())
                .and_then(|text| serde_json::from_str::<JsonValue>(&strip_jsonc(&text)).ok())
                .map(|value| collect_ts_aliases(&value))
                .unwrap_or_default();
            self.ts_aliases.insert(dir.to_path_buf(), aliases);
        }
        self.ts_aliases.get(dir).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether `spec` matches a tsconfig `paths` alias reachable from `dir`.
    pub(super) fn ts_alias_matches(&mut self, dir: &Path, spec: &str) -> bool {
        self.ts_aliases(dir).iter().any(|(prefix, wildcard)| {
            if *wildcard {
                spec.starts_with(prefix.as_str())
            } else {
                spec == prefix
            }
        })
    }
}

/// Whether a dependency spec enables the `feature` (only a table spec can).
fn spec_has_feature(spec: &toml::Value, feature: &str) -> bool {
    spec.get("features")
        .and_then(|f| f.as_array())
        .is_some_and(|features| features.iter().any(|f| f.as_str() == Some(feature)))
}

/// The crate the strum derive macros (`Display`, `IntoStaticStr`, ...) are
/// reachable through for code in `dir`, read from the governing `Cargo.toml`:
/// `strum` when its `derive` feature is on (in the member's spec, or in the
/// `[workspace.dependencies]` entry it inherits), else `strum_macros` when it
/// is a dependency, else `None`. Only `[dependencies]` counts: the fixed code
/// is production code.
pub(crate) fn strum_derive_crate(dir: &Path) -> Option<&'static str> {
    let path = find_up(dir, "Cargo.toml")?;
    let table = read_to_string(&path).ok()?.parse::<Table>().ok()?;
    let deps = table.get("dependencies")?.as_table()?;
    if let Some(spec) = deps.get("strum") {
        let mut derive = spec_has_feature(spec, "derive");
        if !derive && spec.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
            let manifest_dir = path.parent().unwrap_or_else(|| Path::new("."));
            let manifest_dir =
                absolute(manifest_dir).unwrap_or_else(|_| manifest_dir.to_path_buf());
            derive = workspace_root(&manifest_dir, &table).is_some_and(|(_, root)| {
                root.get("workspace")
                    .and_then(|w| w.get("dependencies"))
                    .and_then(|d| d.get("strum"))
                    .is_some_and(|s| spec_has_feature(s, "derive"))
            });
        }
        if derive {
            return Some("strum");
        }
    }
    deps.contains_key("strum_macros").then_some("strum_macros")
}
