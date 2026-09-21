//! Manifest reading and caching, shared by the per-language resolvers. Reads a
//! source file's governing `Cargo.toml`, `package.json` and `tsconfig.json` from
//! disk and exposes their declared dependencies and path aliases. Reads only
//! manifests already on disk: no network, no `cargo`/`npm` invocation.

use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

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

/// Add the keys of a table's `[dependencies]`, `[dev-dependencies]` and
/// `[build-dependencies]` sub-tables, normalized to their `use` form.
fn add_dep_table_keys(parent: &Table, names: &mut HashSet<String>) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = parent.get(key).and_then(|v| v.as_table()) {
            names.extend(table.keys().map(|k| normalize_crate(k)));
        }
    }
}

/// Collect every dependency name a parsed `Cargo.toml` makes usable: the plain,
/// dev and build dependencies, `[workspace.dependencies]`, `[target.*]`
/// variants, and the package's own name.
fn collect_cargo_deps(table: &Table) -> HashSet<String> {
    let mut names = HashSet::new();
    add_dep_table_keys(table, &mut names);

    if let Some(workspace) = table.get("workspace").and_then(|v| v.as_table()) {
        if let Some(deps) = workspace.get("dependencies").and_then(|v| v.as_table()) {
            names.extend(deps.keys().map(|k| normalize_crate(k)));
        }
    }

    if let Some(targets) = table.get("target").and_then(|v| v.as_table()) {
        for target in targets.values().filter_map(|v| v.as_table()) {
            add_dep_table_keys(target, &mut names);
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
    cargo: HashMap<PathBuf, Option<HashSet<String>>>,
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
            let deps = find_up(dir, "Cargo.toml")
                .and_then(|path| read_to_string(&path).ok())
                .and_then(|text| text.parse::<Table>().ok())
                .map(|table| collect_cargo_deps(&table));
            self.cargo.insert(dir.to_path_buf(), deps);
        }
        self.cargo.get(dir).and_then(|entry| entry.as_ref())
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
