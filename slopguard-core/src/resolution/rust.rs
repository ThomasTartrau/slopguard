//! Rust import support: extract `use` / `extern crate` from a parsed file, and
//! resolve a crate-root segment against Cargo manifests, the standard library,
//! the module keywords, or a name the file itself brings into scope.

use std::collections::HashSet;
use std::path::Path;

use ast_grep_core::{AstGrep, Doc, Node};

use super::manifest::ManifestResolver;
use super::{first_line, FileImports, ImportRef, LanguageSupport};

/// Rust paths that always resolve without a manifest: the standard library
/// crates and the module keywords.
const RUST_ALWAYS_RESOLVED: &[&str] = &[
    "std",
    "core",
    "alloc",
    "proc_macro",
    "test",
    "crate",
    "self",
    "super",
    "Self",
];

/// Glob roots that only bring standard items into scope. A glob from anywhere
/// else (`super::*`, `crate::prelude::*`, an external prelude) can bring a
/// module into scope under a name the file never spells out.
const STD_GLOB_ROOTS: &[&str] = &["std", "core", "alloc"];

/// The crate-root segment of a Rust `use` argument: the first path identifier,
/// leading `::` stripped. `std::fmt` -> `std`, `::serde::X` -> `serde`. A
/// grouped top-level use (`use {a, b}`) has no single root and returns `None`.
fn rust_use_root(arg_text: &str) -> Option<String> {
    let trimmed = arg_text.trim().trim_start_matches("::").trim_start();
    if trimmed.starts_with('{') {
        return None;
    }
    let root: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!root.is_empty()).then_some(root)
}

/// The last segment of a path: `crate::runtime::scheduler` -> `scheduler`.
fn last_segment(path: &str) -> String {
    path.rsplit("::").next().unwrap_or(path).trim().to_string()
}

/// The names a `use` tree binds in its scope: the last segment of each imported
/// path, the alias of a renamed one, and the parent path of a `self` in a list
/// (`use crate::runtime::scheduler::{self, Defer}` binds `scheduler`).
fn bound_names<D: Doc>(tree: &Node<'_, D>, out: &mut Vec<String>) {
    match &*tree.kind() {
        "identifier" => out.push(tree.text().to_string()),
        "scoped_identifier" => {
            if let Some(name) = tree.field("name") {
                out.push(name.text().to_string());
            }
        }
        "use_as_clause" => {
            if let Some(alias) = tree.field("alias") {
                out.push(alias.text().to_string());
            }
        }
        "scoped_use_list" => {
            let parent = tree.field("path").map(|p| last_segment(&p.text()));
            if let Some(list) = tree.field("list") {
                for item in list.children() {
                    match (&*item.kind(), &parent) {
                        ("self", Some(parent)) => out.push(parent.clone()),
                        _ => bound_names(&item, out),
                    }
                }
            }
        }
        "use_list" => {
            for item in tree.children() {
                bound_names(&item, out);
            }
        }
        _ => {}
    }
}

/// The `mod name` declarations inside a macro body. tree-sitter keeps a macro's
/// argument as an unparsed token tree, so `cfg_if! { mod imp; }` never yields a
/// `mod_item`. `$name` metavariables of a `macro_rules!` are skipped.
fn mods_in_macro_body(text: &str) -> Vec<String> {
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .filter(|w| !w.is_empty())
        .collect();
    words
        .windows(2)
        .filter(|pair| pair[0] == "mod" && !pair[1].starts_with('$'))
        .map(|pair| pair[1].to_string())
        .collect()
}

/// The module scope a node belongs to: the start of its nearest enclosing
/// `mod` item, or `None` for the file root. Function bodies belong to the
/// module that contains them, like the names they can see.
fn module_scope<D: Doc>(node: &Node<'_, D>) -> Option<usize> {
    node.ancestors()
        .find(|a| a.kind() == "mod_item")
        .map(|m| m.range().start)
}

/// A crate name is lowercase by convention (cargo warns otherwise), so a root
/// starting with an uppercase letter names an item in scope, typically an enum
/// whose variants are imported (`use Ordering::*`), never a crate.
fn names_an_item(root: &str) -> bool {
    root.chars().next().is_some_and(char::is_uppercase)
}

/// Rust import support.
pub struct Rust;

impl LanguageSupport for Rust {
    /// Collect the crate-root imports of one parsed Rust file, and the names the
    /// file binds locally (modules, including those declared in macro bodies,
    /// and every name a `use` brings into scope).
    ///
    /// An import in a module scope that also holds a non-std glob is dropped:
    /// the glob may have brought its root into scope, so nothing can be asserted.
    fn extract_imports<D: Doc>(&self, root: &AstGrep<D>) -> FileImports {
        let mut candidates: Vec<(ImportRef, Option<usize>)> = Vec::new();
        let mut local_names = Vec::new();
        let mut glob_scopes: HashSet<Option<usize>> = HashSet::new();
        for node in root.root().dfs() {
            match &*node.kind() {
                "use_declaration" => {
                    let Some(arg) = node.field("argument") else {
                        continue;
                    };
                    let mut bound = Vec::new();
                    bound_names(&arg, &mut bound);
                    let Some(specifier) = rust_use_root(&arg.text()) else {
                        local_names.extend(bound);
                        continue;
                    };
                    // `use made_up;` binds `made_up`: a name must not vouch for
                    // the very root that introduced it.
                    local_names.extend(bound.into_iter().filter(|name| *name != specifier));
                    let scope = module_scope(&node);
                    let has_glob = arg.dfs().any(|n| n.kind() == "use_wildcard");
                    if has_glob && !STD_GLOB_ROOTS.contains(&specifier.as_str()) {
                        glob_scopes.insert(scope);
                    }
                    let start = node.start_pos();
                    let end = node.end_pos();
                    let import = ImportRef {
                        specifier,
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    };
                    candidates.push((import, scope));
                }
                "extern_crate_declaration" => {
                    let Some(name) = node.field("name") else {
                        continue;
                    };
                    if let Some(alias) = node.field("alias") {
                        local_names.push(alias.text().to_string());
                    }
                    let start = node.start_pos();
                    let end = node.end_pos();
                    let import = ImportRef {
                        specifier: name.text().to_string(),
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    };
                    candidates.push((import, module_scope(&node)));
                }
                "mod_item" => {
                    if let Some(name) = node.field("name") {
                        local_names.push(name.text().to_string());
                    }
                }
                "token_tree"
                    if node
                        .parent()
                        .is_some_and(|p| p.kind() == "macro_invocation") =>
                {
                    local_names.extend(mods_in_macro_body(&node.text()));
                }
                _ => {}
            }
        }
        local_names.sort();
        local_names.dedup();
        let imports = candidates
            .into_iter()
            .filter(|(_, scope)| !glob_scopes.contains(scope))
            .map(|(import, _)| import)
            .collect();
        FileImports {
            imports,
            local_names,
        }
    }

    /// Whether a Rust import resolves against the crate's manifest, the standard
    /// library, the module keywords, an item name, or a name bound in the file.
    fn resolves(
        &self,
        import: &ImportRef,
        local_names: &[String],
        file_dir: &Path,
        manifests: &mut ManifestResolver,
    ) -> bool {
        let spec = import.specifier.as_str();
        if RUST_ALWAYS_RESOLVED.contains(&spec)
            || names_an_item(spec)
            || local_names.iter().any(|m| m == spec)
        {
            return true;
        }
        match manifests.cargo_deps(file_dir) {
            Some(deps) => deps.contains(spec),
            None => true,
        }
    }
}
