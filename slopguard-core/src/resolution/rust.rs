//! Rust import support: extract `use` / `extern crate` / `mod` from a parsed
//! file, and resolve a crate-root segment against Cargo manifests, the standard
//! library, the module keywords, or a module declared in the same file.

use std::path::Path;

use ast_grep_core::{AstGrep, Doc};

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

/// Rust import support.
pub struct Rust;

impl LanguageSupport for Rust {
    /// Collect the imports and local module declarations of one parsed Rust file.
    fn extract_imports<D: Doc>(&self, root: &AstGrep<D>) -> FileImports {
        let mut imports = Vec::new();
        let mut local_mods = Vec::new();
        for node in root.root().dfs() {
            match &*node.kind() {
                "use_declaration" => {
                    let Some(arg) = node.field("argument") else {
                        continue;
                    };
                    let Some(specifier) = rust_use_root(&arg.text()) else {
                        continue;
                    };
                    let start = node.start_pos();
                    let end = node.end_pos();
                    imports.push(ImportRef {
                        specifier,
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    });
                }
                "extern_crate_declaration" => {
                    let Some(name) = node.field("name") else {
                        continue;
                    };
                    let start = node.start_pos();
                    let end = node.end_pos();
                    imports.push(ImportRef {
                        specifier: name.text().to_string(),
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: first_line(&node.text()),
                    });
                }
                "mod_item" => {
                    if let Some(name) = node.field("name") {
                        local_mods.push(name.text().to_string());
                    }
                }
                _ => {}
            }
        }
        FileImports {
            imports,
            local_mods,
        }
    }

    /// Whether a Rust import resolves against the crate's manifest, the standard
    /// library, the module keywords, or a module declared in the same file.
    fn resolves(
        &self,
        import: &ImportRef,
        local_mods: &[String],
        file_dir: &Path,
        manifests: &mut ManifestResolver,
    ) -> bool {
        let spec = import.specifier.as_str();
        if RUST_ALWAYS_RESOLVED.contains(&spec) || local_mods.iter().any(|m| m == spec) {
            return true;
        }
        match manifests.cargo_deps(file_dir) {
            Some(deps) => deps.contains(spec),
            None => true,
        }
    }
}
