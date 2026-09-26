//! Import resolution: verify that every import in a file resolves against the
//! declared dependencies and on-disk paths, without a full compile.
//!
//! Unlike the cross-file pass, resolution is per file: an import references only
//! the manifests reachable from that file, so it is compatible with `--diff`.
//! To stay correct under caching, the per-file *extraction* (the list of
//! imports, [`extract_imports`]) is cached with the file content, while the
//! *resolution* (matching imports against manifests on disk, [`import_resolves`])
//! re-runs on every scan. Editing a manifest to add a dependency therefore clears
//! a finding even when the importing file is unchanged.
//!
//! Each language lives in its own module ([`rust`], [`typescript`]) implementing
//! [`LanguageSupport`]; [`manifest`] holds the shared manifest reading and
//! caching. This module dispatches on [`Language`] and turns unresolved imports
//! into findings.

use std::path::Path;

use ast_grep_core::{AstGrep, Doc};
use globset::GlobSet;
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::finding::Finding;
use crate::rule::{Language, Rule};

mod manifest;
mod rust;
mod typescript;

pub use manifest::ManifestResolver;

use rust::Rust;
use typescript::TypeScript;

/// Resolution analyses a rule can request. Builtin only: a custom YAML may tune
/// an existing kind's severity or message, never invent a new one, so an unknown
/// discriminant is a parse error.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ResolutionKind {
    UnresolvedImport,
}

/// One import reference found in a file, with the location to anchor a finding.
///
/// For Rust, `specifier` is the crate-root segment of a `use` (`std::fmt` ->
/// `std`). For TypeScript, it is the module string (`./foo`, `react`,
/// `@scope/pkg`). Statement-level `import type` is never recorded: a type-only
/// import may resolve to ambient declarations that are not a runtime dependency,
/// so it is out of scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportRef {
    pub specifier: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    /// First line of the import statement, reported as `matched_text`.
    pub matched_text: String,
}

/// What one file contributes to the resolution pass: its imports plus, for Rust,
/// the names it binds itself (`mod foo;`, `use crate::a::foo;`, `use a::b as
/// foo;`), which a bare `use foo::...` in the same file may legitimately
/// reference.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileImports {
    pub imports: Vec<ImportRef>,
    pub local_names: Vec<String>,
}

impl FileImports {
    /// Whether this file imports nothing the resolution pass cares about.
    pub fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }
}

/// Which files a resolution rule may report on, from its `files` / `ignores`
/// globs. Applied to the importing file.
pub struct ResolutionFilter {
    pub files: Option<GlobSet>,
    pub ignores: Option<GlobSet>,
}

impl ResolutionFilter {
    /// Whether a file at `path` is in scope for the rule.
    pub fn allows(&self, path: &Path) -> bool {
        if !self.files.as_ref().is_none_or(|g| g.is_match(path)) {
            return false;
        }
        if self.ignores.as_ref().is_some_and(|g| g.is_match(path)) {
            return false;
        }
        true
    }
}

/// Per-language extraction and resolution. Each supported language is a
/// zero-sized type implementing this trait in its own module; the free functions
/// below select the impl by matching on [`Language`]. The extraction method is
/// generic over `Doc`, so this is a static-dispatch contract, not a `dyn` one.
trait LanguageSupport {
    /// Collect the imports (and, for Rust, the names bound in the file) of one
    /// parsed file.
    fn extract_imports<D: Doc>(&self, root: &AstGrep<D>) -> FileImports;

    /// Whether one import resolves against manifests, the standard library /
    /// builtins, on-disk paths, or same-file names. `local_names` is only
    /// meaningful for Rust; other languages ignore it.
    fn resolves(
        &self,
        import: &ImportRef,
        local_names: &[String],
        file_dir: &Path,
        manifests: &mut ManifestResolver,
    ) -> bool;
}

/// The first line of an import statement, trimmed, for the finding's
/// `matched_text`. A multi-line grouped `use` reports only its first line.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or(text).trim().to_string()
}

/// Extract a file's imports for the given language.
pub fn extract_imports<D: Doc>(lang: &Language, root: &AstGrep<D>) -> FileImports {
    match lang {
        Language::Rust => Rust.extract_imports(root),
        Language::TypeScript => TypeScript.extract_imports(root),
    }
}

/// Whether a single import resolves, dispatching on the file's language.
pub fn import_resolves(
    lang: &Language,
    import: &ImportRef,
    local_names: &[String],
    file_dir: &Path,
    manifests: &mut ManifestResolver,
) -> bool {
    match lang {
        Language::Rust => Rust.resolves(import, local_names, file_dir, manifests),
        Language::TypeScript => TypeScript.resolves(import, local_names, file_dir, manifests),
    }
}

/// Evaluate one resolution rule against a single file's imports, emitting a
/// finding per unresolved import. `$import` in the rule message is replaced with
/// the offending specifier.
pub fn evaluate_file(
    rule: &Rule,
    kind: ResolutionKind,
    lang: &Language,
    path: &Path,
    imports: &FileImports,
    manifests: &mut ManifestResolver,
) -> Vec<Finding> {
    let ResolutionKind::UnresolvedImport = kind;
    let file_dir = path.parent().unwrap_or_else(|| Path::new("."));
    imports
        .imports
        .iter()
        .filter(|import| !import_resolves(lang, import, &imports.local_names, file_dir, manifests))
        .map(|import| Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity.clone(),
            category: rule.category.clone().unwrap_or_default(),
            message: rule.message.replace("$import", &import.specifier),
            note: rule.note.clone(),
            fix: rule.fix.clone(),
            file: path.to_path_buf(),
            line: import.line,
            column: import.column,
            end_line: import.end_line,
            end_column: import.end_column,
            matched_text: import.matched_text.clone(),
            confidence: None,
            escalated: false,
        })
        .collect()
}

#[cfg(test)]
mod tests;
