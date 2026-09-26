//! Project-wide analyses that no single file can answer.
//!
//! The per-file scan contributes a [`FileSymbols`] for every file it parses.
//! Those contributions are assembled into a [`SymbolIndex`] once the whole walk
//! is done, and each active cross-file rule is evaluated against that index.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ast_grep_core::{AstGrep, Doc, Node};
use globset::GlobSet;
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::finding::Finding;
use crate::rule::Rule;
use crate::test_filter::{CfgTestRanges, TestPaths};

mod names;

use names::{bare_trait_name, bare_type_name, generic_param_names, last_segment};

/// Cross-file analyses a rule can request. Builtin only: a custom YAML may
/// tune an existing kind's severity or message, never invent a new one, so an
/// unknown discriminant is a parse error.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CrossFileKind {
    SingleImplTrait,
    DuplicateErrorMessage,
}

/// Below this length (message content, quotes excluded) a repeated string is
/// noise (`"utf-8"`, `"id"`), not a copy-pasted error message.
const MIN_ERROR_MESSAGE_LEN: usize = 10;

/// Macros that build an error value from a message. Matched on the last path
/// segment, so `anyhow::bail!` and `bail!` both count.
///
/// `panic!`, `unreachable!`, `todo!` and `.expect()` are left out on purpose:
/// a panic prints its `file:line`, so a message repeated across files is still
/// traced to its site, and those messages are invariants, not errors a user
/// reads. An error value carries no location: two sites with the same text are
/// indistinguishable in a log.
const ERROR_MACROS: &[&str] = &["bail", "anyhow", "eyre", "format_err", "ensure"];

/// A trait declared in a scanned file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraitDecl {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    /// The declaration sits inside a `#[cfg(test)]` item.
    pub in_cfg_test: bool,
    /// Declaration header reported as `matched_text`, e.g. `pub trait Repository`.
    pub header: String,
}

/// An `impl Trait for Type` header found in a scanned file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraitImpl {
    /// Bare trait name: last path segment, generic arguments stripped.
    pub trait_name: String,
    /// `impl<T> Foo for T`: the implementing type is one of the impl's own
    /// generic parameters, so the trait covers a whole family of types.
    pub blanket: bool,
    /// Bare name of the implementing type (`Request<B>` -> `Request`,
    /// `&'a str` -> `str`), matched against the types the project declares.
    pub self_type: String,
}

/// A string literal used as an error message, kept for the duplicate-message
/// cross-file analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessageLit {
    /// Message content, surrounding quotes stripped.
    pub text: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    /// The literal sits inside a `#[cfg(test)]` item.
    pub in_cfg_test: bool,
}

/// What one file contributes to the project index.
///
/// Deliberately carries no path. The scan cache is keyed on file content, so
/// two byte-identical files share one entry; pairing the contribution with the
/// path actually scanned keeps a duplicated file from inheriting the other's
/// location.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSymbols {
    pub traits: Vec<TraitDecl>,
    pub impls: Vec<TraitImpl>,
    pub error_messages: Vec<ErrorMessageLit>,
    /// Names of the structs, enums and unions the file declares: the types
    /// that can take inherent methods. A type alias cannot (its target may be
    /// foreign), so it is left out.
    pub types: Vec<String>,
}

impl FileSymbols {
    /// Whether this file declares or implements nothing the index cares about.
    pub fn is_empty(&self) -> bool {
        self.traits.is_empty()
            && self.impls.is_empty()
            && self.error_messages.is_empty()
            && self.types.is_empty()
    }
}

/// Turn a `string_literal` node into an [`ErrorMessageLit`], dropping the
/// surrounding quotes. Returns `None` for a non-string node, a raw string
/// (`r"..."`, left out to keep quote-stripping simple), or a message shorter
/// than [`MIN_ERROR_MESSAGE_LEN`].
fn string_literal_message<D: Doc>(
    node: &Node<D>,
    cfg_test: &CfgTestRanges,
) -> Option<ErrorMessageLit> {
    if &*node.kind() != "string_literal" {
        return None;
    }
    let raw = node.text();
    let raw = raw.trim();
    let content = raw.strip_prefix('"')?.strip_suffix('"')?;
    if content.chars().count() < MIN_ERROR_MESSAGE_LEN {
        return None;
    }
    let start = node.start_pos();
    let end = node.end_pos();
    let line = start.line() + 1;
    Some(ErrorMessageLit {
        text: content.to_string(),
        line,
        column: start.byte_point().1 + 1,
        end_line: end.line() + 1,
        end_column: end.byte_point().1 + 1,
        in_cfg_test: cfg_test.contains_line(line),
    })
}

/// Collect the error-message string literals of one node, if it is an
/// error-building macro (`bail!`, `anyhow!`, ...).
fn collect_error_messages<D: Doc>(
    node: &Node<D>,
    cfg_test: &CfgTestRanges,
    out: &mut Vec<ErrorMessageLit>,
) {
    if &*node.kind() != "macro_invocation" {
        return;
    }
    let is_error_macro = node
        .field("macro")
        .is_some_and(|m| ERROR_MACROS.contains(&last_segment(&m.text())));
    if is_error_macro {
        out.extend(
            node.dfs()
                .filter_map(|n| string_literal_message(&n, cfg_test)),
        );
    }
}

/// Collect the trait declarations and trait impls of one parsed Rust file.
///
/// `#[derive(Trait)]` parses to an `attribute_item`, never an `impl_item`, so
/// derived implementations are ignored without a special case.
pub fn extract_rust_symbols<D: Doc>(root: &AstGrep<D>, cfg_test: &CfgTestRanges) -> FileSymbols {
    let mut symbols = FileSymbols::default();
    let root_node = root.root();
    for node in root_node.dfs() {
        match &*node.kind() {
            "trait_item" => {
                let Some(name) = node.field("name") else {
                    continue;
                };
                let start = node.start_pos();
                let name_end = name.end_pos();
                let line = start.line() + 1;
                let text = node.text().to_string();
                let header = match text.split_once('{') {
                    Some((head, _)) => head.trim_end().to_string(),
                    None => text.trim_end().to_string(),
                };
                symbols.traits.push(TraitDecl {
                    name: name.text().to_string(),
                    line,
                    column: start.byte_point().1 + 1,
                    end_line: name_end.line() + 1,
                    end_column: name_end.byte_point().1 + 1,
                    in_cfg_test: cfg_test.contains_line(line),
                    header,
                });
            }
            "impl_item" => {
                // An inherent `impl Foo { .. }` has no `trait` field and
                // contributes nothing to the index.
                let Some(trait_ref) = node.field("trait") else {
                    continue;
                };
                let params = generic_param_names(&node);
                let impl_type = node
                    .field("type")
                    .map(|n| n.text().trim().to_string())
                    .unwrap_or_default();
                symbols.impls.push(TraitImpl {
                    trait_name: bare_trait_name(&trait_ref.text()),
                    blanket: params.contains(&impl_type),
                    self_type: bare_type_name(&impl_type),
                });
            }
            "struct_item" | "enum_item" | "union_item" => {
                if let Some(name) = node.field("name") {
                    symbols.types.push(name.text().to_string());
                }
            }
            _ => {}
        }
        collect_error_messages(&node, cfg_test, &mut symbols.error_messages);
    }
    symbols
}

/// Project-wide symbol index assembled from every scanned file.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    traits: HashMap<String, TraitEntry>,
    /// Error-message content -> every occurrence, keyed by exact text so a
    /// literal repeated across files collides.
    error_messages: HashMap<String, Vec<(PathBuf, ErrorMessageLit)>>,
    /// Bare type name -> every file declaring a struct, enum or union of that
    /// name.
    types: HashMap<String, Vec<PathBuf>>,
}

#[derive(Debug, Default)]
struct TraitEntry {
    /// Every declaration seen for this name. More than one makes the name
    /// ambiguous and the trait is never reported.
    decls: Vec<(PathBuf, TraitDecl)>,
    /// Implementing type of each concrete impl.
    concrete_impls: Vec<String>,
    blanket_impls: usize,
}

impl SymbolIndex {
    /// Fold every file's contribution into one index keyed by bare trait name.
    ///
    /// Impls are counted for every scanned file, test code included: a trait
    /// with one production impl plus a test mock is the legitimate "trait
    /// exists to be mocked" pattern, and the mock counting as a second impl is
    /// what suppresses the dominant false positive.
    pub fn build<'a, I>(contributions: I) -> Self
    where
        I: IntoIterator<Item = (&'a Path, &'a FileSymbols)>,
    {
        let mut traits: HashMap<String, TraitEntry> = HashMap::new();
        let mut error_messages: HashMap<String, Vec<(PathBuf, ErrorMessageLit)>> = HashMap::new();
        let mut types: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (path, symbols) in contributions {
            for decl in &symbols.traits {
                traits
                    .entry(decl.name.clone())
                    .or_default()
                    .decls
                    .push((path.to_path_buf(), decl.clone()));
            }
            for imp in &symbols.impls {
                let entry = traits.entry(imp.trait_name.clone()).or_default();
                if imp.blanket {
                    entry.blanket_impls += 1;
                } else {
                    entry.concrete_impls.push(imp.self_type.clone());
                }
            }
            for name in &symbols.types {
                types
                    .entry(name.clone())
                    .or_default()
                    .push(path.to_path_buf());
            }
            for msg in &symbols.error_messages {
                error_messages
                    .entry(msg.text.clone())
                    .or_default()
                    .push((path.to_path_buf(), msg.clone()));
            }
        }
        Self {
            traits,
            error_messages,
            types,
        }
    }

    /// Whether `type_name` is a struct, enum or union declared in the same
    /// crate as the file at `decl_path`: the only case where a trait's single
    /// impl could have been inherent methods instead.
    fn declares_local_type(&self, type_name: &str, decl_path: &Path) -> bool {
        let decl_crate = crate_root(decl_path);
        self.types
            .get(type_name)
            .is_some_and(|paths| paths.iter().any(|p| crate_root(p) == decl_crate))
    }
}

/// The directory of the crate a file belongs to: its nearest ancestor holding a
/// `Cargo.toml`, or `None` when no manifest is reachable.
fn crate_root(path: &Path) -> Option<&Path> {
    path.ancestors()
        .skip(1)
        .find(|dir| dir.join("Cargo.toml").is_file())
}

/// Which trait declarations a cross-file rule may report, derived from the
/// rule's `files` / `ignores` globs and `skip_test_code`. Applied to the
/// declaration site only: impls are counted wherever they are found.
pub struct DeclFilter {
    pub files: Option<GlobSet>,
    pub ignores: Option<GlobSet>,
    pub skip_test_code: bool,
    pub(crate) test_paths: TestPaths,
}

impl DeclFilter {
    /// Whether a declaration found at `path` is in scope for the rule.
    pub fn allows(&self, path: &Path, decl: &TraitDecl) -> bool {
        if !self.files.as_ref().is_none_or(|g| g.is_match(path)) {
            return false;
        }
        if self.ignores.as_ref().is_some_and(|g| g.is_match(path)) {
            return false;
        }
        if self.skip_test_code && (self.test_paths.is_test(path) || decl.in_cfg_test) {
            return false;
        }
        true
    }

    /// Whether an error-message literal found at `path` is in scope for the rule.
    /// Same globs and `skip_test_code` policy as [`DeclFilter::allows`].
    pub fn allows_message(&self, path: &Path, msg: &ErrorMessageLit) -> bool {
        if !self.files.as_ref().is_none_or(|g| g.is_match(path)) {
            return false;
        }
        if self.ignores.as_ref().is_some_and(|g| g.is_match(path)) {
            return false;
        }
        if self.skip_test_code && (self.test_paths.is_test(path) || msg.in_cfg_test) {
            return false;
        }
        true
    }
}

/// Evaluate one cross-file rule against the project index.
///
/// `single_impl_trait` fires for a trait with exactly one declaration, exactly
/// one concrete impl and no blanket impl. Zero impls stays silent: the trait is
/// probably implemented outside this crate. Two or more is a legitimate
/// abstraction. A blanket impl covers a whole family of types, so it is never
/// an over-abstraction. A name declared twice is ambiguous and abstains. An
/// impl for a type that is not a struct, enum or union of the trait's own
/// crate is an extension trait (`impl VersionExt for semver::Version`, or a
/// type from a sibling workspace crate): Rust only allows inherent methods in
/// the type's crate, so the trait is the only way to add them and stays silent.
///
/// The returned order follows `HashMap` iteration and is not stable; the caller
/// (`normalize_findings`) sorts and dedups before the result is reported.
pub fn evaluate(
    rule: &Rule,
    kind: CrossFileKind,
    index: &SymbolIndex,
    filter: &DeclFilter,
) -> Vec<Finding> {
    match kind {
        CrossFileKind::SingleImplTrait => index
            .traits
            .values()
            .filter(|entry| entry.decls.len() == 1 && entry.blanket_impls == 0)
            .filter_map(
                |entry| match (entry.decls.first(), entry.concrete_impls.as_slice()) {
                    (Some(decl), [only]) if index.declares_local_type(only, &decl.0) => Some(decl),
                    _ => None,
                },
            )
            .filter(|(path, decl)| filter.allows(path, decl))
            .map(|(path, decl)| Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone(),
                category: rule.category.clone().unwrap_or_default(),
                message: rule.message.clone(),
                note: rule.note.clone(),
                fix: rule.fix.clone(),
                file: path.clone(),
                line: decl.line,
                column: decl.column,
                end_line: decl.end_line,
                end_column: decl.end_column,
                matched_text: decl.header.clone(),
                confidence: None,
                escalated: false,
            })
            .collect(),
        CrossFileKind::DuplicateErrorMessage => index
            .error_messages
            .values()
            .flat_map(|occurrences| {
                let in_scope: Vec<&(PathBuf, ErrorMessageLit)> = occurrences
                    .iter()
                    .filter(|(path, msg)| filter.allows_message(path, msg))
                    .collect();
                let distinct_files: HashSet<&Path> =
                    in_scope.iter().map(|(path, _)| path.as_path()).collect();
                if distinct_files.len() < 2 {
                    return Vec::new();
                }
                in_scope
                    .into_iter()
                    .map(|(path, msg)| Finding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        category: rule.category.clone().unwrap_or_default(),
                        message: rule.message.clone(),
                        note: rule.note.clone(),
                        fix: rule.fix.clone(),
                        file: path.clone(),
                        line: msg.line,
                        column: msg.column,
                        end_line: msg.end_line,
                        end_column: msg.end_column,
                        matched_text: msg.text.clone(),
                        confidence: None,
                        escalated: false,
                    })
                    .collect()
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
