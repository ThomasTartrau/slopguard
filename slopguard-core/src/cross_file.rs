//! Project-wide analyses that no single file can answer.
//!
//! The per-file scan contributes a [`FileSymbols`] for every file it parses.
//! Those contributions are assembled into a [`SymbolIndex`] once the whole walk
//! is done, and each active cross-file rule is evaluated against that index.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ast_grep_core::{AstGrep, Doc, Node};
use globset::GlobSet;
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::finding::Finding;
use crate::rule::Rule;
use crate::test_filter::{is_test_path, CfgTestRanges};

/// Cross-file analyses a rule can request. Builtin only: a custom YAML may
/// tune an existing kind's severity or message, never invent a new one, so an
/// unknown discriminant is a parse error.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CrossFileKind {
    SingleImplTrait,
}

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
}

impl FileSymbols {
    /// Whether this file declares or implements nothing the index cares about.
    pub fn is_empty(&self) -> bool {
        self.traits.is_empty() && self.impls.is_empty()
    }
}

/// The bare name a trait reference resolves to: the last path segment with any
/// generic arguments stripped. `fmt::Display` -> `Display`, `From<u32>` ->
/// `From`, `crate::db::Repo` -> `Repo`. Matching is by bare name, not by a
/// real Rust path resolver.
fn bare_trait_name(text: &str) -> String {
    let base = text.split('<').next().unwrap_or(text);
    base.rsplit("::").next().unwrap_or(base).trim().to_string()
}

/// The names of an impl's own generic parameters, used to recognise a blanket
/// impl. Lifetimes and const parameters are skipped: only a plain type
/// parameter can be the implementing type of a blanket impl.
fn generic_param_names<D: Doc>(impl_node: &Node<D>) -> Vec<String> {
    let Some(params) = impl_node.field("type_parameters") else {
        return Vec::new();
    };
    params
        .children()
        .filter(|child| child.is_named())
        .filter_map(|child| {
            let text = child.text().to_string();
            // `T: Clone` and `T = u32` keep their head; `'a` and
            // `const N: usize` do not survive the shape check below.
            let head = text
                .split([':', '=', '<'])
                .next()
                .unwrap_or(&text)
                .trim()
                .to_string();
            let starts_ok = head.starts_with(|c: char| c.is_alphabetic() || c == '_');
            let rest_ok = head.chars().all(|c| c.is_alphanumeric() || c == '_');
            (starts_ok && rest_ok).then_some(head)
        })
        .collect()
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
                });
            }
            _ => {}
        }
    }
    symbols
}

/// Project-wide symbol index assembled from every scanned file.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    traits: HashMap<String, TraitEntry>,
}

#[derive(Debug, Default)]
struct TraitEntry {
    /// Every declaration seen for this name. More than one makes the name
    /// ambiguous and the trait is never reported.
    decls: Vec<(PathBuf, TraitDecl)>,
    concrete_impls: usize,
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
                    entry.concrete_impls += 1;
                }
            }
        }
        Self { traits }
    }
}

/// Which trait declarations a cross-file rule may report, derived from the
/// rule's `files` / `ignores` globs and `skip_test_code`. Applied to the
/// declaration site only: impls are counted wherever they are found.
pub struct DeclFilter {
    pub files: Option<GlobSet>,
    pub ignores: Option<GlobSet>,
    pub skip_test_code: bool,
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
        if self.skip_test_code && (is_test_path(path) || decl.in_cfg_test) {
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
/// an over-abstraction. A name declared twice is ambiguous and abstains.
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
            .filter(|entry| {
                entry.decls.len() == 1 && entry.concrete_impls == 1 && entry.blanket_impls == 0
            })
            .filter_map(|entry| entry.decls.first())
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
    }
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    use super::*;
    use crate::rule::parse_rule;

    fn symbols(source: &str) -> FileSymbols {
        let root = SupportLang::Rust.ast_grep(source);
        let cfg_test = CfgTestRanges::from_root(&root);
        extract_rust_symbols(&root, &cfg_test)
    }

    #[test]
    fn extracts_trait_declaration() {
        let found = symbols("pub trait Repository {\n    fn get(&self);\n}\n");
        assert_eq!(found.traits.len(), 1);
        let decl = &found.traits[0];
        assert_eq!(decl.name, "Repository");
        assert_eq!(decl.line, 1);
        assert_eq!(decl.column, 1);
        assert_eq!(decl.header, "pub trait Repository");
        assert!(!decl.in_cfg_test);
    }

    #[test]
    fn extracts_impl_trait_for_type() {
        let found = symbols("impl Repository for Postgres {\n    fn get(&self) {}\n}\n");
        assert_eq!(found.impls.len(), 1);
        assert_eq!(found.impls[0].trait_name, "Repository");
        assert!(!found.impls[0].blanket);
    }

    #[test]
    fn inherent_impl_contributes_nothing() {
        let found = symbols("impl Foo {\n    fn a(&self) {}\n}\n");
        assert!(found.impls.is_empty());
    }

    #[test]
    fn scoped_trait_name_resolves_to_last_segment() {
        let found = symbols("impl fmt::Display for X {}\n");
        assert_eq!(found.impls[0].trait_name, "Display");
    }

    #[test]
    fn generic_trait_name_strips_arguments() {
        let found = symbols("impl From<u32> for X {}\n");
        assert_eq!(found.impls[0].trait_name, "From");
    }

    #[test]
    fn blanket_impl_detected() {
        let found = symbols("impl<T> Describe for T {}\n");
        assert_eq!(found.impls.len(), 1);
        assert!(found.impls[0].blanket);
    }

    #[test]
    fn generic_impl_on_concrete_type_is_not_blanket() {
        let found = symbols("impl<T: Clone> Describe for Wrapper<T> {}\n");
        assert_eq!(found.impls.len(), 1);
        assert!(!found.impls[0].blanket);
    }

    #[test]
    fn lifetime_and_const_params_are_not_blanket() {
        let lifetime = symbols("impl<'a> Foo for &'a Bar {}\n");
        assert_eq!(lifetime.impls.len(), 1);
        assert!(!lifetime.impls[0].blanket);

        let konst = symbols("impl<const N: usize> Foo for [u8; N] {}\n");
        assert_eq!(konst.impls.len(), 1);
        assert!(!konst.impls[0].blanket);
    }

    #[test]
    fn derive_is_not_an_impl() {
        let found = symbols("#[derive(Clone)]\nstruct S;\n");
        assert!(found.impls.is_empty());
        assert!(found.is_empty());
    }

    #[test]
    fn trait_in_cfg_test_is_flagged() {
        let found = symbols("#[cfg(test)]\nmod tests {\n    trait Mockable {}\n}\n");
        assert_eq!(found.traits.len(), 1);
        assert!(found.traits[0].in_cfg_test);
    }

    fn single_impl_rule() -> Rule {
        parse_rule(
            r#"
id: no-single-impl-trait
language: rust
severity: warning
category: slop
cross_file: single_impl_trait
message: "Trait with a single implementation in the project."
"#,
        )
        .unwrap()
    }

    fn decl(name: &str) -> TraitDecl {
        TraitDecl {
            name: name.to_string(),
            line: 3,
            column: 1,
            end_line: 3,
            end_column: 20,
            in_cfg_test: false,
            header: format!("pub trait {name}"),
        }
    }

    fn concrete(name: &str) -> TraitImpl {
        TraitImpl {
            trait_name: name.to_string(),
            blanket: false,
        }
    }

    fn open_filter() -> DeclFilter {
        DeclFilter {
            files: None,
            ignores: None,
            skip_test_code: false,
        }
    }

    fn contribution(
        path: &str,
        traits: Vec<TraitDecl>,
        impls: Vec<TraitImpl>,
    ) -> (PathBuf, FileSymbols) {
        (PathBuf::from(path), FileSymbols { traits, impls })
    }

    /// Evaluate `single_impl_trait` over hand-written per-file contributions.
    fn findings(contributions: &[(PathBuf, FileSymbols)], filter: &DeclFilter) -> Vec<Finding> {
        let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
        evaluate(
            &single_impl_rule(),
            CrossFileKind::SingleImplTrait,
            &index,
            filter,
        )
    }

    #[test]
    fn single_concrete_impl_fires() {
        let contributions = [
            contribution("src/repo.rs", vec![decl("Repository")], vec![]),
            contribution("src/pg.rs", vec![], vec![concrete("Repository")]),
        ];
        assert_eq!(findings(&contributions, &open_filter()).len(), 1);
    }

    #[test]
    fn zero_impls_stays_silent() {
        let contributions = [contribution(
            "src/repo.rs",
            vec![decl("Repository")],
            vec![],
        )];
        assert!(findings(&contributions, &open_filter()).is_empty());
    }

    #[test]
    fn two_impls_stay_silent() {
        let contributions = [
            contribution("src/repo.rs", vec![decl("Repository")], vec![]),
            contribution("src/pg.rs", vec![], vec![concrete("Repository")]),
            contribution("src/mem.rs", vec![], vec![concrete("Repository")]),
        ];
        assert!(findings(&contributions, &open_filter()).is_empty());
    }

    #[test]
    fn blanket_impl_stays_silent() {
        let blanket = TraitImpl {
            trait_name: "Describe".to_string(),
            blanket: true,
        };
        let contributions = [
            contribution("src/describe.rs", vec![decl("Describe")], vec![blanket]),
            contribution("src/pg.rs", vec![], vec![concrete("Describe")]),
        ];
        assert!(findings(&contributions, &open_filter()).is_empty());
    }

    #[test]
    fn duplicate_trait_name_stays_silent() {
        let contributions = [
            contribution("src/a.rs", vec![decl("Repository")], vec![]),
            contribution("src/b.rs", vec![decl("Repository")], vec![]),
            contribution("src/pg.rs", vec![], vec![concrete("Repository")]),
        ];
        assert!(findings(&contributions, &open_filter()).is_empty());
    }

    #[test]
    fn impl_without_local_declaration_is_ignored() {
        let contributions = [contribution(
            "src/pg.rs",
            vec![],
            vec![concrete("Serialize")],
        )];
        assert!(findings(&contributions, &open_filter()).is_empty());
    }

    #[test]
    fn decl_filter_drops_test_path_declaration() {
        let contributions = [
            contribution("tests/support.rs", vec![decl("Repository")], vec![]),
            contribution("src/pg.rs", vec![], vec![concrete("Repository")]),
        ];
        assert_eq!(findings(&contributions, &open_filter()).len(), 1);

        let skipping = DeclFilter {
            files: None,
            ignores: None,
            skip_test_code: true,
        };
        assert!(findings(&contributions, &skipping).is_empty());
    }

    #[test]
    fn finding_points_at_the_declaration() {
        let contributions = [
            contribution("src/repo.rs", vec![decl("Repository")], vec![]),
            contribution("src/pg.rs", vec![], vec![concrete("Repository")]),
        ];
        let found = findings(&contributions, &open_filter());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, PathBuf::from("src/repo.rs"));
        assert_eq!(found[0].line, 3);
        assert_eq!(found[0].matched_text, "pub trait Repository");
    }
}
