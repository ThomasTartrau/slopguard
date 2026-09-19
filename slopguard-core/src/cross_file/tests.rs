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
        test_paths: TestPaths::default(),
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
        test_paths: TestPaths::default(),
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
