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
    assert!(found.traits.is_empty());
    assert_eq!(found.types, vec!["S"]);
}

#[test]
fn trait_in_cfg_test_is_flagged() {
    let found = symbols("#[cfg(test)]\nmod tests {\n    trait Mockable {}\n}\n");
    assert_eq!(found.traits.len(), 1);
    assert!(found.traits[0].in_cfg_test);
}

// --- duplicate_error_message ---

fn dup_rule() -> Rule {
    parse_rule(
        r#"
id: no-duplicate-error-message
language: rust
severity: warning
category: slop
cross_file: duplicate_error_message
message: "Same error message literal in more than one file."
"#,
    )
    .unwrap()
}

fn dup_findings(contributions: &[(PathBuf, FileSymbols)], filter: &DeclFilter) -> Vec<Finding> {
    let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
    evaluate(
        &dup_rule(),
        CrossFileKind::DuplicateErrorMessage,
        &index,
        filter,
    )
}

fn errmsgs(source: &str) -> Vec<ErrorMessageLit> {
    symbols(source).error_messages
}

fn with_msgs(path: &str, msgs: Vec<ErrorMessageLit>) -> (PathBuf, FileSymbols) {
    (
        PathBuf::from(path),
        FileSymbols {
            error_messages: msgs,
            ..Default::default()
        },
    )
}

#[test]
fn extracts_bail_message() {
    let found = errmsgs(r#"fn f() -> Result<()> { bail!("the widget failed to load"); }"#);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "the widget failed to load");
}

#[test]
fn extracts_scoped_anyhow_message() {
    let found = errmsgs(r#"fn f() { let e = anyhow::anyhow!("could not open the file"); }"#);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "could not open the file");
}

// Benchmark regression (tokio, cargo): a panic prints its own file:line, so
// its message is an invariant note, not an error value to deduplicate.
#[test]
fn location_bearing_panic_messages_are_ignored() {
    let found = errmsgs(
        r#"fn f() {
            panic!("the widget failed to load");
            unreachable!("unexpected command {}", cmd);
            let x = do_it().expect("could not open the file");
        }"#,
    );
    assert!(found.is_empty(), "got: {found:?}");
}

#[test]
fn short_message_is_ignored() {
    assert!(errmsgs(r#"fn f() { bail!("nope"); }"#).is_empty());
}

#[test]
fn non_error_string_is_ignored() {
    assert!(errmsgs(r#"fn f() { let name = "a long plain configuration string"; }"#).is_empty());
}

#[test]
fn same_message_in_two_files_fires_per_occurrence() {
    let msg = errmsgs(r#"fn a() { bail!("an unexpected error occurred"); }"#);
    let contributions = [
        with_msgs("src/a.rs", msg.clone()),
        with_msgs("src/b.rs", msg),
    ];
    let found = dup_findings(&contributions, &open_filter());
    assert_eq!(found.len(), 2, "got: {found:?}");
    assert_eq!(found[0].rule_id.as_str(), "no-duplicate-error-message");
}

#[test]
fn message_in_one_file_stays_silent() {
    let mut msg = errmsgs(r#"fn a() { bail!("an unexpected error occurred"); }"#);
    // Same literal twice, but in a single file: not a cross-file duplicate.
    msg.push(msg[0].clone());
    let contributions = [with_msgs("src/a.rs", msg)];
    assert!(dup_findings(&contributions, &open_filter()).is_empty());
}

#[test]
fn distinct_messages_stay_silent() {
    let contributions = [
        with_msgs(
            "src/a.rs",
            errmsgs(r#"fn a() { bail!("the widget failed to load"); }"#),
        ),
        with_msgs(
            "src/b.rs",
            errmsgs(r#"fn b() { bail!("the gadget failed to save"); }"#),
        ),
    ];
    assert!(dup_findings(&contributions, &open_filter()).is_empty());
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

/// The implementing type every `contribution` declares, so `concrete` impls
/// target a project type unless a test says otherwise.
const LOCAL_TYPE: &str = "PostgresRepository";

fn concrete(name: &str) -> TraitImpl {
    TraitImpl {
        trait_name: name.to_string(),
        blanket: false,
        self_type: LOCAL_TYPE.to_string(),
    }
}

fn open_filter() -> DeclFilter {
    DeclFilter {
        files: None,
        ignores: None,
        skip_test_code: false,
        test_paths: TestPaths::default(),
        assert_functions: None,
    }
}

fn contribution(
    path: &str,
    traits: Vec<TraitDecl>,
    impls: Vec<TraitImpl>,
) -> (PathBuf, FileSymbols) {
    (
        PathBuf::from(path),
        FileSymbols {
            traits,
            impls,
            types: vec![LOCAL_TYPE.to_string()],
            ..Default::default()
        },
    )
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

// Benchmark regression (cargo, axum, tokio): an extension trait implemented
// once for a foreign type cannot be replaced by inherent methods.
#[test]
fn extension_trait_on_foreign_type_stays_silent() {
    let ext = TraitImpl {
        trait_name: "VersionExt".to_string(),
        blanket: false,
        self_type: "Version".to_string(),
    };
    let contributions = [contribution(
        "src/semver_ext.rs",
        vec![decl("VersionExt")],
        vec![ext],
    )];
    assert!(findings(&contributions, &open_filter()).is_empty());
}

#[test]
fn extracts_implementing_type_and_declared_types() {
    let found = symbols(
        "pub struct Local;\nenum Kind { A }\ntype Alias = u8;\n\
         impl<B> RequestExt for http::Request<B> {}\n\
         impl<'a> Show for &'a mut Local {}\n",
    );
    let self_types: Vec<&str> = found.impls.iter().map(|i| i.self_type.as_str()).collect();
    assert_eq!(self_types, vec!["Request", "Local"]);
    // A type alias cannot take inherent methods (its target may be foreign).
    assert_eq!(found.types, vec!["Local", "Kind"]);
}

// Benchmark regression (axum-extra, tokio-util): the implementing type lives
// in a sibling workspace crate, where the trait's crate cannot add inherent
// methods. The same pair inside one crate still fires.
#[test]
fn extension_trait_on_sibling_crate_type_stays_silent() {
    let workspace = tempfile::tempdir().unwrap();
    for krate in ["ext", "core", "app"] {
        std::fs::create_dir_all(workspace.path().join(krate).join("src")).unwrap();
        std::fs::write(workspace.path().join(krate).join("Cargo.toml"), "").unwrap();
    }
    let file = |krate: &str, name: &str| {
        workspace
            .path()
            .join(krate)
            .join("src")
            .join(name)
            .display()
            .to_string()
    };
    let router_ext = TraitImpl {
        self_type: "Router".to_string(),
        ..concrete("RouterExt")
    };
    let store = TraitImpl {
        self_type: "PgStore".to_string(),
        ..concrete("Store")
    };
    let mut router = contribution(&file("core", "router.rs"), vec![], vec![]);
    router.1.types = vec!["Router".to_string()];
    let mut pg = contribution(&file("app", "pg.rs"), vec![], vec![store]);
    pg.1.types = vec!["PgStore".to_string()];
    let contributions = [
        contribution(
            &file("ext", "lib.rs"),
            vec![decl("RouterExt")],
            vec![router_ext],
        ),
        router,
        contribution(&file("app", "store.rs"), vec![decl("Store")], vec![]),
        pg,
    ];
    let found = findings(&contributions, &open_filter());
    let headers: Vec<&str> = found.iter().map(|f| f.matched_text.as_str()).collect();
    assert_eq!(headers, vec!["pub trait Store"]);
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
        self_type: "T".to_string(),
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
        skip_test_code: true,
        ..open_filter()
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
