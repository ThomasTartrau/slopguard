use std::fs::{create_dir_all, write};

use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use globset::{Glob, GlobSetBuilder};
use tempfile::tempdir;

use super::*;
use crate::rule::parse_rule;

fn symbols(source: &str) -> FileSymbols {
    let root = SupportLang::Rust.ast_grep(source);
    let cfg_test = CfgTestRanges::from_root(&root);
    extract_rust_symbols(&root, &cfg_test)
}

/// The calls of every recorded unasserted test, in source order.
fn unasserted(source: &str) -> Vec<Vec<String>> {
    symbols(source)
        .unasserted_tests
        .into_iter()
        .map(|t| t.calls)
        .collect()
}

fn globs(patterns: &[&str]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).unwrap());
    }
    builder.build().unwrap()
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

fn rule() -> Rule {
    parse_rule(
        r#"
id: no-assertion-free-test
language: rust
severity: warning
category: correctness
cross_file: assertion_free_test
message: "Test function with no assertion."
"#,
    )
    .unwrap()
}

/// Evaluate the rule over `(path, source)` files, returning the reported
/// `(path, line)` pairs.
fn report(files: &[(&str, &str)], filter: &DeclFilter) -> Vec<(String, usize)> {
    let contributions: Vec<(PathBuf, FileSymbols)> = files
        .iter()
        .map(|(path, source)| (PathBuf::from(path), symbols(source)))
        .collect();
    let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
    let mut found: Vec<(String, usize)> =
        evaluate(&rule(), CrossFileKind::AssertionFreeTest, &index, filter)
            .into_iter()
            .map(|f| (f.file.display().to_string(), f.line))
            .collect();
    found.sort();
    found
}

// --- extraction: what counts as a test, and as an assertion ---

#[test]
fn test_without_assertion_is_recorded_with_its_calls() {
    let found = symbols("#[test]\nfn t() {\n    let x = compute();\n}\n");
    assert_eq!(found.unasserted_tests.len(), 1);
    let test = &found.unasserted_tests[0];
    assert_eq!(test.calls, vec!["compute"]);
    assert_eq!((test.line, test.column), (2, 1));
    assert_eq!((test.end_line, test.end_column), (4, 2));
    assert_eq!(test.text, "fn t() {\n    let x = compute();\n}");
}

#[test]
fn calls_are_sorted_and_deduplicated() {
    let calls = unasserted("#[test]\nfn t() {\n    setup();\n    run();\n    setup();\n}\n");
    assert_eq!(calls, vec![vec!["run", "setup"]]);
}

#[test]
fn stacked_attributes_and_comments_still_mark_a_test() {
    let source = "#[tokio::test(flavor = \"multi_thread\")]\n#[ignore]\n// slow\nasync fn t() {\n    run().await;\n}\n";
    assert_eq!(unasserted(source), vec![vec!["run"]]);
}

#[test]
fn assertion_macro_is_an_assertion() {
    assert!(unasserted("#[test]\nfn t() {\n    assert_eq!(compute(), 42);\n}\n").is_empty());
}

#[test]
fn should_panic_test_is_not_recorded() {
    assert!(unasserted("#[test]\n#[should_panic]\nfn t() {\n    do_bad_thing();\n}\n").is_empty());
}

#[test]
fn question_mark_is_an_assertion() {
    let source = "#[test]\nfn t() -> Result<(), Error> {\n    let x = compute()?;\n    Ok(())\n}\n";
    assert!(unasserted(source).is_empty());
}

#[test]
fn panicking_accessors_are_assertions() {
    for call in [
        "unwrap()",
        "expect(\"x\")",
        "unwrap_err()",
        "expect_err(\"x\")",
    ] {
        let source = format!("#[test]\nfn t() {{\n    compute().{call};\n}}\n");
        assert!(unasserted(&source).is_empty(), "{call} should count");
    }
}

#[test]
fn unwrap_or_is_not_an_assertion() {
    let calls = unasserted("#[test]\nfn t() {\n    compute().unwrap_or(0);\n}\n");
    assert_eq!(calls, vec![vec!["compute", "unwrap_or"]]);
}

#[test]
fn inline_snapshot_is_an_assertion() {
    let source = "#[cargo_test]\nfn t() {\n    p.cargo(\"build\").with_stderr_data(str![[r#\"[FINISHED]\"#]]).run();\n}\n";
    assert!(unasserted(source).is_empty());
}

#[test]
fn attribute_of_the_previous_item_does_not_mark_a_test() {
    let found =
        symbols("#[test]\nfn t() {\n    assert!(ok());\n}\n\nfn helper() {\n    setup();\n}\n");
    assert!(found.unasserted_tests.is_empty());
    assert_eq!(found.helpers.len(), 1);
    assert_eq!(found.helpers[0].name, "helper");
    assert_eq!(found.helpers[0].calls, vec!["setup"]);
    assert!(!found.helpers[0].asserts);
}

#[test]
fn cfg_test_is_not_a_test_attribute() {
    let found = symbols("#[cfg(test)]\nfn helper() {\n    setup();\n}\n");
    assert!(found.unasserted_tests.is_empty());
    assert_eq!(found.helpers.len(), 1);
    assert!(found.helpers[0].in_cfg_test);
}

#[test]
fn test_named_attribute_paths_count() {
    for attribute in ["#[test]", "#[tokio::test]", "#[cargo_test]", "#[ rstest ]"] {
        let source = format!("{attribute}\nfn t() {{\n    run();\n}}\n");
        assert_eq!(
            unasserted(&source).len(),
            1,
            "{attribute} should mark a test"
        );
    }
    let derive = symbols("#[derive(Test)]\nfn t() {\n    run();\n}\n");
    assert!(derive.unasserted_tests.is_empty());
}

#[test]
fn every_call_shape_is_collected() {
    let source = r#"#[test]
fn t() {
    check(1);
    a::b::scoped(2);
    obj.method(3);
    generic::<u8>(4);
    my_macro!(inner_call(5), nested!(x));
}
"#;
    assert_eq!(
        unasserted(source),
        vec![vec![
            "check",
            "generic",
            "inner_call",
            "method",
            "my_macro",
            "nested",
            "scoped"
        ]]
    );
}

#[test]
fn compile_only_tests_are_not_recorded() {
    let items = "#[test]\nfn t() {\n    #[derive(Serialize)]\n    struct S;\n    impl S {}\n}\n";
    let typed = "#[test]\nfn t() {\n    let _: Router<()> = get(ok).head(ok);\n}\n";
    assert!(unasserted(items).is_empty());
    assert!(unasserted(typed).is_empty());
}

#[test]
fn empty_and_untyped_discard_tests_are_recorded() {
    assert_eq!(
        unasserted("#[test]\nfn t() {}\n"),
        vec![Vec::<String>::new()]
    );
    assert_eq!(
        unasserted("#[test]\nfn t() {\n    let _ = build();\n}\n"),
        vec![vec!["build"]]
    );
}

#[test]
fn macro_definition_is_a_helper() {
    let found =
        symbols("macro_rules! check {\n    ($x:expr) => {\n        verify($x);\n        assert!($x);\n    };\n}\n");
    assert_eq!(found.helpers.len(), 1);
    assert_eq!(found.helpers[0].name, "check");
    assert!(found.helpers[0].asserts);
    // Token trees are not parsed: `name!` and `name(..)` both read as calls.
    assert_eq!(found.helpers[0].calls, vec!["assert", "verify"]);
}

#[test]
fn function_that_calls_nothing_and_asserts_nothing_is_not_kept() {
    assert!(symbols("fn noop() {}\n").helpers.is_empty());
}

// --- evaluation: which helpers vouch for a test ---

#[test]
fn test_calling_an_asserting_test_helper_is_silent() {
    let source = "#[cfg(test)]\nmod tests {\n    fn check(x: u8) {\n        assert_eq!(x, 1);\n    }\n\n    #[test]\n    fn t() {\n        check(1);\n    }\n}\n";
    assert!(report(&[("src/lib.rs", source)], &open_filter()).is_empty());
}

#[test]
fn test_calling_nothing_that_asserts_is_reported() {
    let source =
        "#[cfg(test)]\nmod tests {\n    fn setup() {\n        init();\n    }\n\n    #[test]\n    fn t() {\n        setup();\n    }\n}\n";
    assert_eq!(
        report(&[("src/lib.rs", source)], &open_filter()),
        vec![("src/lib.rs".to_string(), 8)]
    );
}

#[test]
fn assertion_reached_through_a_chain_of_helpers_counts() {
    let source = "#[cfg(test)]\nmod tests {\n    fn outer() {\n        middle();\n    }\n    fn middle() {\n        inner();\n    }\n    fn inner() {\n        assert!(true);\n    }\n\n    #[test]\n    fn t() {\n        outer();\n    }\n}\n";
    assert!(report(&[("src/lib.rs", source)], &open_filter()).is_empty());
}

#[test]
fn helper_in_another_test_file_counts() {
    let helper = "pub fn check_output(out: &str) {\n    assert!(out.is_empty());\n}\n";
    let test = "#[test]\nfn t() {\n    common::check_output(\"\");\n}\n";
    let files = [("tests/common/mod.rs", helper), ("tests/cli.rs", test)];
    assert!(report(&files, &open_filter()).is_empty());
}

#[test]
fn production_function_with_an_assert_does_not_vouch() {
    let production =
        "pub fn new(cap: usize) -> Pool {\n    assert!(cap > 0);\n    Pool { cap }\n}\n";
    let test = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        new(1);\n    }\n}\n";
    let files = [("src/pool.rs", production), ("src/pool_user.rs", test)];
    assert_eq!(
        report(&files, &open_filter()),
        vec![("src/pool_user.rs".to_string(), 4)]
    );
}

#[test]
fn configured_assert_function_silences_the_test() {
    let test = "#[test]\nfn t() {\n    p.cargo(\"build\").run();\n    check_output();\n}\n";
    let run = DeclFilter {
        assert_functions: Some(globs(&["run"])),
        ..open_filter()
    };
    let wildcard = DeclFilter {
        assert_functions: Some(globs(&["check_*"])),
        ..open_filter()
    };
    let unrelated = DeclFilter {
        assert_functions: Some(globs(&["verify_*"])),
        ..open_filter()
    };
    assert!(report(&[("tests/build.rs", test)], &run).is_empty());
    assert!(report(&[("tests/build.rs", test)], &wildcard).is_empty());
    assert_eq!(report(&[("tests/build.rs", test)], &unrelated).len(), 1);
}

#[test]
fn helper_calling_a_configured_function_asserts() {
    let helper = "#[cfg(test)]\nfn build_ok() {\n    cmd().run();\n}\n";
    let test =
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        build_ok();\n    }\n}\n";
    let filter = DeclFilter {
        assert_functions: Some(globs(&["run"])),
        ..open_filter()
    };
    assert!(report(&[("src/a.rs", helper), ("src/b.rs", test)], &filter).is_empty());
}

#[test]
fn ignored_path_is_not_reported() {
    let test = "#[test]\nfn t() {}\n";
    let filter = DeclFilter {
        ignores: Some(globs(&["**/tests/ui/**"])),
        ..open_filter()
    };
    assert!(report(&[("crate/tests/ui/bad.rs", test)], &filter).is_empty());
    assert_eq!(report(&[("crate/tests/it.rs", test)], &filter).len(), 1);
}

// --- test-support crates ---

/// A workspace where `support` is pulled in by `app` as a dev-dependency (via
/// `[workspace.dependencies]`), and optionally by `tool` as a normal one.
fn workspace(support_ships: bool) -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\", \"support\", \"tool\"]\n\n[workspace.dependencies]\nsupport = { path = \"support\" }\n",
    )
    .unwrap();
    for member in ["app", "support", "tool"] {
        create_dir_all(root.join(member).join("src")).unwrap();
    }
    write(
        root.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\n\n[dev-dependencies]\nsupport.workspace = true\n",
    )
    .unwrap();
    write(
        root.join("support/Cargo.toml"),
        "[package]\nname = \"support\"\n",
    )
    .unwrap();
    let tool_deps = if support_ships {
        "[dependencies]\nsupport = { path = \"../support\" }\n"
    } else {
        ""
    };
    write(
        root.join("tool/Cargo.toml"),
        format!("[package]\nname = \"tool\"\n\n{tool_deps}"),
    )
    .unwrap();
    write(
        root.join("support/src/lib.rs"),
        "pub fn run(&self) {\n    if self.failed() {\n        panic!(\"command failed\");\n    }\n}\n",
    )
    .unwrap();
    write(
        root.join("app/src/lib.rs"),
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        project().run();\n    }\n}\n",
    )
    .unwrap();
    // Contributes no helper and no test: only its manifest matters.
    write(root.join("tool/src/lib.rs"), "pub struct Tool;\n").unwrap();
    dir
}

fn report_workspace(dir: &Path) -> Vec<(String, usize)> {
    let members = ["support/src/lib.rs", "app/src/lib.rs", "tool/src/lib.rs"];
    let files: Vec<(String, String)> = members
        .iter()
        .map(|rel| {
            let path = dir.join(rel);
            let source = std::fs::read_to_string(&path).unwrap();
            (path.display().to_string(), source)
        })
        .collect();
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, s)| (p.as_str(), s.as_str()))
        .collect();
    report(&borrowed, &open_filter())
}

#[test]
fn dev_dependency_crate_is_test_support() {
    let dir = workspace(false);
    assert!(report_workspace(dir.path()).is_empty());
}

#[test]
fn crate_that_is_also_a_normal_dependency_is_not_test_support() {
    let dir = workspace(true);
    let found = report_workspace(dir.path());
    assert_eq!(found.len(), 1, "got: {found:?}");
    assert!(found[0].0.ends_with("app/src/lib.rs"));
}
