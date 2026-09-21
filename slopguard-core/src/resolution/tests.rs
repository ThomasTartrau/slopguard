use std::fs;
use std::path::Path;

use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use tempfile::{tempdir, TempDir};

use super::{evaluate_file, extract_imports, ManifestResolver, ResolutionKind};
use crate::finding::Finding;
use crate::rule::{parse_rule, Language, Rule};

const RUST_RULE: &str = r#"
id: unresolved-import
language: rust
severity: error
category: correctness
resolution: unresolved_import
message: "Unresolved import '$import'."
"#;

const TS_RULE: &str = r#"
id: unresolved-import
language: typescript
severity: error
category: correctness
resolution: unresolved_import
message: "Unresolved import '$import'."
"#;

fn rust_rule() -> Rule {
    parse_rule(RUST_RULE).unwrap()
}

fn ts_rule() -> Rule {
    parse_rule(TS_RULE).unwrap()
}

/// Write `source` to `dir/name` and resolve its imports for `lang`.
fn findings(dir: &Path, name: &str, source: &str, lang: Language, rule: &Rule) -> Vec<Finding> {
    let path = dir.join(name);
    fs::write(&path, source).unwrap();
    let ast_lang = match lang {
        Language::Rust => SupportLang::Rust,
        Language::TypeScript => SupportLang::TypeScript,
    };
    let root = ast_lang.ast_grep(source);
    let imports = extract_imports(&lang, &root);
    let mut manifests = ManifestResolver::new();
    evaluate_file(
        rule,
        ResolutionKind::UnresolvedImport,
        &lang,
        &path,
        &imports,
        &mut manifests,
    )
}

fn specifiers(findings: &[Finding]) -> Vec<String> {
    findings.iter().map(|f| f.matched_text.clone()).collect()
}

fn write_cargo(dir: &Path, body: &str) {
    fs::write(dir.join("Cargo.toml"), body).unwrap();
}

fn write_package_json(dir: &Path, body: &str) {
    fs::write(dir.join("package.json"), body).unwrap();
}

fn project() -> TempDir {
    tempdir().unwrap()
}

// Row 1: a bare TS import of a package absent from package.json is a finding on
// its import line.
#[test]
fn ts_missing_package_is_a_finding() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": { "react": "18" } }"#);
    let found = findings(
        dir.path(),
        "a.ts",
        "import { thing } from \"totally-made-up\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert_eq!(found.len(), 1, "got: {found:?}");
    assert_eq!(found[0].line, 1);
    assert!(found[0].message.contains("totally-made-up"));
}

// Row 2: a bare TS import present in deps/devDeps is not a finding.
#[test]
fn ts_declared_package_resolves() {
    let dir = project();
    write_package_json(
        dir.path(),
        r#"{ "dependencies": { "react": "18" }, "devDependencies": { "vitest": "1" } }"#,
    );
    let found = findings(
        dir.path(),
        "a.ts",
        "import React from \"react\";\nimport { test } from \"vitest\";\nimport sub from \"react/jsx-runtime\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 3: a relative import resolves when the target exists, is a finding when it
// does not.
#[test]
fn ts_relative_import_existing_and_missing() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": {} }"#);
    fs::write(dir.path().join("helper.ts"), "export const x = 1;\n").unwrap();
    fs::create_dir(dir.path().join("mod")).unwrap();
    fs::write(dir.path().join("mod/index.ts"), "export const y = 2;\n").unwrap();

    let found = findings(
        dir.path(),
        "a.ts",
        "import { x } from \"./helper\";\nimport { y } from \"./mod\";\nimport { z } from \"./ghost\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert_eq!(found.len(), 1, "got: {:?}", specifiers(&found));
    assert!(found[0].message.contains("./ghost"));
}

// Row 4: Node builtins, with and without the `node:` prefix, resolve.
#[test]
fn ts_node_builtins_resolve() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": {} }"#);
    let found = findings(
        dir.path(),
        "a.ts",
        "import fs from \"fs\";\nimport { join } from \"node:path\";\nconst os = require(\"os\");\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 5 (negative): a statement-level type-only import is never a finding, even
// when the module is absent from package.json.
#[test]
fn ts_type_only_import_is_ignored() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": {} }"#);
    let found = findings(
        dir.path(),
        "a.ts",
        "import type { Foo } from \"missing-types-pkg\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 6 (negative): a specifier matching a tsconfig `paths` alias resolves.
#[test]
fn ts_tsconfig_alias_resolves() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": {} }"#);
    fs::write(
        dir.path().join("tsconfig.json"),
        r#"{
  // aliases
  "compilerOptions": {
    "paths": {
      "@app/*": ["src/*"],
      "@config": ["src/config.ts"],
    },
  },
}"#,
    )
    .unwrap();
    let found = findings(
        dir.path(),
        "a.ts",
        "import { Button } from \"@app/ui/button\";\nimport cfg from \"@config\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 7: a Rust `use` of a crate absent from Cargo.toml is a finding.
#[test]
fn rust_missing_crate_is_a_finding() {
    let dir = project();
    write_cargo(
        dir.path(),
        "[package]\nname = \"demo\"\n[dependencies]\nserde = \"1\"\n",
    );
    let found = findings(
        dir.path(),
        "a.rs",
        "use made_up_crate::Thing;\n",
        Language::Rust,
        &rust_rule(),
    );
    assert_eq!(found.len(), 1, "got: {:?}", specifiers(&found));
    assert_eq!(found[0].line, 1);
    assert!(found[0].message.contains("made_up_crate"));
}

// Row 8: std family, module keywords and a declared dependency all resolve.
// Hyphenated dependency keys are matched in their `use` form.
#[test]
fn rust_std_keywords_and_deps_resolve() {
    let dir = project();
    write_cargo(
        dir.path(),
        "[package]\nname = \"demo\"\n[dependencies]\nserde = \"1\"\nast-grep-core = \"0.45\"\n",
    );
    let found = findings(
        dir.path(),
        "a.rs",
        "use std::fmt;\nuse core::mem;\nuse alloc::vec::Vec;\nuse crate::foo::Bar;\nuse super::baz;\nuse serde::Serialize;\nuse ast_grep_core::AstGrep;\nuse demo::internal;\n",
        Language::Rust,
        &rust_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 9 (negative workspace): a dependency declared only in the root
// `[workspace.dependencies]` resolves for a member crate.
#[test]
fn rust_workspace_dependency_resolves() {
    let root = project();
    write_cargo(
        root.path(),
        "[workspace]\nmembers = [\"member\"]\n[workspace.dependencies]\ntokio = \"1\"\n",
    );
    let member = root.path().join("member");
    fs::create_dir(&member).unwrap();
    write_cargo(
        &member,
        "[package]\nname = \"member\"\n[dependencies]\ntokio = { workspace = true }\n",
    );
    let src = member.join("src");
    fs::create_dir(&src).unwrap();
    let found = findings(
        &src,
        "lib.rs",
        "use tokio::spawn;\n",
        Language::Rust,
        &rust_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// Row 10: a bare `use foo::...` referencing a module declared in the same file
// resolves.
#[test]
fn rust_local_module_resolves() {
    let dir = project();
    write_cargo(dir.path(), "[package]\nname = \"demo\"\n[dependencies]\n");
    let found = findings(
        dir.path(),
        "a.rs",
        "mod helpers;\nuse helpers::compute;\n",
        Language::Rust,
        &rust_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// No manifest reachable: nothing can be asserted, so no finding.
#[test]
fn no_manifest_reports_nothing() {
    let dir = project();
    let found = findings(
        dir.path(),
        "a.ts",
        "import x from \"whatever\";\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}

// A file with no imports produces no findings.
#[test]
fn empty_file_reports_nothing() {
    let dir = project();
    write_package_json(dir.path(), r#"{ "dependencies": {} }"#);
    let found = findings(
        dir.path(),
        "a.ts",
        "export const x = 1;\n",
        Language::TypeScript,
        &ts_rule(),
    );
    assert!(found.is_empty(), "got: {:?}", specifiers(&found));
}
