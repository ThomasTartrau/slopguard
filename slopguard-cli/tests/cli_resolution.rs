mod common;

use std::fs::{self, create_dir_all};
use std::path::Path;

use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/resolution");

/// Copy the fixture project `name` into a fresh tempdir.
///
/// Copying matters: `unresolved-import` ignores `**/fixtures/**`, so a scan
/// pointed straight at `tests/fixtures/resolution/...` would report nothing.
fn fixture_project(name: &str) -> TempDir {
    let tmp = tempdir().unwrap();
    copy_dir(&Path::new(FIXTURES_DIR).join(name), tmp.path());
    tmp
}

fn copy_dir(from: &Path, to: &Path) {
    create_dir_all(to).unwrap();
    let entries = fs::read_dir(from)
        .unwrap_or_else(|e| panic!("failed to read fixture dir {}: {e}", from.display()));
    for entry in entries {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// Findings reported by `unresolved-import` alone, so unrelated builtins cannot
/// perturb the count.
fn resolution_findings(path: &str, cache_dir: Option<&str>) -> Vec<Value> {
    let mut args = vec![
        "scan",
        "--format",
        "json",
        "--rule",
        "unresolved-import",
        path,
    ];
    match cache_dir {
        Some(dir) => args.extend_from_slice(&["--cache-dir", dir]),
        None => args.push("--no-cache"),
    }
    let output = slopguard().args(&args).output().unwrap();
    let json: Value = serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .clone()
}

fn mentions(findings: &[Value], specifier: &str) -> bool {
    findings
        .iter()
        .any(|f| f["message"].as_str().unwrap_or("").contains(specifier))
}

/// A TypeScript project in a fresh tempdir: a `package.json` listing `react` and
/// an `index.ts` importing both `react` and a package that does not exist.
fn ts_project() -> TempDir {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "demo", "dependencies": { "react": "18" } }"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("index.ts"),
        "import React from \"react\";\nimport { gone } from \"left-pad-that-is-absent\";\nexport const x = gone(React);\n",
    )
    .unwrap();
    tmp
}

// Row 12: scanning a fixture whose import is not declared yields a finding on
// the hallucinated specifier, and the declared package is left alone.
#[test]
fn scan_reports_hallucinated_import() {
    let project = fixture_project("hallucinated_ts");
    let found = resolution_findings(project.path().to_str().unwrap(), None);

    assert!(!found.is_empty(), "expected a finding, got: {found:?}");
    assert!(
        mentions(&found, "nonexistent-package-xyz"),
        "the missing package should be flagged, got: {found:?}"
    );
    assert!(
        !mentions(&found, "'react'"),
        "react is declared and must not be flagged, got: {found:?}"
    );
    let missing = found
        .iter()
        .find(|f| {
            f["message"]
                .as_str()
                .unwrap()
                .contains("nonexistent-package-xyz")
        })
        .unwrap();
    assert_eq!(missing["line"], 2, "finding anchors on the import line");
}

// Row 13: an inline disable comment silences the resolution finding.
#[test]
fn disable_comment_silences_the_import() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "demo", "dependencies": {} }"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("index.ts"),
        "// slopguard-disable-next-line unresolved-import\nimport { gone } from \"ghost-module\";\nexport const x = gone;\n",
    )
    .unwrap();

    let found = resolution_findings(tmp.path().to_str().unwrap(), None);
    assert!(
        found.is_empty(),
        "disable comment should suppress, got: {found:?}"
    );
}

// Row 14: editing the manifest to declare the dependency clears the finding even
// though the importing file is byte-for-byte unchanged (its imports come from
// the cache; resolution re-runs against the current manifest).
#[test]
fn manifest_edit_clears_finding_under_cache() {
    let project = ts_project();
    let cache = tempdir().unwrap();
    let cache_dir = cache.path().to_str().unwrap();
    let project_path = project.path().to_str().unwrap();

    let before = resolution_findings(project_path, Some(cache_dir));
    assert!(
        mentions(&before, "left-pad-that-is-absent"),
        "first scan should flag the missing package, got: {before:?}"
    );

    // Declare the dependency; leave index.ts untouched so its cache entry is a
    // hit on the second scan.
    fs::write(
        project.path().join("package.json"),
        r#"{ "name": "demo", "dependencies": { "react": "18", "left-pad-that-is-absent": "1" } }"#,
    )
    .unwrap();

    let after = resolution_findings(project_path, Some(cache_dir));
    assert!(
        !mentions(&after, "left-pad-that-is-absent"),
        "declaring the dependency should clear the finding, got: {after:?}"
    );
}

// A path dependency imported under its `[lib] name`, and a package importing its
// own `[lib] name` from `tests/`, are not unresolved.
#[test]
fn renamed_lib_import_is_not_flagged() {
    let project = fixture_project("renamed_lib");
    let found = resolution_findings(project.path().to_str().unwrap(), None);
    assert!(found.is_empty(), "got: {found:?}");
}

// Files under a `fixtures/` directory are test inputs, not part of the build:
// an import that does not resolve there is not reported, in either language,
// while the same import under `src/` still is.
#[test]
fn imports_under_fixtures_are_not_resolved() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("package.json"), r#"{ "name": "demo" }"#).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    for dir in ["src", "tests/fixtures"] {
        create_dir_all(root.join(dir)).unwrap();
    }
    fs::write(
        root.join("src/index.ts"),
        "import { a } from \"ghost-src-ts\";\nexport const x = a;\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "use ghost_src_rs::Item;\n").unwrap();
    fs::write(
        root.join("tests/fixtures/sample.ts"),
        "import { b } from \"ghost-fixture-ts\";\nexport const y = b;\n",
    )
    .unwrap();
    fs::write(
        root.join("tests/fixtures/sample.rs"),
        "use ghost_fixture_rs::Item;\n",
    )
    .unwrap();

    let found = resolution_findings(root.to_str().unwrap(), None);
    for missing in ["ghost-src-ts", "ghost_src_rs"] {
        assert!(
            mentions(&found, missing),
            "{missing} under src/ should be flagged, got: {found:?}"
        );
    }
    for fixture in ["ghost-fixture-ts", "ghost_fixture_rs"] {
        assert!(
            !mentions(&found, fixture),
            "{fixture} under fixtures/ must not be flagged, got: {found:?}"
        );
    }
}
