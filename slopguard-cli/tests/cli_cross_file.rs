mod common;

use std::fs::{self, create_dir_all};
use std::path::Path;

use tempfile::{tempdir, TempDir};

use common::slopguard;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/cross_file");

/// Copy a cross-file fixture project into a fresh tempdir under `src/`.
///
/// Copying matters: a scan pointed straight at `tests/fixtures/cross_file/...`
/// sees a `tests` path component, and `skip_test_code` correctly suppresses the
/// declaration there.
fn fixture_project(name: &str) -> TempDir {
    let tmp = tempdir().unwrap();
    let src = tmp.path().join("src");
    create_dir_all(&src).unwrap();

    let from = Path::new(FIXTURES_DIR).join(name);
    let entries = fs::read_dir(&from)
        .unwrap_or_else(|e| panic!("failed to read fixture dir {}: {e}", from.display()));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap();
        fs::copy(&path, src.join(name)).unwrap();
    }
    tmp
}

/// Findings reported by `no-single-impl-trait` alone, so unrelated builtins
/// cannot perturb the count.
fn findings(dir: &Path) -> Vec<serde_json::Value> {
    let output = slopguard()
        .args([
            "scan",
            "--format",
            "json",
            "--rule",
            "no-single-impl-trait",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .clone()
}

#[test]
fn single_impl_reports_one_finding() {
    let project = fixture_project("single_impl");
    let found = findings(project.path());

    assert_eq!(found.len(), 1, "got: {found:?}");
    assert_eq!(found[0]["rule_id"], "no-single-impl-trait");
    let file = found[0]["file"].as_str().unwrap();
    assert!(
        file.ends_with("trait_def.rs"),
        "the finding should point at the declaration, got: {file}"
    );
}

#[test]
fn two_impls_reports_nothing() {
    let project = fixture_project("two_impls");
    assert!(findings(project.path()).is_empty());
}

#[test]
fn no_impl_reports_nothing() {
    let project = fixture_project("no_impl");
    assert!(findings(project.path()).is_empty());
}

#[test]
fn disable_comment_silences_the_declaration() {
    let project = fixture_project("single_impl");
    let decl = project.path().join("src").join("trait_def.rs");
    let original = fs::read_to_string(&decl).unwrap();
    let suppressed = format!("// slopguard-disable-next-line no-single-impl-trait\n{original}");
    fs::write(&decl, suppressed).unwrap();

    assert!(findings(project.path()).is_empty());
}
