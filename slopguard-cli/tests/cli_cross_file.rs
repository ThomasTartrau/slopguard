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
    findings_for(dir, "no-single-impl-trait")
}

/// Findings reported by a single cross-file rule, so unrelated builtins cannot
/// perturb the count.
fn findings_for(dir: &Path, rule: &str) -> Vec<serde_json::Value> {
    let output = slopguard()
        .args([
            "scan",
            "--format",
            "json",
            "--rule",
            rule,
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
fn duplicate_error_message_reports_each_occurrence() {
    let project = fixture_project("dup_error_message");
    let found = findings_for(project.path(), "no-duplicate-error-message");

    assert_eq!(found.len(), 2, "got: {found:?}");
    for finding in &found {
        assert_eq!(finding["rule_id"], "no-duplicate-error-message");
    }
    let files: std::collections::HashSet<&str> =
        found.iter().map(|f| f["file"].as_str().unwrap()).collect();
    assert_eq!(
        files.len(),
        2,
        "occurrences should span two files: {found:?}"
    );
}

#[test]
fn unique_error_message_reports_nothing() {
    let project = fixture_project("unique_error_message");
    assert!(findings_for(project.path(), "no-duplicate-error-message").is_empty());
}

/// Lines of the `no-assertion-free-test` findings for `project`, scanned with
/// the given `slopguard.toml` content.
fn assertion_free_lines(project: &Path, config: &str) -> Vec<u64> {
    let config_path = project.join("slopguard.toml");
    fs::write(&config_path, config).unwrap();
    let output = slopguard()
        .args([
            "scan",
            "--format",
            "json",
            "--no-cache",
            "--rule",
            "no-assertion-free-test",
            "--config",
            config_path.to_str().unwrap(),
            project.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .map(|f| f["line"].as_u64().unwrap())
        .collect()
}

#[test]
fn assertion_free_test_follows_local_helpers() {
    let project = fixture_project("assertion_free");
    // `checks_nothing` and `delegates_to_external_test_support`: the
    // helper-backed and compile-only tests stay silent.
    assert_eq!(assertion_free_lines(project.path(), ""), vec![19, 24]);
}

#[test]
fn assert_functions_option_covers_external_test_support() {
    let project = fixture_project("assertion_free");
    let config = "[rules.options.no-assertion-free-test]\nassert_functions = [\"run_*\"]\n";
    assert_eq!(assertion_free_lines(project.path(), config), vec![19]);
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
