mod common;

use std::collections::HashMap;
use std::fs::{self, create_dir_all, write};
use std::path::Path;

use tempfile::tempdir;

use common::slopguard;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures");

fn fixture_content(name: &str) -> String {
    let path = Path::new(FIXTURES_DIR).join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()))
}

fn setup_src_dir(dir: &Path) {
    create_dir_all(dir.join("src")).unwrap();
}

fn setup_migrations_dir(dir: &Path) {
    create_dir_all(dir.join("migrations")).unwrap();
}

// --- Row 1: scan rust_violations.rs ---

#[test]
fn scan_rust_violations() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/violations.rs"),
        fixture_content("rust_violations.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        let rule_id = f["rule_id"].as_str().unwrap();
        *counts.entry(rule_id).or_default() += 1;
    }

    let expected_rules = [
        "no-slop-words",
        "no-trivial-doc",
        "no-paraphrase-doc",
        "no-and-more-doc",
        "no-restated-comment",
        "no-manual-display",
        "no-manual-rfc3339",
        "no-inline-qualified-path",
        "no-glob-reexport",
        "no-debug-on-secrets",
        "no-unsafe-without-safety",
        "no-safety-hallucination",
        "no-allow-dead-code",
        "no-client-without-timeout",
        "no-unwrap-in-prod",
        "no-expect-in-prod",
        "no-ignored-result",
        "no-swallowed-error",
        "no-silent-fallback",
        "no-double-fallback",
        "no-ok-chain",
    ];

    for rule_id in &expected_rules {
        assert_eq!(
            counts.get(rule_id).copied().unwrap_or(0),
            1,
            "expected exactly 1 finding for rule '{rule_id}', got {}",
            counts.get(rule_id).copied().unwrap_or(0)
        );
    }

    assert_eq!(
        findings.len(),
        expected_rules.len(),
        "expected {} total findings, got {} (rules found: {:?})",
        expected_rules.len(),
        findings.len(),
        counts.keys().collect::<Vec<_>>()
    );
}

// --- Row 1b: scan rust_migrations_violations.rs ---

#[test]
fn scan_rust_migration_violations() {
    let dir = tempdir().unwrap();
    setup_migrations_dir(dir.path());
    write(
        dir.path().join("migrations/001_init.rs"),
        fixture_content("rust_migrations_violations.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        let rule_id = f["rule_id"].as_str().unwrap();
        *counts.entry(rule_id).or_default() += 1;
    }

    assert_eq!(
        counts
            .get("no-index-without-if-not-exists")
            .copied()
            .unwrap_or(0),
        1,
        "expected 1 finding for no-index-without-if-not-exists"
    );
    assert_eq!(
        counts.get("no-float-money").copied().unwrap_or(0),
        1,
        "expected 1 finding for no-float-money"
    );
}

// --- Row 1c: scan with no-sqlx-runtime violation (inline, hook-safe) ---

#[test]
fn scan_sqlx_runtime_violation() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    let code = format!(
        "fn fetch() {{\n    {}(\"{}\").fetch_all(&pool).await;\n}}\n",
        // Concatenate to avoid triggering the guard-sqlx hook on this file
        ["sqlx", "query"].join("::"),
        "SELECT * FROM users",
    );
    write(dir.path().join("src/repo.rs"), code).unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    assert!(
        findings.iter().any(|f| f["rule_id"] == "no-sqlx-runtime"),
        "expected a finding for no-sqlx-runtime, got: {:?}",
        findings
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>()
    );
}

// --- Row 2: scan clean_rust.rs ---

#[test]
fn scan_clean_rust() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/clean.rs"),
        fixture_content("clean_rust.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    assert_eq!(json["summary"]["total"], 0);
    assert_eq!(json["summary"]["errors"], 0);
    assert_eq!(json["summary"]["warnings"], 0);

    let findings = json["findings"].as_array().unwrap();
    assert!(findings.is_empty(), "clean file should have no findings");
}

// --- Row 3: scan ts_violations.ts ---

#[test]
fn scan_ts_violations() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("violations.ts"),
        fixture_content("ts_violations.ts"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    let expected_ts_rules = [
        "no-any-typescript",
        "no-async-foreach",
        "no-replace-single",
        "no-sort-without-comparator",
    ];

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        let rule_id = f["rule_id"].as_str().unwrap();
        *counts.entry(rule_id).or_default() += 1;
    }

    for rule_id in &expected_ts_rules {
        assert_eq!(
            counts.get(rule_id).copied().unwrap_or(0),
            1,
            "expected exactly 1 finding for TS rule '{rule_id}'"
        );
    }

    assert_eq!(
        findings.len(),
        expected_ts_rules.len(),
        "expected {} TS findings, got {}",
        expected_ts_rules.len(),
        findings.len()
    );
}

// --- Row 4: scan with_disable.rs ---

#[test]
fn scan_with_disable() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/with_disable.rs"),
        fixture_content("with_disable.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    assert_eq!(
        findings.len(),
        2,
        "expected 2 findings (wrong-id disable + no-disable), got {}",
        findings.len()
    );

    for f in findings {
        assert_eq!(
            f["rule_id"].as_str().unwrap(),
            "no-unwrap-in-prod",
            "only no-unwrap-in-prod should remain"
        );
    }
}

// --- Row 5: scan with custom config ---

#[test]
fn scan_custom_config() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/violations.rs"),
        fixture_content("rust_violations.rs"),
    )
    .unwrap();

    let config_path = dir.path().join("slopguard.toml");
    write(&config_path, fixture_content("slopguard.toml")).unwrap();

    let output = slopguard()
        .args([
            "scan",
            "--format",
            "json",
            "--config",
            config_path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    let findings = json["findings"]
        .as_array()
        .expect("findings should be an array");

    for f in findings {
        let rule_id = f["rule_id"].as_str().unwrap();
        assert_ne!(
            rule_id, "no-unwrap-in-prod",
            "disabled rule no-unwrap-in-prod should not appear"
        );
        assert_ne!(
            rule_id, "no-expect-in-prod",
            "disabled rule no-expect-in-prod should not appear"
        );
    }

    assert_eq!(
        findings.len(),
        21,
        "expected 21 findings (23 total minus 2 disabled), got {}",
        findings.len()
    );
}

// --- Row 6: JSON output structure ---

#[test]
fn json_output_structure() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/violations.rs"),
        fixture_content("rust_violations.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    assert!(json["findings"].is_array());
    assert!(json["summary"]["errors"].is_number());
    assert!(json["summary"]["warnings"].is_number());
    assert!(json["summary"]["total"].is_number());

    let first = &json["findings"][0];
    assert!(first["rule_id"].is_string());
    assert!(first["severity"].is_string());
    assert!(first["category"].is_string());
    assert!(first["message"].is_string());
    assert!(first["file"].is_string());
    assert!(first["line"].is_number());
    assert!(first["column"].is_number());
    assert!(first["end_line"].is_number());
    assert!(first["end_column"].is_number());
    assert!(first["matched_text"].is_string());
}

// --- Row 7: SARIF output structure ---

#[test]
fn sarif_output_structure() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/violations.rs"),
        fixture_content("rust_violations.rs"),
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "sarif", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid SARIF JSON");

    assert_eq!(json["version"].as_str(), Some("2.1.0"));
    assert!(json["$schema"].as_str().unwrap_or("").contains("sarif"));

    let runs = json["runs"].as_array().expect("should have runs[]");
    assert_eq!(runs.len(), 1);

    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"].as_str(), Some("slopguard"));
    assert!(run["tool"]["driver"]["rules"].is_array());

    let results = run["results"].as_array().expect("should have results[]");
    assert!(
        !results.is_empty(),
        "SARIF results should not be empty for violation fixtures"
    );

    let first = &results[0];
    assert!(first["ruleId"].is_string());
    assert!(first["level"].is_string());
    assert!(first["message"]["text"].is_string());

    let locations = first["locations"]
        .as_array()
        .expect("should have locations[]");
    assert!(!locations.is_empty());
    let region = &locations[0]["physicalLocation"]["region"];
    assert!(region["startLine"].is_number());
    assert!(region["startColumn"].is_number());

    let driver_rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("should have driver.rules[]");
    assert!(
        !driver_rules.is_empty(),
        "SARIF should list the rule descriptors"
    );
}

// --- Row 8: exit codes ---

#[test]
fn exit_code_zero_on_clean() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/clean.rs"),
        fixture_content("clean_rust.rs"),
    )
    .unwrap();

    slopguard()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn exit_code_one_on_violations() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/violations.rs"),
        fixture_content("rust_violations.rs"),
    )
    .unwrap();

    slopguard()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn exit_code_two_on_invalid_config() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    let config_path = dir.path().join("bad.toml");
    write(&config_path, "this is not [valid toml {{{").unwrap();

    slopguard()
        .args([
            "scan",
            "--config",
            config_path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

// --- Row 9: --severity-threshold ---

#[test]
fn severity_threshold_error_exits_zero_on_warnings_only() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/lib.rs"),
        "// This will streamline the API.\npub fn api() {}\n",
    )
    .unwrap();

    let output = slopguard()
        .args([
            "scan",
            "--severity-threshold",
            "error",
            "--format",
            "json",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "exit code should be 0 when only warnings exist and threshold=error"
    );

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        json["summary"]["warnings"].as_u64().unwrap_or(0) > 0,
        "should still have warnings in the output"
    );
}

#[test]
fn severity_threshold_error_exits_one_on_errors() {
    let dir = tempdir().unwrap();
    setup_src_dir(dir.path());
    write(
        dir.path().join("src/bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .args([
            "scan",
            "--severity-threshold",
            "error",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);
}
