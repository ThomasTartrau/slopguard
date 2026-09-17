mod common;

use std::fs::{self, write};

use predicates::prelude::*;
use tempfile::tempdir;

use common::slopguard;

#[test]
fn clean_exit_zero() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    slopguard()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"));
}

#[test]
fn violations_text_output() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .args(["scan", "--no-colors", dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error["))
        .stdout(predicate::str::contains("-->"))
        .stdout(predicate::str::contains("bad.rs:2:"))
        .stdout(predicate::str::contains("unwrap"))
        .stdout(predicate::str::contains("error"));
}

#[test]
fn json_output() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
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
    assert!(!findings.is_empty(), "should have at least one finding");

    let first = &findings[0];
    assert!(first["rule_id"].is_string());
    assert!(first["severity"].is_string());
    assert!(first["message"].is_string());
    assert!(first["file"].is_string());
    assert!(first["line"].is_number());
    assert!(first["column"].is_number());

    let summary = &json["summary"];
    assert!(summary["errors"].is_number());
    assert!(summary["warnings"].is_number());
    assert!(summary["total"].is_number());
}

#[test]
fn sarif_output() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--format", "sarif", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

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
    assert!(!results.is_empty());

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
}

#[test]
fn threshold_error_ignores_warnings() {
    let dir = tempdir().unwrap();
    // no-slop-words fires as a warning on AI filler words in comments
    write(
        dir.path().join("lib.rs"),
        "/// A comprehensive guide to the API.\npub fn api() {}\n",
    )
    .unwrap();

    slopguard()
        .args([
            "scan",
            "--severity-threshold",
            "error",
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("warning"));
}

#[test]
fn invalid_config_exit_two() {
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
        .code(2)
        .stderr(predicate::str::contains("error"));
}

#[test]
fn no_colors_no_ansi() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--no-colors", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("\x1b["),
        "output should not contain ANSI escape codes, got: {stdout}"
    );
    assert!(
        stdout.contains("error["),
        "should still contain diagnostic markers"
    );
}

#[test]
fn custom_config_disables_rule() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let config = dir.path().join("custom.toml");
    write(&config, "[rules]\ndisable = [\"no-unwrap-in-prod\"]\n").unwrap();

    let output = slopguard()
        .args([
            "scan",
            "--config",
            config.to_str().unwrap(),
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("no-unwrap-in-prod"),
        "disabled rule should not appear in output, got: {stdout}"
    );
}

#[test]
fn scan_rule_filter() {
    let dir = tempdir().unwrap();
    // This file triggers both no-unwrap-in-prod (error) and no-expect-in-prod (error)
    write(
        dir.path().join("bad.rs"),
        "fn main() {\n    foo().unwrap();\n    bar().expect(\"boom\");\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .args([
            "scan",
            "--rule",
            "no-unwrap-in-prod",
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("no-unwrap-in-prod"),
        "should contain the filtered rule, got: {stdout}"
    );
    assert!(
        !stdout.contains("no-expect-in-prod"),
        "should NOT contain other rules, got: {stdout}"
    );
}

#[test]
fn scan_rule_unknown_exit_two() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    slopguard()
        .args(["scan", "--rule", "fake-rule", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"));
}

#[test]
fn text_summary_line() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("a.rs"),
        "fn f() {\n    foo().unwrap();\n    bar().unwrap();\n}\n",
    )
    .unwrap();
    write(
        dir.path().join("b.rs"),
        "fn g() {\n    baz().unwrap();\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .args(["scan", "--no-colors", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("3 errors") && stdout.contains("in 2 files"),
        "summary should show correct counts, got: {stdout}"
    );
}

#[test]
fn no_cache_flag() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let output = slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-cache", "--no-colors", "."])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("cached"),
        "--no-cache should not show cache metrics, got: {stdout}"
    );
    assert!(
        !dir.path().join(".slopguard-cache").exists(),
        "--no-cache should not create a cache directory"
    );
}

#[test]
fn cache_metrics_in_output() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    // First scan: all files changed, nothing cached
    let output1 = slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-colors", "."])
        .output()
        .unwrap();

    let stdout1 = String::from_utf8(output1.stdout).unwrap();
    assert!(
        stdout1.contains("0 cached") && stdout1.contains("1 changed"),
        "first scan should show 0 cached and 1 changed, got: {stdout1}"
    );

    // Verify cache directory was created
    assert!(
        dir.path().join(".slopguard-cache").exists(),
        "cache directory should be created after first scan"
    );

    // Second scan: all files cached
    let output2 = slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-colors", "."])
        .output()
        .unwrap();

    let stdout2 = String::from_utf8(output2.stdout).unwrap();
    assert!(
        stdout2.contains("1 cached") && stdout2.contains("0 changed"),
        "second scan should show 1 cached and 0 changed, got: {stdout2}"
    );

    // Modify file, third scan should show changed
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    bar().unwrap();\n    baz().unwrap();\n}\n",
    )
    .unwrap();

    let output3 = slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-colors", "."])
        .output()
        .unwrap();

    let stdout3 = String::from_utf8(output3.stdout).unwrap();
    assert!(
        stdout3.contains("0 cached") && stdout3.contains("1 changed"),
        "third scan after modification should show 0 cached and 1 changed, got: {stdout3}"
    );
}

#[test]
fn cache_dir_flag() {
    let dir = tempdir().unwrap();
    let cache = tempdir().unwrap();
    let cache_path = cache.path().join("custom-cache");
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .args([
            "scan",
            "--cache-dir",
            cache_path.to_str().unwrap(),
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);

    assert!(
        cache_path.exists(),
        "cache directory should be created at the specified path"
    );
    let has_bin = cache_path
        .read_dir()
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".bin"))
        })
        .unwrap_or(false);
    assert!(has_bin, "cache directory should contain .bin files");

    assert!(
        !dir.path().join(".slopguard-cache").exists(),
        "default cache dir should NOT be created when --cache-dir is specified"
    );
}

#[test]
fn cache_dir_priority() {
    let dir = tempdir().unwrap();
    let cli_cache = tempdir().unwrap();
    let cli_path = cli_cache.path().join("cli-wins");
    let env_cache = tempdir().unwrap();
    let env_path = env_cache.path().join("env-cache");
    let toml_cache = tempdir().unwrap();
    let toml_path = toml_cache.path().join("toml-cache");

    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let config = dir.path().join("slopguard.toml");
    write(
        &config,
        format!(
            "[scan]\ncache_dir = \"{}\"\n",
            toml_path.to_str().unwrap().replace('\\', "\\\\")
        ),
    )
    .unwrap();

    slopguard()
        .env("SLOPGUARD_CACHE_DIR", env_path.to_str().unwrap())
        .args([
            "scan",
            "--cache-dir",
            cli_path.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);

    assert!(
        cli_path.exists(),
        "CLI --cache-dir should win over env and TOML"
    );
    assert!(
        !env_path.exists(),
        "env SLOPGUARD_CACHE_DIR should NOT be used when --cache-dir is provided"
    );
    assert!(
        !toml_path.exists(),
        "TOML cache_dir should NOT be used when --cache-dir is provided"
    );
}

#[test]
fn no_cache_ignores_cache_dir() {
    let dir = tempdir().unwrap();
    let cache = tempdir().unwrap();
    let cache_path = cache.path().join("should-not-exist");
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .args([
            "scan",
            "--no-cache",
            "--cache-dir",
            cache_path.to_str().unwrap(),
            "--no-colors",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);

    assert!(
        !cache_path.exists(),
        "cache directory should NOT be created when --no-cache is used"
    );
}

#[test]
fn cache_dir_env() {
    let dir = tempdir().unwrap();
    let cache = tempdir().unwrap();
    let cache_path = cache.path().join("env-cache");
    write(
        dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    slopguard()
        .env("SLOPGUARD_CACHE_DIR", cache_path.to_str().unwrap())
        .args(["scan", "--no-colors", dir.path().to_str().unwrap()])
        .assert()
        .code(1);

    assert!(
        cache_path.exists(),
        "cache directory should be created at SLOPGUARD_CACHE_DIR path"
    );
    let has_bin = cache_path
        .read_dir()
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".bin"))
        })
        .unwrap_or(false);
    assert!(has_bin, "cache directory should contain .bin files");

    assert!(
        !dir.path().join(".slopguard-cache").exists(),
        "default cache dir should NOT be created when SLOPGUARD_CACHE_DIR is set"
    );
}

#[test]
fn cache_gitignore_created() {
    let dir = tempdir().unwrap();
    write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    slopguard()
        .current_dir(dir.path())
        .args(["scan", "--no-colors", "."])
        .assert()
        .success();

    let gitignore = dir.path().join(".slopguard-cache/.gitignore");
    assert!(
        gitignore.exists(),
        ".gitignore should be created in cache dir"
    );
    let content = fs::read_to_string(&gitignore).unwrap();
    assert_eq!(content, "*\n");
}

#[test]
fn scan_reports_file_level_finding() {
    let dir = tempdir().unwrap();
    let big: String = (0..200)
        .map(|i| format!("fn f{i}() {{\n    let _ = {i};\n}}\n"))
        .collect();
    write(dir.path().join("big.rs"), big).unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");
    let findings = json["findings"].as_array().unwrap();

    let file_level = findings
        .iter()
        .find(|f| f["rule_id"] == "max-file-lines")
        .expect("a 600 line file should trigger max-file-lines");

    assert_eq!(file_level["line"], 1, "file-level findings sit on line 1");
    assert_eq!(file_level["column"], 1);
    let matched = file_level["matched_text"].as_str().unwrap();
    assert!(matched.ends_with(" lines"), "got: {matched}");
    assert_eq!(matched, "600 lines");
    let message = file_level["message"].as_str().unwrap();
    assert!(
        message.contains("600 lines"),
        "the measured value should be interpolated, got: {message}"
    );
}

#[test]
fn scan_short_file_has_no_file_level_finding() {
    let dir = tempdir().unwrap();
    let small: String = (0..5)
        .map(|i| format!("fn f{i}() {{\n    let _ = {i};\n}}\n"))
        .collect();
    write(dir.path().join("small.rs"), small).unwrap();

    let output = slopguard()
        .args(["scan", "--format", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "max-file-lines"),
        "a 15 line file must not trigger max-file-lines"
    );
}
