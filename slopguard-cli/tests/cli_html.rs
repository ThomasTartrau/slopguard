mod common;

use std::fs::{read_to_string, write};
use std::path::Path;
use std::process::{Command, Output};

use predicates::prelude::*;
use tempfile::{tempdir, TempDir};

use common::slopguard;

/// Two violations, so the report exercises plural labels and a non-trivial
/// per-rule tally.
const BAD_RS: &str = "fn main() {\n    foo().unwrap();\n    bar().unwrap();\n}\n";
const BAD_TS: &str = "function f(x: any) { return x; }\n";

fn project_with(name: &str, content: &str) -> TempDir {
    let dir = tempdir().unwrap();
    write(dir.path().join(name), content).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Render a report to `<dir>/report.html` and return its contents.
fn report_of(dir: &Path, extra: &[&str]) -> String {
    let path = dir.join("report.html");
    let mut args = vec![
        "scan",
        "--format",
        "html",
        "-o",
        path.to_str().unwrap(),
        ".",
    ];
    args.extend_from_slice(extra);
    slopguard().current_dir(dir).args(&args).output().unwrap();
    read_to_string(&path).expect("the report should have been written")
}

#[test]
fn html_stdout_starts_with_doctype() {
    let dir = project_with("bad.rs", BAD_RS);

    let output = slopguard()
        .args(["scan", "--format", "html", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let out = String::from_utf8(output.stdout).expect("the report should be valid UTF-8");
    assert!(
        out.starts_with("<!DOCTYPE html>"),
        "report should open with the doctype, got: {}",
        &out[..out.len().min(64)]
    );
}

#[test]
fn html_output_flag_writes_file() {
    let dir = project_with("bad.rs", BAD_RS);
    let path = dir.path().join("report.html");

    let output = slopguard()
        .args([
            "scan",
            "--format",
            "html",
            "-o",
            path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "-o should keep stdout empty");

    let report = read_to_string(&path).expect("the report file should exist");
    assert!(report.starts_with("<!DOCTYPE html>"));
    assert!(report.trim_end().ends_with("</html>"));
}

#[test]
fn html_long_output_flag_writes_file() {
    let dir = project_with("bad.rs", BAD_RS);
    let path = dir.path().join("report.html");

    slopguard()
        .args([
            "scan",
            "--format",
            "html",
            "--output",
            path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);

    let report = read_to_string(&path).expect("the report file should exist");
    assert!(report.starts_with("<!DOCTYPE html>"));
}

#[test]
fn html_is_single_file() {
    let dir = project_with("bad.rs", BAD_RS);
    let report = report_of(dir.path(), &[]);

    for needle in ["http://", "https://", "<link ", "fetch("] {
        assert!(
            !report.contains(needle),
            "the report should be self-contained but contains {needle}"
        );
    }
    assert!(report.contains("<style>"));
    assert!(report.contains("<script>"));
}

#[test]
fn html_contains_findings() {
    let dir = project_with("bad.rs", BAD_RS);
    let report = report_of(dir.path(), &[]);

    assert!(report.contains("no-unwrap-in-prod"));
    assert!(report.contains("bad.rs"));
    assert!(report.contains("unwrap"));
}

#[test]
fn html_contains_summary_counts() {
    let dir = project_with("bad.rs", BAD_RS);
    let report = report_of(dir.path(), &[]);

    let error_rows = report.matches("data-severity=\"error\"").count();
    assert!(error_rows >= 2, "both unwrap calls should render as rows");

    let tile = format!("<span class=\"n\">{error_rows}</span><span class=\"l\">errors</span>");
    assert!(report.contains(&tile), "the errors tile should agree");
    assert!(report.contains("files scanned"));
}

#[test]
fn html_escapes_source_code() {
    let dir = project_with(
        "bad.rs",
        "fn main() {\n    foo::<Vec<String>>().unwrap();\n}\n",
    );
    let report = report_of(dir.path(), &[]);

    assert!(report.contains("&lt;"));
    assert!(
        !report.contains("<Vec<String>>"),
        "matched source should be escaped, never emitted raw"
    );
}

#[test]
fn html_clean_project_exits_zero() {
    let dir = project_with("main.rs", "fn main() {}\n");
    let path = dir.path().join("report.html");

    slopguard()
        .args([
            "scan",
            "--format",
            "html",
            "-o",
            path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let report = read_to_string(&path).expect("the report file should exist");
    assert!(report.starts_with("<!DOCTYPE html>"));
    assert!(report.contains("No findings."));
}

#[test]
fn html_mentions_baseline_in_header() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["baseline", "."])
        .assert()
        .success();

    let report = report_of(dir.path(), &[]);
    assert!(report.contains("baseline applied"), "header should say so");
}

#[test]
fn html_mentions_diff_in_header() {
    let dir = tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    git(dir.path(), &["config", "user.email", "test@example.com"]);
    git(dir.path(), &["config", "user.name", "Test"]);
    git(dir.path(), &["config", "commit.gpgsign", "false"]);
    write(dir.path().join("old.rs"), "fn main() {}\n").unwrap();
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "old"]);

    write(dir.path().join("bad.rs"), BAD_RS).unwrap();
    git(dir.path(), &["add", "bad.rs"]);

    let report = report_of(dir.path(), &["--diff"]);
    assert!(report.contains("diff vs"), "header should scope the diff");
}

#[test]
fn html_typescript_language_axis() {
    let dir = project_with("bad.ts", BAD_TS);
    let report = report_of(dir.path(), &[]);

    assert!(report.contains("data-language=\"typescript\""));
}

#[test]
fn stats_rejects_html_format() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .current_dir(dir.path())
        .args(["stats", ".", "--format", "html"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("HTML format is not supported"));
}

#[test]
fn explain_rejects_html_format() {
    slopguard()
        .args(["explain", "no-unwrap-in-prod", "--format", "html"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("HTML format is not supported"));
}

#[test]
fn output_flag_works_with_json() {
    let dir = project_with("bad.rs", BAD_RS);
    let path = dir.path().join("report.json");

    let output = slopguard()
        .args([
            "scan",
            "--format",
            "json",
            "-o",
            path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "-o should keep stdout empty");

    let raw = read_to_string(&path).expect("the report file should exist");
    let json: serde_json::Value =
        serde_json::from_str(&raw).expect("the file should contain valid JSON");
    assert!(
        json["stats"]["total"].as_u64().unwrap_or(0) >= 2,
        "the JSON file should carry the scan totals"
    );
}

#[test]
fn output_flag_to_unwritable_path_exits_two() {
    let dir = project_with("bad.rs", BAD_RS);

    slopguard()
        .args([
            "scan",
            "--format",
            "html",
            "-o",
            "/nonexistent-dir-xyz/report.html",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}
