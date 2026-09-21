use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::baseline::{self, Baseline};
use crate::config::Config;
use crate::rule::{parse_rule, Rule};
use crate::scanner::scan;

use super::{fix_paths, fix_snippet};

/// Detect-broad, fix-narrow: detection matches every dbg!(), but the dedicated
/// `autofix_rule` rewrites only a single comma-free argument.
const DBG_RULE: &str = r#"
id: no-dbg-in-prod
language: rust
severity: error
message: "dbg!() left in production code."
rewrite: "$$$E"
autofix_safe: true
autofix_rule:
  all:
    - pattern: dbg!($$$E)
    - not:
        regex: '^dbg\s*!\s*\(\s*\)$'
    - not:
        regex: ','
rule:
  kind: macro_invocation
  has:
    kind: identifier
    regex: '^dbg$'
"#;

fn dbg_rule() -> Rule {
    parse_rule(DBG_RULE).expect("dbg rule should parse")
}

/// The autofix-safe clone rule: match `$R.clone()` where the receiver is already
/// an owned value, rewrite to the receiver alone.
const CLONE_RULE: &str = r#"
id: no-unnecessary-clone
language: rust
severity: warning
message: "Unnecessary .clone()."
rewrite: "$R"
autofix_safe: true
skip_test_code: true
rule:
  pattern: $R.clone()
constraints:
  R:
    any:
      - pattern: $X.to_string()
      - pattern: $X.to_owned()
      - pattern: "String::from($$$A)"
      - pattern: "format!($$$B)"
"#;

fn clone_rule() -> Rule {
    parse_rule(CLONE_RULE).expect("clone rule should parse")
}

/// Same matcher, but not marked safe: `--fix` must ignore it.
fn unsafe_clone_rule() -> Rule {
    let mut rule = clone_rule();
    rule.autofix_safe = false;
    rule
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn rewrites_unnecessary_clone() {
    let dir = tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "a.rs",
        "fn f() { let s = name.to_string().clone(); }\n",
    );

    let report = fix_paths(
        std::slice::from_ref(&file),
        &[clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 1, "one clone should be rewritten");
    assert_eq!(report.files_changed(), 1);
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let s = name.to_string(); }\n"
    );
    // Nothing is written by fix_paths itself.
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "fn f() { let s = name.to_string().clone(); }\n",
        "fix_paths must not touch the file on disk"
    );
}

#[test]
fn rewrite_ignored_without_autofix_safe() {
    let dir = tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "a.rs",
        "fn f() { let s = name.to_string().clone(); }\n",
    );

    let report = fix_paths(
        &[file],
        &[unsafe_clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 0, "a rewrite is inert without autofix_safe");
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn inline_disabled_finding_is_not_rewritten() {
    let dir = tempdir().unwrap();
    let source = "fn f() {\n    // slopguard-disable-next-line no-unnecessary-clone\n    let s = name.to_string().clone();\n}\n";
    let file = write_file(dir.path(), "a.rs", source);

    let report = fix_paths(
        &[file],
        &[clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 0,
        "a disabled finding must not be rewritten"
    );
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn baselined_finding_is_not_rewritten() {
    let dir = tempdir().unwrap();
    let source = "fn f() { let s = name.to_string().clone(); }\n";
    let file = write_file(dir.path(), "a.rs", source);

    // Capture the finding into a baseline, then fix with that baseline active.
    let detected = scan(
        std::slice::from_ref(&file),
        &[clone_rule()],
        &Config::default(),
    )
    .unwrap();
    assert_eq!(detected.findings.len(), 1, "sanity: the clone is detected");
    let baseline: Baseline = baseline::build(&detected.findings, dir.path());

    let report = fix_paths(
        std::slice::from_ref(&file),
        &[clone_rule()],
        &Config::default(),
        Some(&baseline),
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 0,
        "a finding recorded in the baseline must not be rewritten"
    );
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn overlapping_matches_reach_a_fix_point() {
    let dir = tempdir().unwrap();
    // The outer String::from(..).clone() and the inner a.to_string().clone()
    // overlap: the inner one is nested inside the outer's range (and, unlike a
    // macro's token tree, String::from's argument is a real expression). One
    // pass applies the non-overlapping (outer) edit; the next pass applies the
    // newly isolated inner one, proving the fix-point loop.
    let source = "fn f() { let s = String::from(a.to_string().clone()).clone(); }\n";
    let file = write_file(dir.path(), "a.rs", source);

    let report = fix_paths(
        &[file],
        &[clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 2,
        "both clones should be removed across iterations"
    );
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let s = String::from(a.to_string()); }\n"
    );
}

#[test]
fn dedicated_autofix_rule_fixes_only_the_safe_subset() {
    let dir = tempdir().unwrap();
    let source = "fn a() { let x = dbg!(compute()); }\nfn b() { let y = dbg!(); }\nfn c() { let z = dbg!(p, q); }\n";
    let file = write_file(dir.path(), "a.rs", source);

    let report = fix_paths(&[file], &[dbg_rule()], &Config::default(), None, dir.path()).unwrap();

    // Only the single comma-free argument is rewritten; the empty and multi-arg
    // forms are left intact so the result still compiles.
    assert_eq!(report.applied, 1);
    assert_eq!(
        report.files[0].fixed,
        "fn a() { let x = compute(); }\nfn b() { let y = dbg!(); }\nfn c() { let z = dbg!(p, q); }\n"
    );
}

#[test]
fn fix_snippet_applies_a_single_rule() {
    assert_eq!(
        fix_snippet(&dbg_rule(), "fn f() { let x = dbg!(y()); }").unwrap(),
        "fn f() { let x = y(); }"
    );
    // A statement-position dbg! unwraps to its argument (a benign path statement).
    assert_eq!(
        fix_snippet(&dbg_rule(), "fn f() { dbg!(value); }").unwrap(),
        "fn f() { value; }"
    );
}

#[test]
fn fix_snippet_is_inert_without_autofix_safe() {
    let mut rule = dbg_rule();
    rule.autofix_safe = false;
    assert_eq!(
        fix_snippet(&rule, "fn f() { let x = dbg!(y()); }").unwrap(),
        "fn f() { let x = dbg!(y()); }"
    );
}
