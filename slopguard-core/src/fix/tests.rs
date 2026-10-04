use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::baseline::{self, Baseline};
use crate::config::{Config, FixConfig};
use crate::rule::{parse_rule, Rule, RuleId};
use crate::scanner::scan;
use crate::source::RuleOrigin;

use super::{apply_edits, fix_paths, fix_snippet, shift_protected, Protected, RawEdit};

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

/// The clone rule as if loaded from a local `custom_dirs` directory.
fn external_clone_rule() -> Rule {
    let mut rule = clone_rule();
    rule.origin = RuleOrigin::Local {
        path: PathBuf::from("/team/rules"),
    };
    rule
}

/// A config whose `fix.allow_external` lists `ids`.
fn config_allowing(ids: &[&str]) -> Config {
    Config {
        fix: FixConfig {
            allow_external: ids.iter().map(|id| id.to_string()).collect(),
        },
        ..Config::default()
    }
}

const CLONE_SOURCE: &str = "fn f() { let s = name.to_string().clone(); }\n";

#[test]
fn external_rule_with_autofix_safe_is_not_applied() {
    let dir = tempdir().unwrap();
    let file = write_file(dir.path(), "a.rs", CLONE_SOURCE);

    let report = fix_paths(
        &[file],
        &[external_clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 0,
        "autofix_safe on an external rule alone must not rewrite"
    );
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn external_rule_listed_in_allow_external_is_applied() {
    let dir = tempdir().unwrap();
    let file = write_file(dir.path(), "a.rs", CLONE_SOURCE);

    let report = fix_paths(
        &[file],
        &[external_clone_rule()],
        &config_allowing(&["no-unnecessary-clone"]),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 1);
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let s = name.to_string(); }\n"
    );
}

#[test]
fn external_rule_allow_list_naming_another_rule_is_not_applied() {
    let dir = tempdir().unwrap();
    let file = write_file(dir.path(), "a.rs", CLONE_SOURCE);

    let report = fix_paths(
        &[file],
        &[external_clone_rule()],
        &config_allowing(&["some-other-rule"]),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 0);
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn external_rule_allowed_but_not_autofix_safe_is_not_applied() {
    let dir = tempdir().unwrap();
    let file = write_file(dir.path(), "a.rs", CLONE_SOURCE);
    let mut rule = external_clone_rule();
    rule.autofix_safe = false;

    let report = fix_paths(
        &[file],
        &[rule],
        &config_allowing(&["no-unnecessary-clone"]),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 0);
    assert_eq!(report.files_changed(), 0);
}

#[test]
fn fix_snippet_applies_an_external_rule() {
    // `slopguard test` validates should_fix of custom rules too; a snippet is
    // never written to disk, so the trust gate does not apply.
    assert_eq!(
        fix_snippet(&external_clone_rule(), CLONE_SOURCE).unwrap(),
        "fn f() { let s = name.to_string(); }\n"
    );
}

#[test]
fn rewrite_respects_ignores_glob() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("skip")).unwrap();
    let skipped = write_file(dir.path(), "skip/a.rs", CLONE_SOURCE);
    let kept = write_file(dir.path(), "b.rs", CLONE_SOURCE);
    let mut rule = clone_rule();
    rule.ignores = Some(vec!["**/skip/*.rs".to_string()]);

    let report = fix_paths(
        &[skipped, kept.clone()],
        &[rule],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 1,
        "only the file outside skip/ is rewritten"
    );
    assert_eq!(report.files_changed(), 1);
    assert_eq!(report.files[0].path, kept);
}

#[test]
fn rewrite_respects_files_glob() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    let selected = write_file(dir.path(), "src/a.rs", CLONE_SOURCE);
    let outside = write_file(dir.path(), "b.rs", CLONE_SOURCE);
    let mut rule = clone_rule();
    rule.files = Some(vec!["**/src/*.rs".to_string()]);

    let report = fix_paths(
        &[selected.clone(), outside],
        &[rule],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(
        report.applied, 1,
        "only the file selected by `files` is rewritten"
    );
    assert_eq!(report.files_changed(), 1);
    assert_eq!(report.files[0].path, selected);
}

/// Detection only flags a clone that initializes a `let`; the dedicated
/// `autofix_rule` matches every clone.
const LET_CLONE_RULE: &str = r#"
id: no-let-clone
language: rust
severity: warning
message: "Clone in a let initializer."
rewrite: "$X"
autofix_safe: true
autofix_rule:
  pattern: $X.clone()
rule:
  pattern: $R.clone()
  inside:
    kind: let_declaration
"#;

#[test]
fn autofix_rule_rewrites_only_where_detection_matched() {
    let dir = tempdir().unwrap();
    let source = "fn f() { let s = a.clone(); g(b.clone()); }\n";
    let file = write_file(dir.path(), "a.rs", source);
    let rule = parse_rule(LET_CLONE_RULE).unwrap();

    let report = fix_paths(&[file], &[rule], &Config::default(), None, dir.path()).unwrap();

    assert_eq!(report.applied, 1, "the undetected clone must stay");
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let s = a; g(b.clone()); }\n"
    );
}

/// Detection constrains the receiver to names starting with `owned`; the
/// dedicated `autofix_rule` uses its own metavariable and no constraint.
const CONSTRAINED_CLONE_RULE: &str = r#"
id: no-owned-clone
language: rust
severity: warning
message: "Clone of an owned value."
rewrite: "$X"
autofix_safe: true
autofix_rule:
  pattern: $X.clone()
rule:
  pattern: $R.clone()
constraints:
  R:
    regex: '^owned'
"#;

#[test]
fn autofix_rule_honors_detection_constraints() {
    let dir = tempdir().unwrap();
    let source = "fn f() { let a = owned_s.clone(); let b = other.clone(); }\n";
    let file = write_file(dir.path(), "a.rs", source);
    let rule = parse_rule(CONSTRAINED_CLONE_RULE).unwrap();

    let report = fix_paths(&[file], &[rule], &Config::default(), None, dir.path()).unwrap();

    assert_eq!(
        report.applied, 1,
        "a match excluded by the detection constraints must stay"
    );
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let a = owned_s; let b = other.clone(); }\n"
    );
}

/// A rewrite that inserts a line break, so it moves whatever follows it on the
/// same line down by one line.
const FOO_RULE: &str = r#"
id: no-foo-call
language: rust
severity: warning
message: "foo() call."
rewrite: "bar(\n$A)"
autofix_safe: true
rule:
  pattern: foo($A)
"#;

#[test]
fn inline_disable_still_protects_after_earlier_edits_shift_lines() {
    let dir = tempdir().unwrap();
    // The first pass rewrites foo(1) and pushes the disabled clone to the next
    // line, away from the directive's target line. The clone must still be
    // protected in the following passes.
    let source = "fn f() {\n    // slopguard-disable-next-line no-unnecessary-clone\n    foo(1); let s = name.to_string().clone();\n}\n";
    let file = write_file(dir.path(), "a.rs", source);
    let foo_rule = parse_rule(FOO_RULE).unwrap();

    let report = fix_paths(
        &[file],
        &[foo_rule, clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 1, "only foo(1) is rewritten");
    let fixed = &report.files[0].fixed;
    assert!(
        fixed.contains("bar("),
        "foo(1) should be rewritten: {fixed}"
    );
    assert!(
        fixed.contains("name.to_string().clone()"),
        "the disabled clone must survive every pass: {fixed}"
    );
}

#[test]
fn baselined_match_stays_protected_across_iterations() {
    let dir = tempdir().unwrap();
    // Two clones on one line; only the first is baselined. Rewriting the second
    // changes the line, so a hash recomputed on the mutated buffer in the next
    // pass would no longer match the baseline entry.
    let source = "fn f() { let a = x.to_string().clone(); let b = y.to_string().clone(); }\n";
    let file = write_file(dir.path(), "a.rs", source);

    let detected = scan(
        std::slice::from_ref(&file),
        &[clone_rule()],
        &Config::default(),
    )
    .unwrap();
    assert_eq!(
        detected.findings.len(),
        2,
        "sanity: both clones are detected"
    );
    let first: Vec<_> = detected
        .findings
        .into_iter()
        .filter(|f| f.matched_text.starts_with("x."))
        .collect();
    assert_eq!(first.len(), 1);
    let baseline: Baseline = baseline::build(&first, dir.path());

    let report = fix_paths(
        &[file],
        &[clone_rule()],
        &Config::default(),
        Some(&baseline),
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 1, "only the unbaselined clone is rewritten");
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let a = x.to_string().clone(); let b = y.to_string(); }\n"
    );
}

#[test]
fn applied_counts_only_edits_actually_written() {
    let dir = tempdir().unwrap();
    let source = "fn f() { let a = x.to_string().clone(); let b = y.to_string().clone(); }\n";
    let file = write_file(dir.path(), "a.rs", source);

    let report = fix_paths(
        &[file],
        &[clone_rule()],
        &Config::default(),
        None,
        dir.path(),
    )
    .unwrap();

    assert_eq!(report.applied, 2);
    assert_eq!(
        report.files[0].fixed,
        "fn f() { let a = x.to_string(); let b = y.to_string(); }\n"
    );
}

#[test]
fn apply_edits_skips_and_does_not_count_out_of_bounds_edits() {
    let edits = [
        RawEdit {
            position: 0,
            deleted_length: 3,
            inserted: b"xyz".to_vec(),
        },
        RawEdit {
            position: 5,
            deleted_length: 10,
            inserted: b"nope".to_vec(),
        },
    ];

    let (fixed, applied) = apply_edits("abcdef", &edits);

    assert_eq!(fixed, "xyzdef");
    assert_eq!(applied, 1, "the out-of-bounds edit is not counted");
}

#[test]
fn apply_edits_with_invalid_utf8_result_applies_nothing() {
    let edits = [RawEdit {
        position: 0,
        deleted_length: 1,
        inserted: vec![0xff],
    }];

    let (fixed, applied) = apply_edits("abc", &edits);

    assert_eq!(fixed, "abc");
    assert_eq!(applied, 0);
}

fn protected(start: usize, end: usize) -> Protected {
    Protected {
        rule_id: RuleId::from("r"),
        start,
        end,
    }
}

#[test]
fn shift_protected_moves_and_widens_ranges() {
    let mut ranges = [
        protected(0, 2),
        protected(3, 8),
        protected(10, 15),
        protected(5, 7),
    ];
    // Replace bytes 2..5 with a single byte (delta -2).
    let edits = [RawEdit {
        position: 2,
        deleted_length: 3,
        inserted: b"x".to_vec(),
    }];

    shift_protected(&mut ranges, &edits);

    assert_eq!(ranges[0], protected(0, 2), "a range before the edit stays");
    assert_eq!(
        ranges[1],
        protected(2, 6),
        "an overlapped range is widened over the replacement"
    );
    assert_eq!(ranges[2], protected(8, 13), "a range after the edit shifts");
    assert_eq!(
        ranges[3],
        protected(3, 5),
        "a range starting at the edit end shifts"
    );
}

#[test]
fn shift_protected_folds_several_edits_right_to_left() {
    let mut ranges = [protected(10, 12)];
    // Two edits before the range: +2 bytes at 0, +1 byte at 4.
    let edits = [
        RawEdit {
            position: 0,
            deleted_length: 1,
            inserted: b"abc".to_vec(),
        },
        RawEdit {
            position: 4,
            deleted_length: 0,
            inserted: b"z".to_vec(),
        },
    ];

    shift_protected(&mut ranges, &edits);

    assert_eq!(ranges[0], protected(13, 15));
}

#[test]
fn shift_protected_widens_a_range_nesting_an_edit() {
    let mut ranges = [protected(2, 20)];
    // An edit strictly inside the range shrinks it by 4 bytes.
    let edits = [RawEdit {
        position: 5,
        deleted_length: 6,
        inserted: b"ab".to_vec(),
    }];

    shift_protected(&mut ranges, &edits);

    assert_eq!(ranges[0], protected(2, 16));
}
