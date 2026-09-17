use std::fs::{create_dir_all, write as write_file};
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::finding::Finding;
use crate::rule::{Category, RuleId, Severity};

use super::{
    build, filter, find_baseline_file, finding_hash, load, project_root, relative_path, write,
    BaselineError, BASELINE_FILE,
};

fn make_finding(rule_id: &str, file: &str, line: usize, matched_text: &str) -> Finding {
    Finding {
        rule_id: RuleId::from(rule_id),
        severity: Severity::Error,
        category: Category::Correctness,
        message: "test".to_string(),
        note: None,
        fix: None,
        file: PathBuf::from(file),
        line,
        column: 1,
        end_line: line,
        end_column: 10,
        matched_text: matched_text.to_string(),
        confidence: None,
        escalated: false,
    }
}

#[test]
fn hash_is_line_number_independent() {
    let root = Path::new(".");
    // Same file, same matched text, same surrounding context, different line.
    let source = "fn a() {}\nfn b() {}\nfoo().unwrap();\nfn c() {}\nfn d() {}\n";
    let shifted = "// x\n// x\nfn a() {}\nfn b() {}\nfoo().unwrap();\nfn c() {}\nfn d() {}\n";

    let at_line_3 = make_finding("no-unwrap-in-prod", "src/a.rs", 3, "foo().unwrap()");
    let at_line_5 = make_finding("no-unwrap-in-prod", "src/a.rs", 5, "foo().unwrap()");

    assert_eq!(
        finding_hash(&at_line_3, root, Some(source)),
        finding_hash(&at_line_5, root, Some(shifted))
    );
}

#[test]
fn hash_differs_on_rule_id() {
    let root = Path::new(".");
    let a = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()");
    let b = make_finding("no-expect-in-prod", "src/a.rs", 1, "x.unwrap()");
    assert_ne!(finding_hash(&a, root, None), finding_hash(&b, root, None));
}

#[test]
fn hash_differs_on_matched_text() {
    let root = Path::new(".");
    let a = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()");
    let b = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "y.unwrap()");
    assert_ne!(finding_hash(&a, root, None), finding_hash(&b, root, None));
}

#[test]
fn hash_differs_on_file() {
    let root = Path::new(".");
    let a = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()");
    let b = make_finding("no-unwrap-in-prod", "src/b.rs", 1, "x.unwrap()");
    assert_ne!(finding_hash(&a, root, None), finding_hash(&b, root, None));
}

#[test]
fn hash_differs_when_context_changes() {
    let root = Path::new(".");
    let finding = make_finding("no-unwrap-in-prod", "src/a.rs", 3, "x.unwrap()");
    let before = "fn a() {}\nfn b() {}\nx.unwrap();\nfn c() {}\n";
    let after = "fn a() {}\nfn zzz() {}\nx.unwrap();\nfn c() {}\n";
    assert_ne!(
        finding_hash(&finding, root, Some(before)),
        finding_hash(&finding, root, Some(after))
    );
}

#[test]
fn hash_survives_out_of_bounds_line() {
    let root = Path::new(".");
    let finding = make_finding("no-unwrap-in-prod", "src/a.rs", 999, "x.unwrap()");
    let source = "fn a() {}\n";
    assert!(!finding_hash(&finding, root, Some(source)).is_empty());
}

#[test]
fn relative_path_is_stable_across_path_forms() {
    let dir = tempdir().unwrap();
    create_dir_all(dir.path().join("src")).unwrap();
    let file = dir.path().join("src/a.rs");
    write_file(&file, "fn main() {}\n").unwrap();

    let absolute = relative_path(&file, dir.path());
    let dotted = relative_path(&dir.path().join("./src/a.rs"), dir.path());
    assert_eq!(absolute, "src/a.rs");
    assert_eq!(absolute, dotted);
}

#[test]
fn filter_drops_baselined_findings() {
    let root = Path::new(".");
    let findings = vec![
        make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()"),
        make_finding("no-expect-in-prod", "src/b.rs", 4, "y.expect(\"e\")"),
    ];
    let baseline = build(&findings, root);
    let (kept, filtered) = filter(findings, &baseline, root);
    assert!(kept.is_empty());
    assert_eq!(filtered, 2);
}

#[test]
fn filter_keeps_new_findings() {
    let root = Path::new(".");
    let old = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()");
    let new = make_finding("no-unwrap-in-prod", "src/b.rs", 1, "z.unwrap()");
    let baseline = build(std::slice::from_ref(&old), root);

    let (kept, filtered) = filter(vec![old, new], &baseline, root);
    assert_eq!(kept.len(), 1);
    assert_eq!(filtered, 1);
    assert_eq!(kept[0].file, PathBuf::from("src/b.rs"));
}

#[test]
fn filter_counts_duplicates() {
    let root = Path::new(".");
    let one = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "x.unwrap()");
    let baseline = build(&[one.clone(), one.clone()], root);

    let (kept, filtered) = filter(vec![one.clone(), one.clone(), one], &baseline, root);
    assert_eq!(kept.len(), 1);
    assert_eq!(filtered, 2);
}

#[test]
fn filter_ignores_stale_entries() {
    let root = Path::new(".");
    let fixed = make_finding("no-unwrap-in-prod", "src/gone.rs", 1, "x.unwrap()");
    let baseline = build(std::slice::from_ref(&fixed), root);

    let current = make_finding("no-unwrap-in-prod", "src/a.rs", 1, "z.unwrap()");
    let (kept, filtered) = filter(vec![current], &baseline, root);
    assert_eq!(kept.len(), 1);
    assert_eq!(filtered, 0);
}

#[test]
fn load_rejects_bad_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(BASELINE_FILE);
    write_file(&path, r#"{"version": 99, "findings": []}"#).unwrap();

    match load(&path) {
        Err(BaselineError::Version { found, .. }) => assert_eq!(found, 99),
        other => panic!("expected a version error, got {other:?}"),
    }
}

#[test]
fn load_rejects_malformed_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(BASELINE_FILE);
    write_file(&path, "not json").unwrap();

    assert!(matches!(load(&path), Err(BaselineError::Parse { .. })));
}

#[test]
fn find_baseline_file_walks_up() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("a/b");
    create_dir_all(&nested).unwrap();
    let expected = dir.path().join(BASELINE_FILE);
    write_file(&expected, r#"{"version": 1, "findings": []}"#).unwrap();

    assert_eq!(find_baseline_file(&nested), Some(expected));
}

#[test]
fn find_baseline_file_returns_none() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("a/b");
    create_dir_all(&nested).unwrap();

    assert_eq!(find_baseline_file(&nested), None);
}

#[test]
fn write_then_load_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(BASELINE_FILE);
    let findings = vec![make_finding(
        "no-unwrap-in-prod",
        "src/a.rs",
        1,
        "x.unwrap()",
    )];
    let baseline = build(&findings, Path::new("."));

    write(&baseline, &path).unwrap();
    let loaded = load(&path).unwrap();
    assert_eq!(loaded.version, baseline.version);
    assert_eq!(loaded.findings.len(), 1);
    assert_eq!(loaded.findings[0].hash, baseline.findings[0].hash);
    assert_eq!(loaded.findings[0].rule_id, "no-unwrap-in-prod");
    assert_eq!(loaded.findings[0].file, "src/a.rs");
}

#[test]
fn write_produces_empty_baseline_for_clean_project() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(BASELINE_FILE);
    let baseline = build(&[], Path::new("."));

    write(&baseline, &path).unwrap();
    let loaded = load(&path).unwrap();
    assert!(loaded.findings.is_empty());
}

#[test]
fn project_root_prefers_config_file() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("src/deep");
    create_dir_all(&nested).unwrap();
    write_file(dir.path().join("slopguard.toml"), "").unwrap();

    let root = project_root(&nested);
    assert_eq!(
        root.canonicalize().unwrap(),
        dir.path().canonicalize().unwrap()
    );
}
