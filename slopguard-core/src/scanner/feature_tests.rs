use std::collections::HashSet;
use std::fs::{create_dir, write};

use tempfile::tempdir;

use super::test_support::*;
use super::*;
use crate::config::Config;
use crate::rule::RuleId;

#[test]
fn scan_files_cached_keeps_other_entries() {
    let src_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    let a = src_dir.path().join("a.rs");
    let b = src_dir.path().join("b.rs");
    write(&a, "fn a() {\n    foo().unwrap();\n}\n").unwrap();
    write(&b, "fn b() {\n    bar().unwrap();\n}\n").unwrap();

    let rules = [unwrap_rule()];
    let config = Config::default();
    let paths = [src_dir.path().to_path_buf()];

    scan_cached(&paths, &rules, &config, &cache_path).unwrap();

    // A partial scan must not evict the entry of the file it skipped.
    scan_files_cached(&[a], &rules, &config, &cache_path).unwrap();

    let result = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    let stats = result.cache_stats.as_ref().unwrap();
    assert_eq!(stats.cached, 2, "a partial scan must not prune");
    assert_eq!(stats.changed, 0);
}

#[test]
fn file_target_walk_keeps_other_entries() {
    let src_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    let a = src_dir.path().join("a.rs");
    write(&a, "fn a() {\n    foo().unwrap();\n}\n").unwrap();
    write(
        src_dir.path().join("b.rs"),
        "fn b() {\n    bar().unwrap();\n}\n",
    )
    .unwrap();

    let rules = [unwrap_rule()];
    let config = Config::default();
    let paths = [src_dir.path().to_path_buf()];

    scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    // The pre-commit hook passes files as scan paths, not through `--diff`.
    scan_cached(&[a], &rules, &config, &cache_path).unwrap();

    let result = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    let stats = result.cache_stats.as_ref().unwrap();
    assert_eq!(stats.cached, 2, "a file target must not prune");
    assert_eq!(stats.changed, 0);
}

#[test]
fn scan_finds_file_lines_violation() {
    let dir = tempdir().unwrap();
    write(dir.path().join("big.rs"), rust_lines(12)).unwrap();
    let result = scan_dir(dir.path(), &[file_lines_rule()]);
    assert_eq!(result.findings.len(), 1);
    let f = &result.findings[0];
    assert_eq!(f.rule_id, RuleId::from("test-file-lines"));
    assert_eq!(f.line, 1);
    assert_eq!(f.column, 1);
    assert_eq!(f.end_line, 1);
    assert_eq!(f.end_column, 1);
    assert_eq!(f.matched_text, "12 lines");
}

#[test]
fn metric_message_interpolates_value() {
    let dir = tempdir().unwrap();
    write(dir.path().join("big.rs"), rust_lines(12)).unwrap();
    let rule = metric_rule(
        r#"
id: test-interpolate
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "File exceeds 10 lines ($value lines)"
"#,
    );
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    let message = &result.findings[0].message;
    assert!(message.contains("(12 lines)"), "got: {message}");
    assert!(!message.contains("$value"), "got: {message}");
}

#[test]
fn metric_rule_below_threshold_no_finding() {
    let dir = tempdir().unwrap();
    write(dir.path().join("exact.rs"), rust_lines(10)).unwrap();
    let result = scan_dir(dir.path(), &[file_lines_rule()]);
    assert_eq!(
        result.findings.len(),
        0,
        "a file of exactly the threshold length must not fire"
    );
}

#[test]
fn metric_comment_ratio_finding() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("commented.rs"),
        "// a\n// b\n// c\n// d\nfn f() {}\nfn g() {}\nfn h() {}\n",
    )
    .unwrap();
    let rule = metric_rule(
        r#"
id: test-comment-ratio
language: rust
severity: warning
category: slop
metric: comment_ratio
threshold: 0.4
message: "Too many comments ($value)"
"#,
    );
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    assert!(
        result.findings[0].matched_text.ends_with("comment ratio"),
        "got: {}",
        result.findings[0].matched_text
    );
}

#[test]
fn metric_rule_respects_ignores_glob() {
    let dir = tempdir().unwrap();
    let gen = dir.path().join("generated");
    create_dir(&gen).unwrap();
    write(gen.join("out.rs"), rust_lines(12)).unwrap();
    write(dir.path().join("main.rs"), rust_lines(12)).unwrap();
    let rule = metric_rule(
        r#"
id: test-metric-ignores
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "too long"
ignores:
  - "**/generated/**"
"#,
    );
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0]
        .file
        .to_string_lossy()
        .contains("main.rs"));
}

#[test]
fn metric_rule_respects_files_glob() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    create_dir(&src).unwrap();
    write(src.join("lib.rs"), rust_lines(12)).unwrap();
    write(dir.path().join("build.rs"), rust_lines(12)).unwrap();
    let rule = metric_rule(
        r#"
id: test-metric-files
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "too long"
files:
  - "**/src/**/*.rs"
"#,
    );
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].file.to_string_lossy().contains("lib.rs"));
}

#[test]
fn metric_rule_skip_test_code_skips_test_files() {
    let dir = tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    create_dir(&tests_dir).unwrap();
    write(tests_dir.join("it.rs"), rust_lines(12)).unwrap();

    let skipping = metric_rule(
        r#"
id: test-metric-skip
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "too long"
skip_test_code: true
"#,
    );
    let skipped = scan_dir(dir.path(), &[skipping]);
    assert_eq!(skipped.findings.len(), 0);
    let reported = scan_dir(dir.path(), &[file_lines_rule()]);
    assert_eq!(reported.findings.len(), 1);
}

#[test]
fn metric_only_ruleset_still_scans() {
    let dir = tempdir().unwrap();
    write(dir.path().join("big.rs"), rust_lines(12)).unwrap();
    let result = scan_dir(dir.path(), &[file_lines_rule()]);
    assert_eq!(
        result.findings.len(),
        1,
        "a rule set with only metric rules must still scan files"
    );
}

#[test]
fn metric_and_ast_rules_together() {
    let dir = tempdir().unwrap();
    let mut source = String::from("fn main() {\n    foo().unwrap();\n}\n");
    source.push_str(&rust_lines(12));
    write(dir.path().join("main.rs"), source).unwrap();

    let result = scan_dir(dir.path(), &[unwrap_rule(), file_lines_rule()]);
    assert_eq!(result.findings.len(), 2);
    let first = &result.findings[0];
    assert_eq!(first.rule_id, RuleId::from("test-file-lines"));
    assert_eq!(first.line, 1);
    let second = &result.findings[1];
    assert_eq!(second.rule_id, RuleId::from("test-unwrap"));
}

#[test]
fn metric_rule_wrong_language_not_applied() {
    let dir = tempdir().unwrap();
    write(dir.path().join("big.rs"), rust_lines(12)).unwrap();
    let rule = metric_rule(
        r#"
id: test-metric-ts
language: typescript
severity: warning
category: slop
metric: file_lines
threshold: 10
message: "too long"
"#,
    );
    let result = scan_dir(dir.path(), &[rule]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn metric_findings_are_cached() {
    let src_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    write(src_dir.path().join("big.rs"), rust_lines(12)).unwrap();

    let rules = [file_lines_rule()];
    let config = Config::default();
    let paths = [src_dir.path().to_path_buf()];

    let first = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    assert_eq!(first.findings.len(), 1);
    assert_eq!(first.cache_stats.as_ref().unwrap().changed, 1);

    let second = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    assert_eq!(second.cache_stats.as_ref().unwrap().cached, 1);
    assert_eq!(second.findings.len(), 1);
    assert_eq!(second.findings[0].matched_text, "12 lines");
}

#[test]
fn scan_with_cache() {
    let src_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    write(
        src_dir.path().join("main.rs"),
        "fn main() {\n    foo().unwrap();\n}\n",
    )
    .unwrap();

    let rules = [unwrap_rule()];
    let config = Config::default();

    let result1 = scan_cached(
        &[src_dir.path().to_path_buf()],
        &rules,
        &config,
        &cache_path,
    )
    .unwrap();

    assert_eq!(result1.findings.len(), 1);
    let cache_stats1 = result1.cache_stats.as_ref().unwrap();
    assert_eq!(cache_stats1.cached, 0, "first scan: nothing cached");
    assert_eq!(cache_stats1.changed, 1, "first scan: one file scanned");

    let result2 = scan_cached(
        &[src_dir.path().to_path_buf()],
        &rules,
        &config,
        &cache_path,
    )
    .unwrap();

    assert_eq!(result2.findings.len(), 1);
    let cache_stats2 = result2.cache_stats.as_ref().unwrap();
    assert_eq!(cache_stats2.cached, 1, "second scan: one file from cache");
    assert_eq!(cache_stats2.changed, 0, "second scan: nothing changed");
}

#[test]
fn cross_file_single_impl_trait_reported() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("repo.rs"),
        "pub trait Repository {\n    fn get(&self);\n}\n",
    )
    .unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\n\nimpl Repository for Pg {\n    fn get(&self) {}\n}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 1);
    let f = &result.findings[0];
    assert_eq!(f.rule_id, RuleId::from("no-single-impl-trait"));
    assert!(f.file.to_string_lossy().ends_with("repo.rs"));
    assert_eq!(f.line, 1);
    assert_eq!(f.matched_text, "pub trait Repository");
}

#[test]
fn cross_file_two_impls_not_reported() {
    let dir = tempdir().unwrap();
    write(dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();
    write(
        dir.path().join("mem.rs"),
        "pub struct Mem;\nimpl Repository for Mem {}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn cross_file_no_impl_not_reported() {
    let dir = tempdir().unwrap();
    write(dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn cross_file_blanket_impl_not_reported() {
    let dir = tempdir().unwrap();
    write(dir.path().join("desc.rs"), "pub trait Describe {}\n").unwrap();
    write(dir.path().join("all.rs"), "impl<T> Describe for T {}\n").unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn cross_file_duplicate_trait_name_not_reported() {
    let dir = tempdir().unwrap();
    write(dir.path().join("a.rs"), "pub trait Repository {}\n").unwrap();
    write(dir.path().join("b.rs"), "pub trait Repository {}\n").unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn cross_file_disable_comment_on_declaration() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("repo.rs"),
        "// slopguard-disable-next-line no-single-impl-trait\npub trait Repository {}\n",
    )
    .unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(
        result.findings.len(),
        0,
        "a disable comment above the declaration must suppress the finding"
    );
}

#[test]
fn cross_file_cfg_test_mock_counts_as_second_impl() {
    let dir = tempdir().unwrap();
    write(dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();
    write(
        dir.path().join("mock.rs"),
        "#[cfg(test)]\nmod tests {\n    struct MockRepo;\n    impl Repository for MockRepo {}\n}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(
        result.findings.len(),
        0,
        "a test mock counts as a second implementation"
    );
}

#[test]
fn cross_file_declaration_in_test_path_not_reported() {
    let dir = tempdir().unwrap();
    let tests_dir = dir.path().join("tests");
    create_dir(&tests_dir).unwrap();
    write(tests_dir.join("support.rs"), "pub trait Repository {}\n").unwrap();
    write(
        tests_dir.join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(result.findings.len(), 0);
}

/// A project (marked by `slopguard.toml`) whose trait has one impl per file in
/// `impls`.
fn repository_project(impls: &[&str]) -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    write(dir.path().join("slopguard.toml"), "").unwrap();
    write(dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();
    for name in impls {
        write(
            dir.path().join(format!("{}.rs", name.to_lowercase())),
            format!("pub struct {name};\nimpl Repository for {name} {{}}\n"),
        )
        .unwrap();
    }
    dir
}

#[test]
fn scan_files_indexes_the_whole_project() {
    // The second impl lives in a file outside the scanned list: a partial
    // index would see one impl and report the trait.
    let dir = repository_project(&["Pg", "Mem"]);
    let rules = [single_impl_trait_rule()];
    let partial = scan_files(&[dir.path().join("repo.rs")], &rules, &Config::default()).unwrap();
    assert!(partial.findings.is_empty(), "got: {:?}", partial.findings);
}

#[test]
fn scan_files_reports_only_findings_in_the_given_files() {
    let dir = repository_project(&["Pg"]);
    let rules = [single_impl_trait_rule()];
    let config = Config::default();

    let on_decl = scan_files(&[dir.path().join("repo.rs")], &rules, &config).unwrap();
    assert_eq!(on_decl.findings.len(), 1);
    assert!(on_decl.findings[0].file.ends_with("repo.rs"));

    let on_impl = scan_files(&[dir.path().join("pg.rs")], &rules, &config).unwrap();
    assert!(
        on_impl.findings.is_empty(),
        "the finding sits in repo.rs, which was not scanned: {:?}",
        on_impl.findings
    );
}

#[test]
fn file_target_of_a_walk_indexes_the_whole_project() {
    // The pre-commit hook passes files as scan paths, not through `--diff`.
    let dir = repository_project(&["Pg", "Mem"]);
    let rules = [single_impl_trait_rule()];
    let result = scan(&[dir.path().join("repo.rs")], &rules, &Config::default()).unwrap();
    assert!(result.findings.is_empty(), "got: {:?}", result.findings);
    assert_eq!(result.stats.files_scanned, 1);
}

#[test]
fn cached_partial_scan_keeps_the_project_cache() {
    let dir = repository_project(&["Pg", "Mem"]);
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    let rules = [single_impl_trait_rule()];
    let config = Config::default();
    let file_target = [dir.path().join("repo.rs")];

    let first = scan_cached(&file_target, &rules, &config, &cache_path).unwrap();
    assert!(first.findings.is_empty(), "got: {:?}", first.findings);
    let second = scan_cached(&file_target, &rules, &config, &cache_path).unwrap();
    assert!(second.findings.is_empty(), "got: {:?}", second.findings);
    assert_eq!(
        second.cache_stats.map(|s| (s.cached, s.changed)),
        Some((1, 0))
    );

    // The index-only files were scanned and stored by the partial runs, so a
    // full scan finds every entry already cached.
    let full = scan_cached(&[dir.path().to_path_buf()], &rules, &config, &cache_path).unwrap();
    assert_eq!(
        full.cache_stats.map(|s| (s.cached, s.changed)),
        Some((3, 0))
    );
}

#[test]
fn cross_file_survives_cache_round_trip() {
    let src_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let cache_path = cache_dir.path().join("cache");
    write(src_dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();
    write(
        src_dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();

    let rules = [single_impl_trait_rule()];
    let config = Config::default();
    let paths = [src_dir.path().to_path_buf()];

    let first = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    assert_eq!(first.findings.len(), 1);
    assert_eq!(first.cache_stats.as_ref().unwrap().changed, 2);

    let second = scan_cached(&paths, &rules, &config, &cache_path).unwrap();
    let stats = second.cache_stats.as_ref().unwrap();
    assert_eq!(stats.cached, 2, "both files should come from the cache");
    assert_eq!(stats.changed, 0);
    assert_eq!(
        second.findings.len(),
        1,
        "symbols must survive the cache round trip"
    );
}

#[test]
fn cross_file_rule_with_no_ast_rules_still_parses_files() {
    let dir = tempdir().unwrap();
    write(dir.path().join("repo.rs"), "pub trait Repository {}\n").unwrap();
    write(
        dir.path().join("pg.rs"),
        "pub struct Pg;\nimpl Repository for Pg {}\n",
    )
    .unwrap();

    let result = scan_dir(dir.path(), &[single_impl_trait_rule()]);
    assert_eq!(
        result.findings.len(),
        1,
        "a cross-file-only ruleset must still parse every file"
    );
}

#[test]
fn all_engine_kinds_run_and_aggregate() {
    // One scan with an AST rule (per-file), a metric rule (per-file) and a
    // cross-file rule (project-level) must return the union of their findings:
    // the orchestrator iterates every registered engine across both scopes.
    let dir = tempdir().unwrap();
    let mut service = String::from(
        "fn main() {\n    foo().unwrap();\n}\npub trait Repo {\n    fn get(&self);\n}\n",
    );
    // Push the file past the file_lines threshold of 10.
    service.push_str(&rust_lines(10));
    write(dir.path().join("service.rs"), service).unwrap();
    write(
        dir.path().join("postgres.rs"),
        "struct Pg;\nimpl Repo for Pg {\n    fn get(&self) {}\n}\n",
    )
    .unwrap();

    let result = scan_dir(
        dir.path(),
        &[unwrap_rule(), file_lines_rule(), single_impl_trait_rule()],
    );

    let ids: HashSet<RuleId> = result.findings.iter().map(|f| f.rule_id.clone()).collect();
    assert!(
        ids.contains(&RuleId::from("test-unwrap")),
        "AST engine finding missing: {ids:?}"
    );
    assert!(
        ids.contains(&RuleId::from("test-file-lines")),
        "metric engine finding missing: {ids:?}"
    );
    assert!(
        ids.contains(&RuleId::from("no-single-impl-trait")),
        "cross-file engine finding missing: {ids:?}"
    );
}
