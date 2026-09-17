use std::collections::HashMap;
use std::fs::{self, read_to_string};
use std::path::{Path, PathBuf};

use ast_grep_config::{
    CombinedScan, GlobalRules, RuleCollection, RuleConfig, RuleConfigError, SerializableRuleConfig,
};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_core::Language as AstLanguage;
use ast_grep_language::SupportLang;
use globset::{Error as GlobError, Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use serde_yaml::with::singleton_map_recursive;
use serde_yaml::{to_value, Value};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::cache::{file_content_hash, rules_hash, CacheStore};
use crate::config::Config;
use crate::disable::filter_disabled;
use crate::finding::{CacheStats, Finding, ScanResult, ScanStats};
use crate::rule::{Language, Rule, RuleId, Severity};
use crate::test_filter::CfgTestRanges;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("failed to compile rule '{id}': {source}")]
    RuleCompile {
        id: RuleId,
        #[source]
        source: RuleConfigError,
    },

    #[error("invalid glob pattern: {0}")]
    Glob(#[from] GlobError),
}

/// The subset of a slopguard rule that ast-grep understands. slopguard-only
/// fields (`category`, `fix` as free text, `tests`) are deliberately left out.
#[derive(Serialize)]
pub struct AstGrepRule<'a> {
    pub id: &'a str,
    pub language: SupportLang,
    pub severity: &'a Severity,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
    pub rule: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignores: Option<&'a [String]>,
}

/// Rules compiled for scanning, plus a way back to the slopguard rule that
/// produced each ast-grep config.
struct CompiledRules<'a> {
    collection: RuleCollection<SupportLang>,
    by_id: HashMap<(&'a str, Language), &'a Rule>,
}

fn extension_to_lang(path: &Path) -> Option<SupportLang> {
    SupportLang::from_path(path)
        .filter(|lang| Language::iter().any(|l| l.ast_grep_langs().contains(lang)))
}

fn support_lang_to_language(lang: SupportLang) -> Language {
    match lang {
        SupportLang::Rust => Language::Rust,
        _ => Language::TypeScript,
    }
}

pub(crate) fn compile_ast_grep_rule(
    rule: &AstGrepRule,
) -> Result<RuleConfig<SupportLang>, RuleConfigError> {
    let inner: SerializableRuleConfig<SupportLang> = to_value(rule)
        .and_then(singleton_map_recursive::deserialize)
        .map_err(RuleConfigError::from)?;
    RuleConfig::try_from(inner, &GlobalRules::default())
}

fn compile_rule(rule: &Rule, lang: SupportLang) -> Result<RuleConfig<SupportLang>, ScanError> {
    let ast_grep_rule = AstGrepRule {
        id: rule.id.as_str(),
        language: lang,
        severity: &rule.severity,
        message: &rule.message,
        note: rule.note.as_deref(),
        rule: &rule.rule,
        files: rule.files.as_deref(),
        ignores: rule.ignores.as_deref(),
    };
    compile_ast_grep_rule(&ast_grep_rule).map_err(|source| ScanError::RuleCompile {
        id: rule.id.clone(),
        source,
    })
}

fn compile_rules(rules: &[Rule]) -> Result<CompiledRules<'_>, ScanError> {
    let configs = rules
        .iter()
        .flat_map(|rule| {
            rule.language
                .ast_grep_langs()
                .iter()
                .map(move |lang| compile_rule(rule, *lang))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledRules {
        collection: RuleCollection::try_new(configs)?,
        by_id: rules
            .iter()
            .map(|rule| ((rule.id.as_str(), rule.language.clone()), rule))
            .collect::<HashMap<_, _>>(),
    })
}

fn build_glob_set(patterns: &[String]) -> Result<GlobSet, GlobError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    builder.build()
}

/// Whether `path` lives in a conventional test, bench, or example tree.
///
/// Rust integration tests, benchmarks, and examples are not `#[cfg(test)]`
/// modules, so `CfgTestRanges` cannot see them. Rules with `skip_test_code`
/// should treat these whole files as test code.
///
/// Matches exact directory names (`tests`, `benches`, `examples`) and also
/// crate-level test directories whose name ends with `_test` or `_tests`
/// (e.g. `integrations_tests`, `e2e_tests`).
fn is_test_path(path: &Path) -> bool {
    let in_test_dir = path.components().any(|c| {
        let Some(name) = c.as_os_str().to_str() else {
            return false;
        };
        matches!(name, "tests" | "benches" | "examples")
            || name.ends_with("_tests")
            || name.ends_with("_test")
            || name.starts_with("test_")
    });
    let test_file_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with("_test") || s.ends_with("_tests"));
    in_test_dir || test_file_name
}

fn scan_file(path: &Path, lang: SupportLang, rules: &CompiledRules) -> Vec<Finding> {
    let applicable = rules.collection.get_rule_from_lang(path, lang);
    if applicable.is_empty() {
        return Vec::new();
    }
    let Ok(source) = read_to_string(path) else {
        return Vec::new();
    };

    let root = lang.ast_grep(&source);
    let combined = CombinedScan::new(applicable);
    let result = combined.scan(&root, false);

    let cfg_test = (lang == SupportLang::Rust && !result.matches.is_empty())
        .then(|| CfgTestRanges::from_root(&root));
    let cfg_test = cfg_test.as_ref();
    let is_test_file = is_test_path(path);

    let findings = result
        .matches
        .into_iter()
        .filter_map(|(config, matches)| {
            let rule_lang = support_lang_to_language(lang);
            let rule = rules.by_id.get(&(config.id.as_str(), rule_lang))?;
            Some((*rule, matches))
        })
        .flat_map(|(rule, matches)| {
            let skip_test_code = rule.skip_test_code;
            matches
                .into_iter()
                .map(move |node_match| {
                    let start = node_match.start_pos();
                    let end = node_match.end_pos();
                    Finding {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        category: rule.category.clone().unwrap_or_default(),
                        message: rule.message.clone(),
                        note: rule.note.clone(),
                        fix: rule.fix.clone(),
                        file: path.to_path_buf(),
                        line: start.line() + 1,
                        column: start.byte_point().1 + 1,
                        end_line: end.line() + 1,
                        end_column: end.byte_point().1 + 1,
                        matched_text: node_match.text().to_string(),
                        confidence: None,
                        escalated: false,
                    }
                })
                .filter(move |f| {
                    if !skip_test_code {
                        return true;
                    }
                    let in_test_code =
                        is_test_file || cfg_test.is_some_and(|r| r.contains_line(f.line));
                    !in_test_code
                })
        })
        .collect();

    filter_disabled(findings, &source)
}

/// Walk `paths` (gitignore-aware) and keep the source files slopguard can parse.
fn walk_files(paths: &[PathBuf], ignores: &GlobSet) -> Vec<(PathBuf, SupportLang)> {
    paths
        .iter()
        .flat_map(|path| WalkBuilder::new(path).build().flatten())
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| !ignores.is_match(path))
        .filter_map(|path| extension_to_lang(&path).map(|lang| (path, lang)))
        .collect()
}

/// Keep the given files as-is (no directory walk), dropping the ones that are
/// ignored by config or written in an unsupported language.
///
/// Deliberately not gitignore-aware: a file git reports as changed must be
/// scanned even when it lives under a hidden or ignored directory.
fn explicit_files(files: &[PathBuf], ignores: &GlobSet) -> Vec<(PathBuf, SupportLang)> {
    files
        .iter()
        .filter(|path| path.is_file())
        .filter(|path| !ignores.is_match(path))
        .filter_map(|path| extension_to_lang(path).map(|lang| (path.clone(), lang)))
        .collect()
}

/// Count errors and warnings in one pass.
pub fn count_severities(findings: &[Finding]) -> (usize, usize) {
    let mut errors = 0;
    let mut warnings = 0;
    for finding in findings {
        match finding.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
        }
    }
    (errors, warnings)
}

/// Sort findings by location and drop duplicates from overlapping rules.
fn normalize_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| (&a.file, a.line, a.column).cmp(&(&b.file, b.line, b.column)));
    findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
    });
}

/// Scan an already-collected file list without touching the cache.
fn scan_collected(files: Vec<(PathBuf, SupportLang)>, compiled: &CompiledRules) -> ScanResult {
    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|(path, lang)| scan_file(path, *lang, compiled))
        .collect();
    normalize_findings(&mut findings);

    let (errors, warnings) = count_severities(&findings);

    ScanResult {
        findings,
        stats: ScanStats {
            errors,
            warnings,
            total: errors + warnings,
            files_scanned: files.len(),
            baseline_filtered: 0,
            diff_base: None,
            files_changed: None,
        },
        cache_stats: None,
    }
}

/// Scan an already-collected file list, reusing cached findings for files
/// whose content hash is unchanged.
///
/// `prune` drops cache entries that no longer correspond to a scanned file. A
/// partial scan must pass `false`: it never saw the other files, so their
/// entries are still valid.
fn scan_collected_cached(
    files: Vec<(PathBuf, SupportLang)>,
    compiled: &CompiledRules,
    rules: &[Rule],
    cache_dir: &Path,
    prune: bool,
) -> ScanResult {
    let store = CacheStore::with_dir(cache_dir.to_path_buf());
    let current_rules_hash = rules_hash(rules);
    let rules_changed = store
        .check_rules_changed(&current_rules_hash)
        .unwrap_or(true);

    let file_contents: Vec<(PathBuf, SupportLang, Vec<u8>, String)> = files
        .into_iter()
        .filter_map(|(path, lang)| {
            let content = fs::read(&path).ok()?;
            let hash = file_content_hash(&content);
            Some((path, lang, content, hash))
        })
        .collect();

    let mut cached_count = 0usize;
    let mut changed_count = 0usize;
    let mut all_findings: Vec<Finding> = Vec::new();

    struct FileWork {
        path: PathBuf,
        lang: SupportLang,
        hash: String,
    }

    let mut to_scan: Vec<FileWork> = Vec::new();

    for (path, lang, _content, hash) in file_contents.iter() {
        if !rules_changed {
            if let Some(cached_findings) = store.get(hash) {
                cached_count += 1;
                all_findings.extend(cached_findings);
                continue;
            }
        }
        changed_count += 1;
        to_scan.push(FileWork {
            path: path.clone(),
            lang: *lang,
            hash: hash.clone(),
        });
    }

    let scanned_findings: Vec<(String, Vec<Finding>)> = to_scan
        .par_iter()
        .map(|work| {
            let findings = scan_file(&work.path, work.lang, compiled);
            (work.hash.clone(), findings)
        })
        .collect();

    for (hash, findings) in scanned_findings {
        store.put(&hash, &findings).ok();
        all_findings.extend(findings);
    }

    if prune {
        let current_hashes: Vec<String> =
            file_contents.iter().map(|(_, _, _, h)| h.clone()).collect();
        store.cleanup(&current_hashes).ok();
    }

    normalize_findings(&mut all_findings);

    let (errors, warnings) = count_severities(&all_findings);

    let files_scanned = cached_count + changed_count;

    ScanResult {
        findings: all_findings,
        stats: ScanStats {
            errors,
            warnings,
            total: errors + warnings,
            files_scanned,
            baseline_filtered: 0,
            diff_base: None,
            files_changed: None,
        },
        cache_stats: Some(CacheStats {
            cached: cached_count,
            changed: changed_count,
        }),
    }
}

/// Scan the given paths for rule violations.
pub fn scan(paths: &[PathBuf], rules: &[Rule], config: &Config) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected(walk_files(paths, &ignores), &compiled))
}

/// Scan with file-level caching. Files whose content hash matches a cached
/// entry (and whose rules have not changed) return cached findings without
/// reparsing.
///
/// `cache_dir` is the directory where cache files are stored. When a custom
/// cache directory is specified (via `--cache-dir`, `SLOPGUARD_CACHE_DIR`,
/// or `scan.cache_dir` in config), pass it directly. Otherwise pass the
/// project root and use `CacheStore::new` which appends `.slopguard-cache`.
pub fn scan_cached(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected_cached(
        walk_files(paths, &ignores),
        &compiled,
        rules,
        cache_dir,
        true,
    ))
}

/// Scan an explicit list of files instead of walking directories.
///
/// Used by `--diff`, where git already produced the exact file set. Paths that
/// no longer exist or that slopguard cannot parse are silently skipped.
pub fn scan_files(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected(explicit_files(files, &ignores), &compiled))
}

/// Cached variant of [`scan_files`]. Cache pruning is skipped: a partial scan
/// must not evict the entries of files it did not look at.
pub fn scan_files_cached(
    files: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<ScanResult, ScanError> {
    let compiled = compile_rules(rules)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    Ok(scan_collected_cached(
        explicit_files(files, &ignores),
        &compiled,
        rules,
        cache_dir,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir, write};

    use tempfile::tempdir;

    use super::*;
    use crate::rule::{load_builtin_rules, parse_rule, RuleId};

    fn unwrap_rule() -> Rule {
        parse_rule(
            r#"
id: test-unwrap
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
        )
        .unwrap()
    }

    fn scan_dir(dir: &Path, rules: &[Rule]) -> ScanResult {
        scan(&[dir.to_path_buf()], rules, &Config::default()).unwrap()
    }

    #[test]
    fn scan_finds_unwrap_violation() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("main.rs"),
            "fn main() {\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.findings.len(), 1);
        let f = &result.findings[0];
        assert_eq!(f.rule_id, RuleId::from("test-unwrap"));
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.line, 2);
        assert!(f.matched_text.contains("unwrap()"));
    }

    #[test]
    fn scan_clean_file_no_findings() {
        let dir = tempdir().unwrap();
        write(dir.path().join("main.rs"), "fn main() { let x = foo(); }\n").unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 1);
    }

    #[test]
    fn scan_unsupported_language_ignored() {
        let dir = tempdir().unwrap();
        write(dir.path().join("script.py"), "x.unwrap()\n").unwrap();
        write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 1);
    }

    #[test]
    fn scan_explicit_file_path() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("main.rs");
        write(&file, "fn main() { foo().unwrap(); }\n").unwrap();
        let result = scan(&[file], &[unwrap_rule()], &Config::default()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.stats.files_scanned, 1);
    }

    #[test]
    fn rule_ignores_glob_respected() {
        let dir = tempdir().unwrap();
        let tests_dir = dir.path().join("tests");
        create_dir(&tests_dir).unwrap();
        write(
            tests_dir.join("test_main.rs"),
            "fn t() { foo().unwrap(); }\n",
        )
        .unwrap();
        write(
            dir.path().join("main.rs"),
            "fn main() { foo().unwrap(); }\n",
        )
        .unwrap();
        let rule = parse_rule(
            r#"
id: ign
language: rust
severity: error
category: correctness
message: x
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
ignores:
  - "**/tests/**"
"#,
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[rule]);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0]
            .file
            .to_string_lossy()
            .contains("main.rs"));
    }

    #[test]
    fn config_ignores_respected() {
        let dir = tempdir().unwrap();
        let gen = dir.path().join("generated");
        create_dir(&gen).unwrap();
        write(gen.join("out.rs"), "fn g() { foo().unwrap(); }\n").unwrap();
        write(
            dir.path().join("main.rs"),
            "fn main() { foo().unwrap(); }\n",
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.scan.ignores = vec!["**/generated/**".to_string()];
        let result = scan(&[dir.path().to_path_buf()], &[unwrap_rule()], &cfg).unwrap();
        assert_eq!(result.stats.files_scanned, 1);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn config_invalid_glob_is_an_error() {
        let dir = tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.scan.ignores = vec!["[".to_string()];
        let err = scan(&[dir.path().to_path_buf()], &[unwrap_rule()], &cfg).unwrap_err();
        assert!(matches!(err, ScanError::Glob(_)), "{err:?}");
    }

    #[test]
    fn rule_without_kind_fails_to_compile() {
        let dir = tempdir().unwrap();
        let rule = parse_rule(
            r#"
id: no-kind
language: rust
severity: error
category: correctness
message: x
rule:
  regex: 'unwrap'
"#,
        )
        .unwrap();
        let err = scan(&[dir.path().to_path_buf()], &[rule], &Config::default()).unwrap_err();
        assert!(
            matches!(&err, ScanError::RuleCompile { id, .. } if *id == RuleId::from("no-kind")),
            "{err:?}"
        );
    }

    #[test]
    fn stats_counting_accurate() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("a.rs"),
            "fn f() { foo().unwrap(); bar().unwrap(); }\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.stats.errors, 2);
        assert_eq!(result.stats.warnings, 0);
        assert_eq!(result.stats.total, 2);
        assert_eq!(result.stats.files_scanned, 1);
    }

    #[test]
    fn scan_empty_file() {
        let dir = tempdir().unwrap();
        write(dir.path().join("empty.rs"), "").unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 1);
    }

    #[test]
    fn scan_complex_rule() {
        let rule = parse_rule(
            r#"
id: dbg
language: rust
severity: error
category: security
message: debug on secret
rule:
  kind: attribute_item
  all:
    - regex: 'derive\([^)]*Debug'
    - precedes:
        kind: struct_item
        has:
          kind: field_identifier
          regex: '^(api_key|password|secret)$'
          stopBy: end
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        write(
            dir.path().join("t.rs"),
            "#[derive(Debug)]\nstruct Config {\n    api_key: String,\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[rule]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, RuleId::from("dbg"));
    }

    #[test]
    fn typescript_rule_applies_to_tsx_files() {
        let rule = parse_rule(
            r#"
id: ts-any
language: typescript
severity: warning
category: slop
message: no any
rule:
  kind: predefined_type
  regex: '^any$'
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        write(dir.path().join("a.ts"), "let x: any = 1;\n").unwrap();
        write(dir.path().join("b.tsx"), "let y: any = 2;\n").unwrap();
        let result = scan_dir(dir.path(), &[rule]);
        assert_eq!(result.stats.files_scanned, 2);
        assert_eq!(result.stats.warnings, 2);
    }

    #[test]
    fn scan_with_disable_comment_filters_findings() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("main.rs"),
            "fn main() {\n    // slopguard-disable-next-line\n    foo().unwrap();\n    bar().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(
            result.findings.len(),
            1,
            "only the non-disabled unwrap should remain"
        );
        assert_eq!(result.findings[0].line, 4);
    }

    #[test]
    fn scan_with_disable_rule_id_filters_only_that_rule() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("main.rs"),
            "fn main() {\n    // slopguard-disable-next-line test-unwrap\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(result.findings.len(), 0);
    }

    fn unwrap_rule_skipping_test_code() -> Rule {
        parse_rule(
            r#"
id: test-unwrap
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
skip_test_code: true
"#,
        )
        .unwrap()
    }

    #[test]
    fn cfg_test_block_excluded_by_post_filter() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("main.rs"),
            "fn prod() {\n    foo().unwrap();\n}\n\n#[cfg(test)]\nmod tests {\n    fn test_it() {\n        bar().unwrap();\n    }\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
        assert_eq!(
            result.findings.len(),
            1,
            "should only find the prod unwrap, not the one inside #[cfg(test)]"
        );
        assert_eq!(result.findings[0].line, 2);
    }

    #[test]
    fn cfg_test_kept_without_skip_test_code() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("main.rs"),
            "fn prod() {\n    foo().unwrap();\n}\n\n#[cfg(test)]\nmod tests {\n    fn test_it() {\n        bar().unwrap();\n    }\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(
            result.findings.len(),
            2,
            "rule without skip_test_code should find both"
        );
    }

    #[test]
    fn integration_test_file_excluded_by_skip_test_code() {
        let dir = tempdir().unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        write(
            tests_dir.join("it.rs"),
            "fn check() {\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
        assert_eq!(
            result.findings.len(),
            0,
            "unwrap inside a tests/ integration file should be skipped"
        );
    }

    #[test]
    fn integration_test_file_kept_without_skip_test_code() {
        let dir = tempdir().unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        write(
            tests_dir.join("it.rs"),
            "fn check() {\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(
            result.findings.len(),
            1,
            "rule without skip_test_code should still flag tests/ files"
        );
    }

    #[test]
    fn test_crate_directory_excluded_by_skip_test_code() {
        let dir = tempdir().unwrap();
        let test_crate = dir
            .path()
            .join("crates")
            .join("integrations_tests")
            .join("src");
        std::fs::create_dir_all(&test_crate).unwrap();
        write(
            test_crate.join("api.rs"),
            "fn check() {\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule_skipping_test_code()]);
        assert_eq!(
            result.findings.len(),
            0,
            "unwrap inside a *_tests crate should be skipped"
        );
    }

    #[test]
    fn test_crate_directory_kept_without_skip_test_code() {
        let dir = tempdir().unwrap();
        let test_crate = dir
            .path()
            .join("crates")
            .join("integrations_tests")
            .join("src");
        std::fs::create_dir_all(&test_crate).unwrap();
        write(
            test_crate.join("api.rs"),
            "fn check() {\n    foo().unwrap();\n}\n",
        )
        .unwrap();
        let result = scan_dir(dir.path(), &[unwrap_rule()]);
        assert_eq!(
            result.findings.len(),
            1,
            "rule without skip_test_code should still flag *_tests crate files"
        );
    }

    #[test]
    fn all_builtin_rules_compile() {
        let rules = load_builtin_rules().unwrap();
        assert!(
            rules.len() >= 55,
            "expected at least 55 rules, got {}",
            rules.len()
        );
        let compiled = compile_rules(&rules).expect("all builtin rules should compile");
        assert_eq!(compiled.by_id.len(), rules.len());
    }

    #[test]
    fn scan_files_only_scans_given_files() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.rs");
        let b = dir.path().join("b.rs");
        write(&a, "fn a() {\n    foo().unwrap();\n}\n").unwrap();
        write(&b, "fn b() {\n    bar().unwrap();\n}\n").unwrap();

        let result = scan_files(&[a], &[unwrap_rule()], &Config::default()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.stats.files_scanned, 1);
        assert!(result.findings[0].file.to_string_lossy().contains("a.rs"));
    }

    #[test]
    fn scan_files_skips_unsupported_language() {
        let dir = tempdir().unwrap();
        let py = dir.path().join("script.py");
        write(&py, "x.unwrap()\n").unwrap();

        let result = scan_files(&[py], &[unwrap_rule()], &Config::default()).unwrap();
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 0);
    }

    #[test]
    fn scan_files_skips_missing_file() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("gone.rs");

        let result = scan_files(&[missing], &[unwrap_rule()], &Config::default()).unwrap();
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 0);
    }

    #[test]
    fn scan_files_respects_config_ignores() {
        let dir = tempdir().unwrap();
        let gen = dir.path().join("generated");
        create_dir(&gen).unwrap();
        let out = gen.join("out.rs");
        write(&out, "fn g() { foo().unwrap(); }\n").unwrap();

        let mut cfg = Config::default();
        cfg.scan.ignores = vec!["**/generated/**".to_string()];
        let result = scan_files(&[out], &[unwrap_rule()], &cfg).unwrap();
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.stats.files_scanned, 0);
    }

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
}
