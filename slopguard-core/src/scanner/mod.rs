use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use ast_grep_config::{
    CombinedScan, GlobalRules, RuleCollection, RuleConfig, RuleConfigError, SerializableRuleConfig,
};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_core::Language as AstLanguage;
use ast_grep_core::{AstGrep, Doc};
use ast_grep_language::SupportLang;
use globset::{Error as GlobError, Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::Serialize;
use serde_yaml::with::singleton_map_recursive;
use serde_yaml::{to_value, Value};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::cross_file::{self, CrossFileKind, DeclFilter, FileSymbols, SymbolIndex};
use crate::disable::filter_disabled;
use crate::finding::Finding;
use crate::metric::{self, Metric};
use crate::rule::{Language, Rule, RuleId, Severity};
use crate::test_filter::{CfgTestRanges, TestPaths};

mod orchestrate;

pub use orchestrate::{count_severities, scan, scan_cached, scan_files, scan_files_cached};

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

    #[error("rule '{id}': metric rule is missing a threshold")]
    InvalidMetricRule { id: RuleId },
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
    metrics: Vec<MetricRule<'a>>,
    cross_file: Vec<CrossFileRule<'a>>,
    /// Which paths `skip_test_code` rules treat as test code (built-in
    /// heuristic plus configured `scan.test_paths`).
    test_paths: TestPaths,
}

/// A cross-file rule prepared for scanning: kind resolved and the declaration
/// filter compiled once.
struct CrossFileRule<'a> {
    rule: &'a Rule,
    kind: CrossFileKind,
    decl_filter: DeclFilter,
}

/// A metric rule prepared for scanning: threshold resolved and `files` /
/// `ignores` globs compiled once. ast-grep applies those globs for AST rules;
/// metric rules are evaluated outside ast-grep so they apply them here.
struct MetricRule<'a> {
    rule: &'a Rule,
    metric: Metric,
    threshold: f64,
    min_lines: Option<usize>,
    files: Option<GlobSet>,
    ignores: Option<GlobSet>,
}

impl MetricRule<'_> {
    fn applies_to(&self, path: &Path, lang: &Language) -> bool {
        self.rule.language == *lang
            && self.files.as_ref().is_none_or(|g| g.is_match(path))
            && !self.ignores.as_ref().is_some_and(|g| g.is_match(path))
    }
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

/// Resolve a metric rule's threshold and compile its path globs.
fn build_metric_rule(rule: &Rule) -> Result<MetricRule<'_>, ScanError> {
    let Some((metric, threshold)) = rule.metric_spec() else {
        return Err(ScanError::InvalidMetricRule {
            id: rule.id.clone(),
        });
    };
    Ok(MetricRule {
        rule,
        metric,
        threshold,
        min_lines: rule.min_lines,
        files: rule.files.as_deref().map(build_glob_set).transpose()?,
        ignores: rule.ignores.as_deref().map(build_glob_set).transpose()?,
    })
}

/// Compile the globs that bound which declarations a cross-file rule may
/// report. The `kind` is resolved by the caller, which already partitioned the
/// rules on `is_cross_file()`.
fn build_cross_file_rule<'a>(
    rule: &'a Rule,
    kind: CrossFileKind,
    test_paths: &TestPaths,
) -> Result<CrossFileRule<'a>, ScanError> {
    Ok(CrossFileRule {
        rule,
        kind,
        decl_filter: DeclFilter {
            files: rule.files.as_deref().map(build_glob_set).transpose()?,
            ignores: rule.ignores.as_deref().map(build_glob_set).transpose()?,
            skip_test_code: rule.skip_test_code,
            test_paths: test_paths.clone(),
        },
    })
}

fn compile_rules<'a>(
    rules: &'a [Rule],
    test_paths: TestPaths,
) -> Result<CompiledRules<'a>, ScanError> {
    // Neither cross-file nor metric rules may reach ast-grep: their `rule`
    // field is null and would fail to compile.
    let (cross_rules, rest): (Vec<&Rule>, Vec<&Rule>) =
        rules.iter().partition(|r| r.is_cross_file());
    let (metric_rules, ast_rules): (Vec<&Rule>, Vec<&Rule>) =
        rest.into_iter().partition(|r| r.is_metric());

    let configs = ast_rules
        .iter()
        .copied()
        .flat_map(|rule| {
            rule.language
                .ast_grep_langs()
                .iter()
                .map(move |lang| compile_rule(rule, *lang))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cross_file = cross_rules
        .into_iter()
        .filter_map(|rule| rule.cross_file_kind().map(|kind| (rule, kind)))
        .map(|(rule, kind)| build_cross_file_rule(rule, kind, &test_paths))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledRules {
        collection: RuleCollection::try_new(configs)?,
        by_id: ast_rules
            .iter()
            .copied()
            .map(|rule| ((rule.id.as_str(), rule.language.clone()), rule))
            .collect::<HashMap<_, _>>(),
        metrics: metric_rules
            .into_iter()
            .map(build_metric_rule)
            .collect::<Result<Vec<_>, _>>()?,
        cross_file,
        test_paths,
    })
}

fn build_glob_set(patterns: &[String]) -> Result<GlobSet, GlobError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    builder.build()
}

/// One finding per metric rule whose measured value exceeds its threshold.
///
/// File-level findings have no source position, so they are anchored at 1:1.
/// `skip_test_code` drops the whole file: a line-1 finding can never be inside
/// a `#[cfg(test)]` block.
fn metric_findings<D: Doc>(
    metrics: &[&MetricRule],
    path: &Path,
    root: &AstGrep<D>,
    source: &str,
    lang: &Language,
    test_paths: &TestPaths,
    cfg_test: Option<&CfgTestRanges>,
) -> Vec<Finding> {
    metrics
        .iter()
        .filter(|m| !(m.rule.skip_test_code && test_paths.is_test(path)))
        .filter(|m| {
            m.min_lines
                .is_none_or(|floor| source.lines().count() >= floor)
        })
        .filter_map(|m| {
            // A `skip_test_code` rule also ignores inline `#[cfg(test)]` code, so
            // a production file's test module does not inflate the metric.
            let exclude = m.rule.skip_test_code.then_some(cfg_test).flatten();
            let value = metric::compute(m.metric, lang, root, source, exclude);
            if !metric::exceeds(value, m.threshold) {
                return None;
            }
            let rendered = m.metric.format_value(value);
            Some(Finding {
                rule_id: m.rule.id.clone(),
                severity: m.rule.severity.clone(),
                category: m.rule.category.clone().unwrap_or_default(),
                message: m.rule.message.replace("$value", &rendered),
                note: m.rule.note.clone(),
                fix: m.rule.fix.clone(),
                file: path.to_path_buf(),
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
                matched_text: m.metric.describe(value),
                confidence: None,
                escalated: false,
            })
        })
        .collect()
}

/// One file's contribution to a scan: its findings plus, when a cross-file
/// rule is active, the symbols it adds to the project index. Both come out of
/// a single parse.
#[derive(Default)]
struct FileScan {
    findings: Vec<Finding>,
    symbols: FileSymbols,
}

fn scan_file(
    path: &Path,
    lang: SupportLang,
    rules: &CompiledRules,
    collect_symbols: bool,
) -> FileScan {
    let rule_lang = support_lang_to_language(lang);
    let applicable = rules.collection.get_rule_from_lang(path, lang);
    let metrics: Vec<&MetricRule> = rules
        .metrics
        .iter()
        .filter(|m| m.applies_to(path, &rule_lang))
        .collect();
    // A run scoped to a single cross-file rule has no ast-grep and no metric
    // rule, yet the file still has to be parsed for its symbols.
    let want_symbols = collect_symbols && lang == SupportLang::Rust;
    if applicable.is_empty() && metrics.is_empty() && !want_symbols {
        return FileScan::default();
    }
    let Ok(source) = read_to_string(path) else {
        return FileScan::default();
    };

    let root = lang.ast_grep(&source);
    // Built once and shared by the finding filter and the symbol extractor.
    let cfg_test = (lang == SupportLang::Rust).then(|| CfgTestRanges::from_root(&root));

    let mut findings: Vec<Finding> = if applicable.is_empty() {
        Vec::new()
    } else {
        let combined = CombinedScan::new(applicable);
        let result = combined.scan(&root, false);

        let cfg_test = cfg_test.as_ref();
        let is_test_file = rules.test_paths.is_test(path);

        result
            .matches
            .into_iter()
            .filter_map(|(config, matches)| {
                let rule = rules.by_id.get(&(config.id.as_str(), rule_lang.clone()))?;
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
            .collect()
    };

    findings.extend(metric_findings(
        &metrics,
        path,
        &root,
        &source,
        &rule_lang,
        &rules.test_paths,
        cfg_test.as_ref(),
    ));

    // Symbols are not run through `filter_disabled`: suppression applies to the
    // cross-file findings emitted later, against the declaration file's source.
    let symbols = match (want_symbols, cfg_test.as_ref()) {
        (true, Some(ranges)) => cross_file::extract_rust_symbols(&root, ranges),
        _ => FileSymbols::default(),
    };

    FileScan {
        findings: filter_disabled(findings, &source),
        symbols,
    }
}

/// Assemble the project index from every file's contribution, evaluate each
/// active cross-file rule, then drop the findings a disable comment suppresses
/// in the file that declares the symbol.
fn cross_file_findings(
    rules: &[CrossFileRule<'_>],
    contributions: &[(PathBuf, FileSymbols)],
) -> Vec<Finding> {
    let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
    let mut by_file: HashMap<PathBuf, Vec<Finding>> = HashMap::new();
    for rule in rules {
        let found = cross_file::evaluate(rule.rule, rule.kind, &index, &rule.decl_filter);
        for finding in found {
            by_file
                .entry(finding.file.clone())
                .or_default()
                .push(finding);
        }
    }
    by_file
        .into_iter()
        .flat_map(|(path, findings)| match read_to_string(&path) {
            // A file that can no longer be read keeps its findings unfiltered
            // rather than losing them.
            Ok(source) => filter_disabled(findings, &source),
            Err(_) => findings,
        })
        .collect()
}

/// Run the cross-file pass and append its findings, if it is due. A full scan
/// asks for it via `run_cross_file`; a partial scan (`--diff`, explicit files)
/// collects contributions to warm the cache but leaves the index incomplete, so
/// it must not evaluate. Centralises the `run_cross_file && has cross-file
/// rules` invariant shared by both scan paths.
fn append_cross_file(
    findings: &mut Vec<Finding>,
    compiled: &CompiledRules,
    run_cross_file: bool,
    contributions: &[(PathBuf, FileSymbols)],
) {
    if run_cross_file && !compiled.cross_file.is_empty() {
        findings.extend(cross_file_findings(&compiled.cross_file, contributions));
    }
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

#[cfg(test)]
mod feature_tests;
#[cfg(test)]
mod scan_tests;
#[cfg(test)]
mod test_support;
