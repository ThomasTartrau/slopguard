use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use ast_grep_config::{
    GlobalRules, RuleCollection, RuleConfig, RuleConfigError, SerializableRuleConfig,
};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_core::Language as AstLanguage;
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
use crate::rule::{Language, Rule, RuleId, Severity};
use crate::test_filter::{CfgTestRanges, TestPaths};

use engine::{
    AstEngine, BoxedEngine, CrossFileEngine, CrossFileRule, EngineScope, FileContext, MetricEngine,
    MetricRule, ProjectContext, RuleContext,
};

mod engine;
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
    /// ast-grep metavariable constraints (sibling of `rule`). `None` when the
    /// slopguard rule sets none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<&'a Value>,
    /// ast-grep `fix` template. Only set by the `--fix` pass (from the rule's
    /// `rewrite`); the detection pass leaves it `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignores: Option<&'a [String]>,
}

/// Rules compiled for scanning, plus a way back to the slopguard rule that
/// produced each ast-grep config. Holds the raw compiled data; the registered
/// [`RuleEngine`]s that read it are built on demand.
struct CompiledRules<'a> {
    collection: RuleCollection<SupportLang>,
    by_id: HashMap<(&'a str, Language), &'a Rule>,
    metrics: Vec<MetricRule<'a>>,
    cross_file: Vec<CrossFileRule<'a>>,
    /// Which paths `skip_test_code` rules treat as test code (built-in
    /// heuristic plus configured `scan.test_paths`).
    test_paths: TestPaths,
}

impl CompiledRules<'_> {
    /// The registered engines, split into the per-file phase and the
    /// project-level phase by their declared [`EngineScope`]. The AST engine is
    /// always registered; the metric and cross-file engines only when rules of
    /// their kind exist.
    fn engines(&self) -> (Vec<BoxedEngine<'_>>, Vec<BoxedEngine<'_>>) {
        let mut all: Vec<BoxedEngine<'_>> = vec![Box::new(AstEngine {
            collection: &self.collection,
            by_id: &self.by_id,
        })];
        if !self.metrics.is_empty() {
            all.push(Box::new(MetricEngine {
                rules: &self.metrics,
            }));
        }
        if !self.cross_file.is_empty() {
            all.push(Box::new(CrossFileEngine {
                rules: &self.cross_file,
            }));
        }
        all.into_iter()
            .partition(|e| matches!(e.scope(), EngineScope::PerFile))
    }
}

fn extension_to_lang(path: &Path) -> Option<SupportLang> {
    SupportLang::from_path(path)
        .filter(|lang| Language::iter().any(|l| l.ast_grep_langs().contains(lang)))
}

pub(crate) fn support_lang_to_language(lang: SupportLang) -> Language {
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
        constraints: (!rule.constraints.is_null()).then_some(&rule.constraints),
        fix: None,
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

pub(crate) fn build_glob_set(patterns: &[String]) -> Result<GlobSet, GlobError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    builder.build()
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
    per_file: &[BoxedEngine],
    test_paths: &TestPaths,
    collect_symbols: bool,
) -> FileScan {
    let applies = per_file.iter().any(|e| e.applies_to_file(path, lang));
    // A run scoped to a single cross-file rule has no ast-grep and no metric
    // rule, yet the file still has to be parsed for its symbols.
    let want_symbols = collect_symbols && lang == SupportLang::Rust;
    if !applies && !want_symbols {
        return FileScan::default();
    }
    let Ok(source) = read_to_string(path) else {
        return FileScan::default();
    };

    let root = lang.ast_grep(&source);
    // Built once and shared by every per-file engine and the symbol extractor.
    let cfg_test = (lang == SupportLang::Rust).then(|| CfgTestRanges::from_root(&root));

    let ctx = RuleContext::File(FileContext {
        path,
        lang,
        rule_lang: support_lang_to_language(lang),
        source: &source,
        root: &root,
        cfg_test: cfg_test.as_ref(),
        is_test_file: test_paths.is_test(path),
        test_paths,
    });

    let mut findings: Vec<Finding> = Vec::new();
    for engine in per_file {
        findings.extend(engine.evaluate(&ctx));
    }

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

/// Run the project-level engines and append their findings, if they are due.
///
/// A full scan asks for it via `run_cross_file`; a partial scan (`--diff`,
/// explicit files) collects contributions to warm the cache but leaves the
/// index incomplete, so it must not evaluate. Centralises the `run_cross_file &&
/// has project engines` invariant shared by both scan paths.
fn append_cross_file(
    findings: &mut Vec<Finding>,
    project: &[BoxedEngine],
    run_cross_file: bool,
    contributions: &[(PathBuf, FileSymbols)],
) {
    if !run_cross_file || project.is_empty() {
        return;
    }
    let index = SymbolIndex::build(contributions.iter().map(|(p, s)| (p.as_path(), s)));
    let ctx = RuleContext::Project(ProjectContext { index: &index });
    for engine in project {
        findings.extend(engine.evaluate(&ctx));
    }
}

/// Walk `paths` (gitignore-aware) and keep the source files slopguard can parse.
pub(crate) fn walk_files(paths: &[PathBuf], ignores: &GlobSet) -> Vec<(PathBuf, SupportLang)> {
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
pub(crate) fn explicit_files(files: &[PathBuf], ignores: &GlobSet) -> Vec<(PathBuf, SupportLang)> {
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
