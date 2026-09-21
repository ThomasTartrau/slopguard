//! The rule-engine abstraction. Every in-process rule kind (AST, metric,
//! cross-file) implements [`RuleEngine`], and the scanner iterates over the
//! registered engines instead of calling each pass by hand. Adding a kind
//! (import resolution, clone detection) means adding an engine, not rewiring the
//! orchestrator.
//!
//! The AI pass is deliberately not an engine: it is async, needs an external
//! provider, and runs a two-phase candidate flow. It stays orchestrated by the
//! CLI (`slopguard-cli`), which already partitions AI rules out on `ai_check`.

use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use ast_grep_config::{CombinedScan, RuleCollection};
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;
use globset::GlobSet;

use crate::cross_file::{self, CrossFileKind, DeclFilter, SymbolIndex};
use crate::disable::filter_disabled;
use crate::finding::Finding;
use crate::metric::{self, Metric};
use crate::rule::{Language, Rule};
use crate::test_filter::{CfgTestRanges, TestPaths};

use super::support_lang_to_language;

/// A parsed source document, as produced by `SupportLang::ast_grep`. Every
/// per-file engine reads from the one parse the orchestrator did.
pub(crate) type Tree = AstGrep<StrDoc<SupportLang>>;

/// A registered engine, boxed for uniform iteration. `Sync` is required because
/// the per-file phase runs under rayon.
pub(crate) type BoxedEngine<'a> = Box<dyn RuleEngine + Sync + 'a>;

/// Whether an engine contributes findings once per parsed file or once over the
/// assembled project index.
pub(crate) enum EngineScope {
    PerFile,
    Project,
}

/// Everything a per-file engine sees, all derived from a single parse.
pub(crate) struct FileContext<'a> {
    pub path: &'a Path,
    /// The ast-grep language, needed to re-select applicable ast-grep rules.
    pub lang: SupportLang,
    /// The slopguard language the file is scanned as.
    pub rule_lang: Language,
    pub source: &'a str,
    pub root: &'a Tree,
    pub cfg_test: Option<&'a CfgTestRanges>,
    pub is_test_file: bool,
    pub test_paths: &'a TestPaths,
}

/// Everything a project-level engine sees: the index assembled from every
/// file's symbol contribution.
pub(crate) struct ProjectContext<'a> {
    pub index: &'a SymbolIndex,
}

/// The context handed to [`RuleEngine::evaluate`]. A per-file engine reads the
/// `File` variant, a project engine reads `Project`. One signature is what lets
/// the orchestrator treat every engine the same.
pub(crate) enum RuleContext<'a> {
    File(FileContext<'a>),
    Project(ProjectContext<'a>),
}

/// A single rule kind, evaluated uniformly by the scanner.
pub(crate) trait RuleEngine {
    fn scope(&self) -> EngineScope;

    /// Whether a per-file engine has any work for this file, decided before the
    /// file is parsed so an irrelevant file is never read. Project engines leave
    /// this at the default.
    fn applies_to_file(&self, _path: &Path, _lang: SupportLang) -> bool {
        false
    }

    /// Whether this engine needs the per-file symbol contributions so its
    /// project pass can build an index. Only project engines override this.
    fn needs_symbols(&self) -> bool {
        false
    }

    /// Findings this engine contributes for the given context. A per-file engine
    /// returns nothing for a `Project` context and vice versa.
    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding>;
}

/// The AST engine: ast-grep rules run through `CombinedScan`, matched back to
/// the slopguard rule that produced each config.
pub(crate) struct AstEngine<'a> {
    pub collection: &'a RuleCollection<SupportLang>,
    pub by_id: &'a HashMap<(&'a str, Language), &'a Rule>,
}

impl RuleEngine for AstEngine<'_> {
    fn scope(&self) -> EngineScope {
        EngineScope::PerFile
    }

    fn applies_to_file(&self, path: &Path, lang: SupportLang) -> bool {
        !self.collection.get_rule_from_lang(path, lang).is_empty()
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let RuleContext::File(fc) = ctx else {
            return Vec::new();
        };
        let applicable = self.collection.get_rule_from_lang(fc.path, fc.lang);
        if applicable.is_empty() {
            return Vec::new();
        }
        let combined = CombinedScan::new(applicable);
        let result = combined.scan(fc.root, false);

        let cfg_test = fc.cfg_test;
        let is_test_file = fc.is_test_file;
        let rule_lang = fc.rule_lang.clone();

        result
            .matches
            .into_iter()
            .filter_map(|(config, matches)| {
                let rule = self.by_id.get(&(config.id.as_str(), rule_lang.clone()))?;
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
                            file: fc.path.to_path_buf(),
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
    }
}

/// A metric rule prepared for scanning: threshold resolved and `files` /
/// `ignores` globs compiled once. ast-grep applies those globs for AST rules;
/// metric rules are evaluated outside ast-grep so they apply them here.
pub(crate) struct MetricRule<'a> {
    pub rule: &'a Rule,
    pub metric: Metric,
    pub threshold: f64,
    pub min_lines: Option<usize>,
    pub files: Option<GlobSet>,
    pub ignores: Option<GlobSet>,
}

impl MetricRule<'_> {
    fn applies_to(&self, path: &Path, lang: &Language) -> bool {
        self.rule.language == *lang
            && self.files.as_ref().is_none_or(|g| g.is_match(path))
            && !self.ignores.as_ref().is_some_and(|g| g.is_match(path))
    }
}

/// The metric engine: file-level measurements compared against a threshold.
pub(crate) struct MetricEngine<'a> {
    pub rules: &'a [MetricRule<'a>],
}

impl RuleEngine for MetricEngine<'_> {
    fn scope(&self) -> EngineScope {
        EngineScope::PerFile
    }

    fn applies_to_file(&self, path: &Path, lang: SupportLang) -> bool {
        let rule_lang = support_lang_to_language(lang);
        self.rules.iter().any(|m| m.applies_to(path, &rule_lang))
    }

    /// One finding per metric rule whose measured value exceeds its threshold.
    ///
    /// File-level findings have no source position, so they are anchored at 1:1.
    /// `skip_test_code` drops the whole file: a line-1 finding can never be
    /// inside a `#[cfg(test)]` block.
    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let RuleContext::File(fc) = ctx else {
            return Vec::new();
        };
        self.rules
            .iter()
            .filter(|m| m.applies_to(fc.path, &fc.rule_lang))
            .filter(|m| !(m.rule.skip_test_code && fc.test_paths.is_test(fc.path)))
            .filter(|m| {
                m.min_lines
                    .is_none_or(|floor| fc.source.lines().count() >= floor)
            })
            .filter_map(|m| {
                // A `skip_test_code` rule also ignores inline `#[cfg(test)]`
                // code, so a production file's test module does not inflate the
                // metric.
                let exclude = m.rule.skip_test_code.then_some(fc.cfg_test).flatten();
                let value = metric::compute(m.metric, &fc.rule_lang, fc.root, fc.source, exclude);
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
                    file: fc.path.to_path_buf(),
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
}

/// A cross-file rule prepared for scanning: kind resolved and the declaration
/// filter compiled once.
pub(crate) struct CrossFileRule<'a> {
    pub rule: &'a Rule,
    pub kind: CrossFileKind,
    pub decl_filter: DeclFilter,
}

/// The cross-file engine: project-level analysis over the assembled symbol
/// index.
pub(crate) struct CrossFileEngine<'a> {
    pub rules: &'a [CrossFileRule<'a>],
    /// When false, findings are returned raw (disable comments are not applied).
    /// Used by the `--report-unused-disable` pass, which needs to know which
    /// directives would have suppressed a cross-file finding.
    pub apply_disable: bool,
}

impl RuleEngine for CrossFileEngine<'_> {
    fn scope(&self) -> EngineScope {
        EngineScope::Project
    }

    fn needs_symbols(&self) -> bool {
        true
    }

    /// Evaluate each active cross-file rule against the project index, then drop
    /// the findings a disable comment suppresses in the file that declares the
    /// symbol.
    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let RuleContext::Project(pc) = ctx else {
            return Vec::new();
        };
        let mut by_file: HashMap<PathBuf, Vec<Finding>> = HashMap::new();
        for rule in self.rules {
            let found = cross_file::evaluate(rule.rule, rule.kind, pc.index, &rule.decl_filter);
            for finding in found {
                by_file
                    .entry(finding.file.clone())
                    .or_default()
                    .push(finding);
            }
        }
        by_file
            .into_iter()
            .flat_map(|(path, findings)| {
                if !self.apply_disable {
                    return findings;
                }
                match read_to_string(&path) {
                    // A file that can no longer be read keeps its findings
                    // unfiltered rather than losing them.
                    Ok(source) => filter_disabled(findings, &source),
                    Err(_) => findings,
                }
            })
            .collect()
    }
}
