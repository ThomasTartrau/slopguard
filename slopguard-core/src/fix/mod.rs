//! `scan --fix`: apply the `rewrite` template of autofix-safe rules in place.
//!
//! The detection pass never touches `rewrite`. This module compiles each
//! autofixable rule with its `rewrite` as the ast-grep `fix`, matches the source
//! directly (so it can re-match a mutated buffer and reach a fix point), and
//! applies the resulting edits. Findings that detection would suppress -- inside
//! test code, disabled inline, or recorded in the baseline -- are never
//! rewritten, mirroring the scanner's own filters.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use ast_grep_config::RuleConfig;
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;

use crate::baseline::{finding_hash, Baseline};
use crate::config::Config;
use crate::disable::is_disabled;
use crate::finding::Finding;
use crate::rule::{Category, Rule, RuleId, Severity};
use crate::scanner::{build_glob_set, compile_ast_grep_rule, walk_files, AstGrepRule, ScanError};
use crate::test_filter::{CfgTestRanges, TestPaths};

/// Upper bound on the re-scan/re-apply cycles per file. Fixing overlapping or
/// nested matches can expose new ones; the loop stops at a fix point or here.
const MAX_ITERATIONS: usize = 10;

/// One autofixable rule compiled for a specific ast-grep language, keeping a way
/// back to the slopguard rule identity for filtering.
struct CompiledFixRule {
    rule_id: RuleId,
    lang: SupportLang,
    skip_test_code: bool,
    config: RuleConfig<SupportLang>,
}

/// A single text replacement, decoupled from ast-grep's borrowed `Edit` so it
/// outlives the parsed tree.
struct RawEdit {
    position: usize,
    deleted_length: usize,
    inserted: Vec<u8>,
}

/// The rewrite of one file: kept only when the content actually changed.
pub struct FileFix {
    pub path: PathBuf,
    pub original: String,
    pub fixed: String,
}

/// Outcome of a `--fix` run over one or more paths.
#[derive(Default)]
pub struct FixReport {
    /// Files whose content changed, with their before/after text.
    pub files: Vec<FileFix>,
    /// Total number of edits applied across every file.
    pub applied: usize,
}

impl FixReport {
    /// Number of files whose content changed.
    pub fn files_changed(&self) -> usize {
        self.files.len()
    }
}

/// Compile every autofixable rule (`autofix_safe` + `rewrite`) with its rewrite
/// as the ast-grep fix template, once per ast-grep language it targets.
fn compile_fix_rules(rules: &[Rule]) -> Result<Vec<CompiledFixRule>, ScanError> {
    let mut compiled = Vec::new();
    for rule in rules.iter().filter(|r| r.is_autofixable()) {
        // `is_autofixable` guarantees `rewrite` is present.
        let Some(rewrite) = rule.rewrite.as_deref() else {
            continue;
        };
        // A dedicated `autofix_rule` is self-contained: its metavariables need
        // not match those of the detection `rule`, so detection `constraints`
        // (which reference the detection rule's metavariables) do not apply.
        let uses_dedicated_matcher = !rule.autofix_rule.is_null();
        let constraints =
            (!uses_dedicated_matcher && !rule.constraints.is_null()).then_some(&rule.constraints);
        for &lang in rule.language.ast_grep_langs() {
            let ast_grep_rule = AstGrepRule {
                id: rule.id.as_str(),
                language: lang,
                severity: &rule.severity,
                message: &rule.message,
                note: rule.note.as_deref(),
                rule: rule.fix_matcher(),
                constraints,
                fix: Some(rewrite),
                files: rule.files.as_deref(),
                ignores: rule.ignores.as_deref(),
            };
            let config =
                compile_ast_grep_rule(&ast_grep_rule).map_err(|source| ScanError::RuleCompile {
                    id: rule.id.clone(),
                    source,
                })?;
            compiled.push(CompiledFixRule {
                rule_id: rule.id.clone(),
                lang,
                skip_test_code: rule.skip_test_code,
                config,
            });
        }
    }
    Ok(compiled)
}

/// The baseline hashes to skip, empty when no baseline is active.
fn baseline_hash_set(baseline: Option<&Baseline>) -> HashSet<String> {
    baseline
        .map(|b| b.findings.iter().map(|e| e.hash.clone()).collect())
        .unwrap_or_default()
}

/// Apply non-overlapping edits (sorted ascending) to `source`, right to left so
/// earlier positions stay valid.
fn apply_edits(source: &str, edits: &[RawEdit]) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for edit in edits.iter().rev() {
        let end = edit.position + edit.deleted_length;
        if end > bytes.len() {
            continue;
        }
        bytes.splice(edit.position..end, edit.inserted.iter().copied());
    }
    String::from_utf8(bytes).unwrap_or_else(|_| source.to_string())
}

/// Greedily keep the edits that do not overlap a previously kept one. Input must
/// be sorted by position. An edit starting before the running end (a nested or
/// duplicate match) is dropped and left for the next fix-point iteration.
fn select_non_overlapping(mut edits: Vec<RawEdit>) -> Vec<RawEdit> {
    edits.sort_by_key(|e| e.position);
    let mut kept: Vec<RawEdit> = Vec::new();
    let mut last_end = 0usize;
    for edit in edits {
        if edit.position >= last_end {
            last_end = edit.position + edit.deleted_length;
            kept.push(edit);
        }
    }
    kept
}

/// Collect the edits due for `source` in one pass, honoring the same filters as
/// detection: `skip_test_code` (path heuristic and inline `#[cfg(test)]`),
/// inline disable directives, and baseline membership.
fn collect_edits(
    source: &str,
    path: &Path,
    lang: SupportLang,
    rules: &[CompiledFixRule],
    test_paths: &TestPaths,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> Vec<RawEdit> {
    let ast = lang.ast_grep(source);
    let cfg_test = (lang == SupportLang::Rust).then(|| CfgTestRanges::from_root(&ast));
    let is_test_file = test_paths.is_test(path);

    let mut edits = Vec::new();
    for rule in rules.iter().filter(|r| r.lang == lang) {
        let Some(fixer) = rule.config.fixer.first() else {
            continue;
        };
        for node_match in ast.root().find_all(&rule.config.matcher) {
            let start_line = node_match.start_pos().line() + 1;

            let in_test_code = rule.skip_test_code
                && (is_test_file
                    || cfg_test
                        .as_ref()
                        .is_some_and(|ranges| ranges.contains_line(start_line)));
            if in_test_code {
                continue;
            }
            if is_disabled(source, start_line, &rule.rule_id) {
                continue;
            }
            if !baseline_hashes.is_empty() {
                let finding = position_finding(&rule.rule_id, path, start_line, &node_match.text());
                let hash = finding_hash(&finding, baseline_root, Some(source));
                if baseline_hashes.contains(&hash) {
                    continue;
                }
            }

            let edit = node_match.make_edit(&rule.config.matcher, fixer);
            edits.push(RawEdit {
                position: edit.position,
                deleted_length: edit.deleted_length,
                inserted: edit.inserted_text,
            });
        }
    }
    edits
}

/// A finding shaped only for baseline hashing: `finding_hash` reads the rule id,
/// path, line (for context) and matched text; the rest is filler.
fn position_finding(rule_id: &RuleId, path: &Path, line: usize, matched: &str) -> Finding {
    Finding {
        rule_id: rule_id.clone(),
        severity: Severity::Warning,
        category: Category::Correctness,
        message: String::new(),
        note: None,
        fix: None,
        file: path.to_path_buf(),
        line,
        column: 1,
        end_line: line,
        end_column: 1,
        matched_text: matched.to_string(),
        confidence: None,
        escalated: false,
    }
}

/// Rewrite one file's content to a fix point.
fn fix_source(
    original: &str,
    path: &Path,
    lang: SupportLang,
    rules: &[CompiledFixRule],
    test_paths: &TestPaths,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> (String, usize) {
    let mut source = original.to_string();
    let mut applied = 0;
    for _ in 0..MAX_ITERATIONS {
        let edits = collect_edits(
            &source,
            path,
            lang,
            rules,
            test_paths,
            baseline_hashes,
            baseline_root,
        );
        if edits.is_empty() {
            break;
        }
        let selected = select_non_overlapping(edits);
        if selected.is_empty() {
            break;
        }
        applied += selected.len();
        source = apply_edits(&source, &selected);
    }
    (source, applied)
}

/// Apply the autofix-safe rewrites over `paths`.
///
/// Nothing is written here: [`FileFix`] carries the before/after text so the
/// caller can print a diff (`--dry-run`) or persist the change. `baseline`
/// suppresses rewrites already recorded against `baseline_root`.
pub fn fix_paths(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    baseline: Option<&Baseline>,
    baseline_root: &Path,
) -> Result<FixReport, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    let compiled = compile_fix_rules(rules)?;
    if compiled.is_empty() {
        return Ok(FixReport::default());
    }
    let baseline_hashes = baseline_hash_set(baseline);

    let mut report = FixReport::default();
    for (path, lang) in walk_files(paths, &ignores) {
        let Ok(original) = fs::read_to_string(&path) else {
            continue;
        };
        let (fixed, applied) = fix_source(
            &original,
            &path,
            lang,
            &compiled,
            &test_paths,
            &baseline_hashes,
            baseline_root,
        );
        if applied > 0 && fixed != original {
            report.applied += applied;
            report.files.push(FileFix {
                path,
                original,
                fixed,
            });
        }
    }
    Ok(report)
}

/// Apply a single rule's autofix rewrite to an in-memory snippet, to a fix
/// point. Used by `slopguard test` to validate `tests.should_fix`: no baseline,
/// no test-path filtering, no inline-disable directives are consulted. Returns
/// the snippet unchanged when the rule is not autofixable.
pub fn fix_snippet(rule: &Rule, source: &str) -> Result<String, ScanError> {
    let compiled = compile_fix_rules(std::slice::from_ref(rule))?;
    if compiled.is_empty() {
        return Ok(source.to_string());
    }
    let lang = compiled[0].lang;
    let test_paths = TestPaths::new(&[])?;
    let baseline_hashes = HashSet::new();
    let path = Path::new("snippet");
    let (fixed, _applied) = fix_source(
        source,
        path,
        lang,
        &compiled,
        &test_paths,
        &baseline_hashes,
        path,
    );
    Ok(fixed)
}

#[cfg(test)]
mod tests;
