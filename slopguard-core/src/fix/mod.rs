//! `scan --fix`: apply the `rewrite` template of autofix-safe rules in place.
//!
//! The detection pass never touches `rewrite`. This module compiles each
//! autofixable rule with its `rewrite` as the ast-grep `fix`, matches the source
//! directly (so it can re-match a mutated buffer and reach a fix point), and
//! applies the resulting edits.
//!
//! A rewrite stays within the scope of detection: only builtin rules, or
//! external rules the user listed in `fix.allow_external`, are applied; a rule's
//! `files` / `ignores` globs are honored; a dedicated `autofix_rule` only
//! rewrites inside a match of the detection `rule` (with its `constraints`).
//! Findings that detection would suppress -- inside test code, disabled inline,
//! or recorded in the baseline -- are never rewritten. Inline disables and
//! baseline membership are resolved once on the original content and tracked
//! through every edit, so a rewrite that shifts lines cannot unprotect them.

use std::collections::HashSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::slice::from_ref;

use ast_grep_config::RuleConfig;
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use globset::GlobSet;
use serde_yaml::Value;

use crate::baseline::{finding_hash, Baseline};
use crate::config::Config;
use crate::disable::is_disabled;
use crate::finding::Finding;
use crate::rule::{Category, Rule, RuleId, Severity};
use crate::scanner::{build_glob_set, compile_ast_grep_rule, walk_files, AstGrepRule, ScanError};
use crate::source::RuleOrigin;
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
    /// The detection `rule` (with its `constraints`) when a dedicated
    /// `autofix_rule` drives `config`: a fix match is kept only inside one of
    /// its matches. `None` when `config` already is the detection matcher.
    detect: Option<RuleConfig<SupportLang>>,
    files: Option<GlobSet>,
    ignores: Option<GlobSet>,
}

impl CompiledFixRule {
    /// Whether the rule's `files` / `ignores` globs select `path`, with the
    /// same semantics as the metric engine.
    fn applies_to(&self, path: &Path) -> bool {
        self.files.as_ref().is_none_or(|g| g.is_match(path))
            && !self.ignores.as_ref().is_some_and(|g| g.is_match(path))
    }
}

/// A single text replacement, decoupled from ast-grep's borrowed `Edit` so it
/// outlives the parsed tree.
struct RawEdit {
    position: usize,
    deleted_length: usize,
    inserted: Vec<u8>,
}

/// A match `--fix` must leave alone (inline disable or baseline), as a byte
/// range of the current buffer for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Protected {
    rule_id: RuleId,
    start: usize,
    end: usize,
}

/// A match eligible for rewriting in one pass, with what both the protection
/// pre-pass and the edit pass need from it.
struct Candidate {
    range: Range<usize>,
    line: usize,
    text: String,
    edit: RawEdit,
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

/// Whether `--fix` may apply `rule`: it is autofixable, and either builtin or
/// an external rule the user explicitly allowed in `fix.allow_external`.
fn is_trusted_for_fix(rule: &Rule, allow_external: &[String]) -> bool {
    rule.is_autofixable()
        && (rule.origin == RuleOrigin::Builtin
            || allow_external.iter().any(|id| id == rule.id.as_str()))
}

/// Compile one ast-grep matcher of `rule` for `lang`: the fix matcher (with the
/// `rewrite` as `fix`) or the detection matcher bounding it (`fix: None`).
fn compile_matcher(
    rule: &Rule,
    lang: SupportLang,
    matcher: &Value,
    constraints: Option<&Value>,
    fix: Option<&str>,
) -> Result<RuleConfig<SupportLang>, ScanError> {
    let ast_grep_rule = AstGrepRule {
        id: rule.id.as_str(),
        language: lang,
        severity: &rule.severity,
        message: &rule.message,
        note: rule.note.as_deref(),
        rule: matcher,
        constraints,
        fix,
        files: rule.files.as_deref(),
        ignores: rule.ignores.as_deref(),
    };
    compile_ast_grep_rule(&ast_grep_rule).map_err(|source| ScanError::RuleCompile {
        id: rule.id.clone(),
        source,
    })
}

/// Compile every autofixable rule (`autofix_safe` + `rewrite`) trusted for
/// `--fix` with its rewrite as the ast-grep fix template, once per ast-grep
/// language it targets.
fn compile_fix_rules(
    rules: &[Rule],
    allow_external: &[String],
) -> Result<Vec<CompiledFixRule>, ScanError> {
    let mut compiled = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| is_trusted_for_fix(r, allow_external))
    {
        // `is_autofixable` guarantees `rewrite` is present.
        let Some(rewrite) = rule.rewrite.as_deref() else {
            continue;
        };
        // A dedicated `autofix_rule` is self-contained: its metavariables need
        // not match those of the detection `rule`, so detection `constraints`
        // (which reference the detection rule's metavariables) do not apply to
        // it. They apply to the separate detection matcher instead, which
        // bounds where the dedicated matcher may rewrite.
        let uses_dedicated_matcher = !rule.autofix_rule.is_null();
        let detection_constraints = (!rule.constraints.is_null()).then_some(&rule.constraints);
        let constraints = detection_constraints.filter(|_| !uses_dedicated_matcher);
        let files = rule.files.as_deref().map(build_glob_set).transpose()?;
        let ignores = rule.ignores.as_deref().map(build_glob_set).transpose()?;
        for &lang in rule.language.ast_grep_langs() {
            let config =
                compile_matcher(rule, lang, rule.fix_matcher(), constraints, Some(rewrite))?;
            let detect = uses_dedicated_matcher
                .then(|| compile_matcher(rule, lang, &rule.rule, detection_constraints, None))
                .transpose()?;
            compiled.push(CompiledFixRule {
                rule_id: rule.id.clone(),
                lang,
                skip_test_code: rule.skip_test_code,
                config,
                detect,
                files: files.clone(),
                ignores: ignores.clone(),
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
/// earlier positions stay valid. Returns the new content and the number of
/// edits actually spliced: an out-of-bounds edit is skipped and not counted,
/// and an invalid UTF-8 result yields the original content with 0 applied.
fn apply_edits(source: &str, edits: &[RawEdit]) -> (String, usize) {
    let mut bytes = source.as_bytes().to_vec();
    let mut applied = 0;
    for edit in edits.iter().rev() {
        let end = edit.position + edit.deleted_length;
        if end > bytes.len() {
            continue;
        }
        bytes.splice(edit.position..end, edit.inserted.iter().copied());
        applied += 1;
    }
    match String::from_utf8(bytes) {
        Ok(fixed) => (fixed, applied),
        Err(_) => (source.to_string(), 0),
    }
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

/// Move the protected ranges through one pass of applied edits (sorted
/// ascending, non-overlapping, positions in the pre-pass buffer). A range after
/// an edit shifts by the length delta; a range an edit touches is widened to
/// cover the replacement, so it keeps protecting the text it held.
fn shift_protected(protected: &mut [Protected], edits: &[RawEdit]) {
    // Right to left: an edit never moves the positions before it, so each
    // edit's coordinates stay valid while the later ones are folded in.
    for edit in edits.iter().rev() {
        let edit_end = edit.position + edit.deleted_length;
        let inserted = edit.inserted.len();
        for range in protected.iter_mut() {
            if edit_end <= range.start {
                // `range.start >= edit_end >= deleted_length`: no underflow.
                range.start = range.start - edit.deleted_length + inserted;
                range.end = range.end - edit.deleted_length + inserted;
            } else if edit.position < range.end {
                // `max(end, edit_end) >= edit_end >= deleted_length`.
                range.end = range.end.max(edit_end) - edit.deleted_length + inserted;
                range.start = range.start.min(edit.position);
            }
        }
    }
}

/// The matches of every rule over `source` that pass the scope filters shared
/// with detection: the rule's `files` / `ignores` globs, `skip_test_code`
/// (path heuristic and inline `#[cfg(test)]`), and, for a dedicated
/// `autofix_rule`, containment in a detection match.
fn candidates<'r>(
    source: &str,
    path: &Path,
    lang: SupportLang,
    rules: &'r [CompiledFixRule],
    test_paths: &TestPaths,
) -> Vec<(&'r CompiledFixRule, Candidate)> {
    let ast = lang.ast_grep(source);
    let cfg_test = (lang == SupportLang::Rust).then(|| CfgTestRanges::from_root(&ast));
    let is_test_file = test_paths.is_test(path);

    let mut found = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| r.lang == lang && r.applies_to(path))
    {
        let Some(fixer) = rule.config.fixer.first() else {
            continue;
        };
        let detected: Option<Vec<Range<usize>>> = rule.detect.as_ref().map(|detect| {
            ast.root()
                .find_all(&detect.matcher)
                .map(|m| m.range())
                .collect()
        });
        for node_match in ast.root().find_all(&rule.config.matcher) {
            let range = node_match.range();
            let start_line = node_match.start_pos().line() + 1;

            let in_test_code = rule.skip_test_code
                && (is_test_file
                    || cfg_test
                        .as_ref()
                        .is_some_and(|ranges| ranges.contains_line(start_line)));
            if in_test_code {
                continue;
            }
            let outside_detection = detected.as_ref().is_some_and(|ranges| {
                !ranges
                    .iter()
                    .any(|d| d.start <= range.start && range.end <= d.end)
            });
            if outside_detection {
                continue;
            }

            let edit = node_match.make_edit(&rule.config.matcher, fixer);
            found.push((
                rule,
                Candidate {
                    range,
                    line: start_line,
                    text: node_match.text().to_string(),
                    edit: RawEdit {
                        position: edit.position,
                        deleted_length: edit.deleted_length,
                        inserted: edit.inserted_text,
                    },
                },
            ));
        }
    }
    found
}

/// Resolve, once on the original content, which matches detection suppresses
/// through an inline disable directive or the baseline. Each directive is
/// checked per (rule, match), so a blanket directive protects every rule.
fn protected_ranges(
    original: &str,
    path: &Path,
    lang: SupportLang,
    rules: &[CompiledFixRule],
    test_paths: &TestPaths,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> Vec<Protected> {
    candidates(original, path, lang, rules, test_paths)
        .into_iter()
        .filter(|(rule, candidate)| {
            if is_disabled(original, candidate.line, &rule.rule_id) {
                return true;
            }
            if baseline_hashes.is_empty() {
                return false;
            }
            let finding = position_finding(&rule.rule_id, path, candidate.line, &candidate.text);
            let hash = finding_hash(&finding, baseline_root, Some(original));
            baseline_hashes.contains(&hash)
        })
        .map(|(rule, candidate)| Protected {
            rule_id: rule.rule_id.clone(),
            start: candidate.range.start,
            end: candidate.range.end,
        })
        .collect()
}

/// Collect the edits due for `source` in one pass: the in-scope matches that
/// do not overlap a protected range of the same rule.
fn collect_edits(
    source: &str,
    path: &Path,
    lang: SupportLang,
    rules: &[CompiledFixRule],
    test_paths: &TestPaths,
    protected: &[Protected],
) -> Vec<RawEdit> {
    candidates(source, path, lang, rules, test_paths)
        .into_iter()
        .filter(|(rule, candidate)| {
            !protected.iter().any(|p| {
                p.rule_id == rule.rule_id
                    && candidate.range.start < p.end
                    && p.start < candidate.range.end
            })
        })
        .map(|(_, candidate)| candidate.edit)
        .collect()
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

/// Rewrite one file's content to a fix point. Returns the new content and the
/// number of edits actually applied.
fn fix_source(
    original: &str,
    path: &Path,
    lang: SupportLang,
    rules: &[CompiledFixRule],
    test_paths: &TestPaths,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> (String, usize) {
    let mut protected = protected_ranges(
        original,
        path,
        lang,
        rules,
        test_paths,
        baseline_hashes,
        baseline_root,
    );
    let mut source = original.to_string();
    let mut applied = 0;
    for _ in 0..MAX_ITERATIONS {
        let edits = collect_edits(&source, path, lang, rules, test_paths, &protected);
        let selected = select_non_overlapping(edits);
        if selected.is_empty() {
            break;
        }
        let (fixed, count) = apply_edits(&source, &selected);
        if count == 0 {
            break;
        }
        shift_protected(&mut protected, &selected);
        applied += count;
        source = fixed;
    }
    (source, applied)
}

/// Apply the autofix-safe rewrites over `paths`.
///
/// Only builtin rules and the external rules listed in `fix.allow_external`
/// are applied. Nothing is written here: [`FileFix`] carries the before/after
/// text so the caller can print a diff (`--dry-run`) or persist the change.
/// `baseline` suppresses rewrites already recorded against `baseline_root`.
pub fn fix_paths(
    paths: &[PathBuf],
    rules: &[Rule],
    config: &Config,
    baseline: Option<&Baseline>,
    baseline_root: &Path,
) -> Result<FixReport, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    let compiled = compile_fix_rules(rules, &config.fix.allow_external)?;
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
/// no test-path filtering, no `files` / `ignores` globs, no inline-disable
/// directives are consulted. Nothing is written to disk, so the external-rule
/// trust gate does not apply. Returns the snippet unchanged when the rule is
/// not autofixable.
pub fn fix_snippet(rule: &Rule, source: &str) -> Result<String, ScanError> {
    let mut compiled = compile_fix_rules(from_ref(rule), &[rule.id.as_str().to_string()])?;
    if compiled.is_empty() {
        return Ok(source.to_string());
    }
    for fix_rule in &mut compiled {
        fix_rule.files = None;
        fix_rule.ignores = None;
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
