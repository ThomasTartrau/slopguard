//! `scan --fix`: apply the rewrites of autofixable rules in place.
//!
//! The detection pass never touches `rewrite` or `fixer`. This module compiles
//! each autofixable rule with its `rewrite` as the ast-grep `fix` (or with its
//! detection matcher alone when a builtin `fixer` computes the edits), matches
//! the source directly (so it can re-match a mutated buffer and reach a fix
//! point), and applies the resulting edits. The edits of one match form a group
//! applied together or not at all. Rules marked `autofix_unsafe` only run when
//! the caller asks for unsafe fixes.
//!
//! A rewrite stays within the scope of detection: only builtin rules, or
//! external rules the user listed in `fix.allow_external`, are applied; a rule's
//! `files` / `ignores` globs are honored; a dedicated `autofix_rule` only
//! rewrites inside a match of the detection `rule` (with its `constraints`).
//! Findings that detection would suppress -- inside test code, disabled inline,
//! or recorded in the baseline -- are never rewritten. Inline disables and
//! baseline membership are resolved once on the original content and tracked
//! through every edit, so a rewrite that shifts lines cannot unprotect them.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::slice::from_ref;

use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;

use crate::baseline::{finding_hash, Baseline};
use crate::config::Config;
use crate::disable::is_disabled;
use crate::finding::Finding;
use crate::resolution::strum_derive_crate;
use crate::rule::{Category, Rule, RuleId, Severity};
use crate::scanner::{build_glob_set, walk_files, ScanError};
use crate::test_filter::{CfgTestRanges, TestPaths};

mod compile;
mod edits;
mod fixers;

use compile::{compile_fix_rules, needs_strum, CompiledFixRule, FixAction};
use edits::{apply_edits, select_non_overlapping, shift_protected, Protected, RawEdit};
use fixers::FixEnv;
pub use fixers::FixerKind;

/// Upper bound on the re-scan/re-apply cycles per file. Fixing overlapping or
/// nested matches can expose new ones; the loop stops at a fix point or here.
const MAX_ITERATIONS: usize = 10;

/// A match in scope for rewriting in one pass, with what both the protection
/// pre-pass and the edit pass need from it. `edits` is the group its rewrite
/// produces, `None` when a builtin fixer declined the match: it is still
/// protected by an inline disable or the baseline, in case a later pass could
/// fix it.
struct Candidate {
    range: Range<usize>,
    line: usize,
    text: String,
    edits: Option<Vec<RawEdit>>,
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

/// The baseline hashes to skip, empty when no baseline is active.
fn baseline_hash_set(baseline: Option<&Baseline>) -> HashSet<String> {
    baseline
        .map(|b| b.findings.iter().map(|e| e.hash.clone()).collect())
        .unwrap_or_default()
}

/// Everything fixing one file needs besides its content.
struct FileContext<'a> {
    path: &'a Path,
    lang: SupportLang,
    rules: &'a [CompiledFixRule],
    test_paths: &'a TestPaths,
    env: FixEnv<'a>,
}

/// The matches of every rule over `source` that pass the scope filters shared
/// with detection: the rule's `files` / `ignores` globs, `skip_test_code`
/// (path heuristic and inline `#[cfg(test)]`), and, for a dedicated
/// `autofix_rule`, containment in a detection match.
fn candidates<'r>(source: &str, file: &FileContext<'r>) -> Vec<(&'r CompiledFixRule, Candidate)> {
    let FileContext {
        path,
        lang,
        rules,
        test_paths,
        env,
    } = file;
    let (path, lang) = (*path, *lang);
    let ast = lang.ast_grep(source);
    let cfg_test = (lang == SupportLang::Rust).then(|| CfgTestRanges::from_root(&ast));
    let is_test_file = test_paths.is_test(path);

    let mut found = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| r.lang == lang && r.applies_to(path))
    {
        let template = rule.config.fixer.first();
        if matches!(rule.action, FixAction::Template) && template.is_none() {
            continue;
        }
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

            let edits = match (rule.action, template) {
                (FixAction::Builtin(kind), _) => fixers::fix(kind, &node_match, env),
                (FixAction::Template, Some(fixer)) => {
                    let edit = node_match.make_edit(&rule.config.matcher, fixer);
                    Some(vec![RawEdit {
                        position: edit.position,
                        deleted_length: edit.deleted_length,
                        inserted: edit.inserted_text,
                    }])
                }
                (FixAction::Template, None) => None,
            };
            found.push((
                rule,
                Candidate {
                    range,
                    line: start_line,
                    text: node_match.text().to_string(),
                    edits,
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
    file: &FileContext<'_>,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> Vec<Protected> {
    let path = file.path;
    candidates(original, file)
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

/// Collect the edit groups due for `source` in one pass: the rewrites of the
/// in-scope matches that do not overlap a protected range of the same rule.
fn collect_edits(
    source: &str,
    file: &FileContext<'_>,
    protected: &[Protected],
) -> Vec<Vec<RawEdit>> {
    candidates(source, file)
        .into_iter()
        .filter(|(rule, candidate)| {
            !protected.iter().any(|p| {
                p.rule_id == rule.rule_id
                    && candidate.range.start < p.end
                    && p.start < candidate.range.end
            })
        })
        .filter_map(|(_, candidate)| candidate.edits)
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
/// number of fixes (edit groups) actually applied.
fn fix_source(
    original: &str,
    file: &FileContext<'_>,
    baseline_hashes: &HashSet<String>,
    baseline_root: &Path,
) -> (String, usize) {
    let mut protected = protected_ranges(original, file, baseline_hashes, baseline_root);
    let mut source = original.to_string();
    let mut applied = 0;
    for _ in 0..MAX_ITERATIONS {
        let groups = collect_edits(&source, file, &protected);
        let (selected, fixes) = select_non_overlapping(groups, source.len());
        if selected.is_empty() {
            break;
        }
        let (fixed, count) = apply_edits(&source, &selected);
        if count == 0 {
            break;
        }
        shift_protected(&mut protected, &selected);
        applied += fixes;
        source = fixed;
    }
    (source, applied)
}

/// Apply the autofix rewrites over `paths`: the `autofix_safe` ones, plus the
/// `autofix_unsafe` ones when `unsafe_fixes` is on.
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
    unsafe_fixes: bool,
) -> Result<FixReport, ScanError> {
    let test_paths = TestPaths::new(&config.scan.test_paths)?;
    let ignores = build_glob_set(&config.scan.ignores)?;
    let compiled = compile_fix_rules(rules, &config.fix.allow_external, unsafe_fixes)?;
    if compiled.is_empty() {
        return Ok(FixReport::default());
    }
    let baseline_hashes = baseline_hash_set(baseline);
    let reads_manifest = needs_strum(&compiled);
    let mut strum_by_dir: HashMap<PathBuf, Option<&'static str>> = HashMap::new();

    let mut report = FixReport::default();
    for (path, lang) in walk_files(paths, &ignores) {
        let Ok(original) = fs::read_to_string(&path) else {
            continue;
        };
        let dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let strum_crate = if reads_manifest {
            *strum_by_dir
                .entry(dir)
                .or_insert_with_key(|dir| strum_derive_crate(dir))
        } else {
            None
        };
        let file = FileContext {
            path: &path,
            lang,
            rules: &compiled,
            test_paths: &test_paths,
            env: FixEnv {
                path: Some(&path),
                strum_crate,
            },
        };
        let (fixed, applied) = fix_source(&original, &file, &baseline_hashes, baseline_root);
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
/// trust gate does not apply, and an `autofix_unsafe` rewrite is applied like
/// a safe one. No manifest is read either: the strum derive macros are assumed
/// reachable through `strum`, and a fixer that needs another file declines.
/// Returns the snippet unchanged when the rule is not autofixable.
pub fn fix_snippet(rule: &Rule, source: &str) -> Result<String, ScanError> {
    let mut compiled = compile_fix_rules(from_ref(rule), &[rule.id.as_str().to_string()], true)?;
    if compiled.is_empty() {
        return Ok(source.to_string());
    }
    for fix_rule in &mut compiled {
        fix_rule.files = None;
        fix_rule.ignores = None;
    }
    let test_paths = TestPaths::new(&[])?;
    let path = Path::new("snippet");
    let file = FileContext {
        path,
        lang: compiled[0].lang,
        rules: &compiled,
        test_paths: &test_paths,
        env: FixEnv {
            path: None,
            strum_crate: Some("strum"),
        },
    };
    let (fixed, _applied) = fix_source(source, &file, &HashSet::new(), path);
    Ok(fixed)
}

#[cfg(test)]
mod tests;
