//! Which rules `--fix` may apply, compiled for matching: the ast-grep matcher
//! with the `rewrite` template as its fix, or the bare matcher a builtin fixer
//! reads.

use std::path::Path;

use ast_grep_config::RuleConfig;
use ast_grep_language::SupportLang;
use globset::GlobSet;
use serde_yaml::Value;

use crate::rule::{FixSafety, Rule, RuleId};
use crate::scanner::{build_glob_set, compile_ast_grep_rule, AstGrepRule, ScanError};
use crate::source::RuleOrigin;

use super::FixerKind;

/// How a compiled rule turns a match into edits.
#[derive(Clone, Copy)]
pub(super) enum FixAction {
    /// The ast-grep fix compiled from the rule's `rewrite` template.
    Template,
    /// A builtin fixer, which may decline a match.
    Builtin(FixerKind),
}

/// One autofixable rule compiled for a specific ast-grep language, keeping a way
/// back to the slopguard rule identity for filtering.
pub(super) struct CompiledFixRule {
    pub(super) rule_id: RuleId,
    pub(super) lang: SupportLang,
    pub(super) skip_test_code: bool,
    pub(super) action: FixAction,
    pub(super) config: RuleConfig<SupportLang>,
    /// The detection `rule` (with its `constraints`) when a dedicated
    /// `autofix_rule` drives `config`: a fix match is kept only inside one of
    /// its matches. `None` when `config` already is the detection matcher.
    pub(super) detect: Option<RuleConfig<SupportLang>>,
    pub(super) files: Option<GlobSet>,
    pub(super) ignores: Option<GlobSet>,
}

impl CompiledFixRule {
    /// Whether the rule's `files` / `ignores` globs select `path`, with the
    /// same semantics as the metric engine.
    pub(super) fn applies_to(&self, path: &Path) -> bool {
        self.files.as_ref().is_none_or(|g| g.is_match(path))
            && !self.ignores.as_ref().is_some_and(|g| g.is_match(path))
    }
}

/// Whether `--fix` may apply `rule`: its fix is safe, or unsafe while
/// `unsafe_fixes` is on, and it is either builtin or an external rule the user
/// explicitly allowed in `fix.allow_external`.
fn is_trusted_for_fix(rule: &Rule, allow_external: &[String], unsafe_fixes: bool) -> bool {
    let level_allowed = match rule.fix_safety() {
        Some(FixSafety::Safe) => true,
        Some(FixSafety::Unsafe) => unsafe_fixes,
        None => false,
    };
    level_allowed
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

/// Compile every autofixable rule trusted for `--fix`, once per ast-grep
/// language it targets: with its `rewrite` as the ast-grep fix template, or
/// with the bare matcher its builtin `fixer` reads.
pub(super) fn compile_fix_rules(
    rules: &[Rule],
    allow_external: &[String],
    unsafe_fixes: bool,
) -> Result<Vec<CompiledFixRule>, ScanError> {
    let mut compiled = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| is_trusted_for_fix(r, allow_external, unsafe_fixes))
    {
        // `fix_safety` guarantees a `rewrite` or a `fixer` is present.
        let (action, rewrite) = match (rule.fixer, rule.rewrite.as_deref()) {
            (Some(kind), _) => (FixAction::Builtin(kind), None),
            (None, Some(rewrite)) => (FixAction::Template, Some(rewrite)),
            (None, None) => continue,
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
            let config = compile_matcher(rule, lang, rule.fix_matcher(), constraints, rewrite)?;
            let detect = uses_dedicated_matcher
                .then(|| compile_matcher(rule, lang, &rule.rule, detection_constraints, None))
                .transpose()?;
            compiled.push(CompiledFixRule {
                rule_id: rule.id.clone(),
                lang,
                skip_test_code: rule.skip_test_code,
                action,
                config,
                detect,
                files: files.clone(),
                ignores: ignores.clone(),
            });
        }
    }
    Ok(compiled)
}

/// Whether any compiled rule runs the strum fixer, the only one that reads the
/// crate manifest.
pub(super) fn needs_strum(rules: &[CompiledFixRule]) -> bool {
    rules
        .iter()
        .any(|r| matches!(r.action, FixAction::Builtin(FixerKind::StrumEnumStr)))
}
