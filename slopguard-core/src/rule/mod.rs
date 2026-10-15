use std::fmt;
use std::io::Error as IoError;
use std::path::{Component, Path, PathBuf};
use std::str::Utf8Error;

use ast_grep_language::SupportLang;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use strum::{Display, EnumIter, EnumString};
use thiserror::Error;

use crate::cross_file::CrossFileKind;
use crate::fix::FixerKind;
use crate::metric::Metric;
use crate::resolution::ResolutionKind;
use crate::source::RuleOrigin;

mod load;

pub use load::{
    is_rule_active, load_all_rules, load_builtin_rules, load_custom_rules, load_effective_rules,
    load_source_rules, read_fixture, validate_unique_ids,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl RuleId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Display, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Display, EnumIter, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Language {
    Rust,
    TypeScript,
}

impl Language {
    /// The ast-grep languages a rule written for this language is compiled
    /// against. TypeScript rules also cover TSX files.
    pub fn ast_grep_langs(&self) -> &'static [SupportLang] {
        match self {
            Language::Rust => &[SupportLang::Rust],
            Language::TypeScript => &[SupportLang::TypeScript, SupportLang::Tsx],
        }
    }
}

#[derive(Debug, Display, EnumString, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Category {
    Slop,
    Security,
    #[default]
    Correctness,
}

impl Category {
    /// Derive the category from the first directory of a rule path relative to
    /// its ruleset root (e.g. `security/no-debug.yml`). Returns `None` when the
    /// path has no directory or the directory is not a known category.
    fn from_rule_path(path: &Path) -> Option<Self> {
        match path.components().next()? {
            Component::Normal(dir) => dir.to_str()?.parse().ok(),
            _ => None,
        }
    }
}

/// Whether an autofix preserves behavior. `scan --fix` applies `Safe` fixes;
/// `Unsafe` ones also need `--unsafe-fixes`.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
#[strum(serialize_all = "lowercase")]
pub enum FixSafety {
    Safe,
    Unsafe,
}

/// One rewrite assertion for an autofixable rule: `slopguard test` applies the
/// rule's `rewrite` to `before` and requires the result to equal `after`. This
/// is what proves a `rewrite` is correct, alongside `should_match`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixCase {
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTests {
    #[serde(default)]
    pub should_match: Vec<String>,
    #[serde(default)]
    pub should_not_match: Vec<String>,
    /// Rewrite assertions checked by `slopguard test` for autofixable rules.
    /// Each case's `before` is rewritten with the rule's `rewrite` and must
    /// equal `after`. Ignored for rules that are not autofixable.
    #[serde(default)]
    pub should_fix: Vec<FixCase>,
    /// Whole-file fixtures for metric rules, resolved against the embedded
    /// ruleset root (builtin rules) or the custom rule directory the rule was
    /// loaded from. A metric cannot be measured on a snippet.
    #[serde(default)]
    pub should_match_files: Vec<String>,
    #[serde(default)]
    pub should_not_match_files: Vec<String>,
}

/// How the `reason` (the finding's `note`) is produced when an `ai_check` rule
/// fires. See [`AiCheck::reason`].
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ReasonMode {
    /// Use the rule's static `note` as the reason. No generative LLM call.
    #[default]
    Static,
    /// Escalate to the generative LLM to write a per-instance reason. Reserved
    /// for relational rules whose message depends on the specific match.
    Generated,
}

/// Optional AI confirmation step for a rule. When present, the rule's `rule`
/// AST pattern acts as a cheap pre-filter: matches become candidates that an
/// LLM (or the System One classifier) must confirm before they are reported.
/// The AST layer never executes this field; the AI pipeline in `slopguard-ai`
/// reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiCheck {
    /// Prompt template. Double use: the generative LLM prompt (variables
    /// `{{code}}`, `{{filename}}`, `{{rule_context}}`), and the `instructions`
    /// of the System One classifier's noul question.
    pub prompt: String,
    /// Model override for this rule. Falls back to `[ai].model` in config.
    #[serde(default)]
    pub model: Option<String>,
    /// How the finding's reason is produced: a `static` note (default) or a
    /// per-instance `generated` note written by the LLM.
    #[serde(default)]
    pub reason: ReasonMode,
    /// Per-rule classifier probability threshold, overriding
    /// `[ai.classifier].threshold`. Fires when `p >= threshold`.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Classifier calibration: what a "yes" (issue) looks like. Maps to the
    /// noul question's `criteria.true`.
    #[serde(default)]
    pub if_true: Option<String>,
    /// Classifier calibration: what a "no" (not an issue) looks like. Maps to
    /// the noul question's `criteria.false`.
    #[serde(default)]
    pub if_false: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub language: Language,
    pub severity: Severity,
    pub message: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub category: Option<Category>,
    #[serde(default)]
    pub fix: Option<String>,
    /// ast-grep rewrite (fix) template applied to this rule's match by
    /// `scan --fix`. Distinct from `fix`, which is a free-text human message:
    /// `rewrite` carries the replacement pattern (it may reference the rule's
    /// metavariables). The AST detection pass never reads this field.
    #[serde(default)]
    pub rewrite: Option<String>,
    /// Builtin fixer applied by `scan --fix` instead of a `rewrite` template,
    /// for rewrites that edit several nodes (an item and its attributes, two
    /// match arms) or read another file. Mutually exclusive with `rewrite`. The
    /// kind selects builtin Rust logic, so an unknown name is a parse error.
    #[serde(default)]
    pub fixer: Option<FixerKind>,
    /// Opt-in marker that this rule's `rewrite` (or `fixer`) is safe to apply
    /// automatically (idempotent, no semantic change). `scan --fix` ignores the
    /// rewrite of any rule without it or `autofix_unsafe`. Defaults to `false`.
    /// On a rule from `custom_dirs` or `[[rules.sources]]` it is not enough:
    /// the rule id must also be listed in the user config's
    /// `fix.allow_external`.
    #[serde(default)]
    pub autofix_safe: bool,
    /// Opt-in marker for a rewrite that deliberately changes behavior (it
    /// recovers a poisoned lock instead of panicking, it lets a derived
    /// `Display` honor width flags). Applied only by `scan --fix
    /// --unsafe-fixes`. Mutually exclusive with `autofix_safe`.
    #[serde(default)]
    pub autofix_unsafe: bool,
    /// Matcher used only by `scan --fix` to locate nodes to rewrite, when it must
    /// be narrower than the detection `rule` (detect broadly, fix narrowly). A
    /// rule can flag every variant of a pattern while auto-rewriting only the
    /// subset whose `rewrite` is provably safe. `null` (the default) means
    /// `--fix` reuses `rule`. The detection pass never reads this field.
    /// `--fix` only rewrites an `autofix_rule` match whose range lies inside a
    /// match of the detection `rule` (with its `constraints`), so it can narrow
    /// but never widen what detection reports.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub autofix_rule: Value,
    #[serde(default)]
    pub rule: Value,
    /// ast-grep metavariable constraints, a sibling of `rule`. Passed through
    /// verbatim so a rule can restrict a captured metavariable (e.g. bind the
    /// receiver of `$R.clone()` to an already-owned value). `null` when unset.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub constraints: Value,
    /// File-level metric evaluated instead of `rule`. Mutually exclusive with it.
    #[serde(default)]
    pub metric: Option<Metric>,
    /// The value `metric` must exceed for the rule to fire. Required with `metric`.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Minimum file length in lines before a metric rule is evaluated. Below it
    /// the file is skipped, so ratios are not distorted by tiny files (a small
    /// module full of required doc comments). `None` means no floor.
    #[serde(default)]
    pub min_lines: Option<usize>,
    /// Project-wide analysis evaluated instead of `rule` or `metric`, and
    /// mutually exclusive with both. The kind selects builtin Rust logic; the
    /// YAML only carries the rule's identity, severity and user-facing text.
    #[serde(default)]
    pub cross_file: Option<CrossFileKind>,
    /// Per-file import resolution evaluated instead of `rule`, `metric` or
    /// `cross_file`, and mutually exclusive with all three. The kind selects
    /// builtin resolution logic; the YAML only carries the rule's identity,
    /// severity and user-facing text. `$import` in `message` is replaced with
    /// the unresolved specifier.
    #[serde(default)]
    pub resolution: Option<ResolutionKind>,
    /// Directory a custom rule was loaded from, used to resolve test fixture
    /// paths. `None` for builtin rules, which resolve against `BuiltinRules`.
    #[serde(skip)]
    pub source_dir: Option<PathBuf>,
    /// Provenance of this rule (builtin, git source, or local path), stamped at
    /// load time and reported by `slopguard list`. Never present in YAML.
    #[serde(skip)]
    pub origin: RuleOrigin,
    #[serde(default)]
    pub files: Option<Vec<String>>,
    #[serde(default)]
    pub ignores: Option<Vec<String>>,
    /// Drop findings located inside `#[cfg(test)]` blocks of scanned Rust files.
    /// Complements `ignores`, which only filters whole files by path.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub skip_test_code: bool,
    #[serde(default)]
    pub tests: Option<RuleTests>,
    /// When set, matches of `rule` are candidates confirmed by an LLM before
    /// being reported. See [`AiCheck`]. The AST scanner ignores this field.
    #[serde(default)]
    pub ai_check: Option<AiCheck>,
}

impl Rule {
    /// The rule's category, resolving an unset category to the default
    /// (`Correctness`), the way the scanner treats it.
    pub fn effective_category(&self) -> Category {
        self.category.clone().unwrap_or_default()
    }

    /// Whether this rule measures a file-level metric instead of matching AST.
    pub fn is_metric(&self) -> bool {
        self.metric.is_some()
    }

    /// The metric and threshold of a file-level rule, `None` for AST rules.
    pub fn metric_spec(&self) -> Option<(Metric, f64)> {
        Some((self.metric?, self.threshold?))
    }

    /// Whether this rule is evaluated by the project-wide pass instead of per file.
    pub fn is_cross_file(&self) -> bool {
        self.cross_file.is_some()
    }

    /// Whether this rule is evaluated by the per-file import resolution pass.
    pub fn is_resolution(&self) -> bool {
        self.resolution.is_some()
    }

    /// How safe this rule's autofix is: `None` when `scan --fix` never rewrites
    /// its matches (no `rewrite` or `fixer`, or neither `autofix_safe` nor
    /// `autofix_unsafe`). An external (non-builtin) rule additionally needs its
    /// id in `fix.allow_external`, which `scan --fix` checks on top of this.
    pub fn fix_safety(&self) -> Option<FixSafety> {
        if self.rewrite.is_none() && self.fixer.is_none() {
            return None;
        }
        if self.autofix_safe {
            Some(FixSafety::Safe)
        } else if self.autofix_unsafe {
            Some(FixSafety::Unsafe)
        } else {
            None
        }
    }

    /// Whether `scan --fix` may rewrite this rule's matches at some safety level.
    pub fn is_autofixable(&self) -> bool {
        self.fix_safety().is_some()
    }

    /// The matcher `scan --fix` uses to find nodes to rewrite: the dedicated
    /// `autofix_rule` when set, otherwise the detection `rule`.
    pub fn fix_matcher(&self) -> &Value {
        if self.autofix_rule.is_null() {
            &self.rule
        } else {
            &self.autofix_rule
        }
    }

    /// The cross-file analysis this rule requests, `None` for AST and metric rules.
    // Read-only accessor for a private field.
    // slopguard-disable-next-line no-trivial-function
    pub fn cross_file_kind(&self) -> Option<CrossFileKind> {
        self.cross_file
    }

    /// The resolution analysis this rule requests, `None` for all other rules.
    // Read-only accessor for a private field.
    // slopguard-disable-next-line no-trivial-function
    pub fn resolution_kind(&self) -> Option<ResolutionKind> {
        self.resolution
    }
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("failed to parse rule YAML: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("rule '{id}': rule field must not be empty")]
    EmptyRule { id: RuleId },

    #[error("rule '{id}': 'metric' and 'rule' are mutually exclusive")]
    MetricAndRule { id: RuleId },

    #[error("rule '{id}': 'cross_file' and 'rule' are mutually exclusive")]
    CrossFileAndRule { id: RuleId },

    #[error("rule '{id}': 'cross_file' and 'metric' are mutually exclusive")]
    CrossFileAndMetric { id: RuleId },

    #[error("rule '{id}': 'resolution' and 'rule' are mutually exclusive")]
    ResolutionAndRule { id: RuleId },

    #[error("rule '{id}': 'resolution' and 'metric' are mutually exclusive")]
    ResolutionAndMetric { id: RuleId },

    #[error("rule '{id}': 'resolution' and 'cross_file' are mutually exclusive")]
    ResolutionAndCrossFile { id: RuleId },

    #[error("rule '{id}': a metric rule requires a 'threshold'")]
    MissingThreshold { id: RuleId },

    #[error("rule '{id}': 'rewrite' and 'fixer' are mutually exclusive")]
    RewriteAndFixer { id: RuleId },

    #[error("rule '{id}': a 'fixer' needs an ast-grep 'rule' to locate its matches")]
    FixerWithoutRule { id: RuleId },

    #[error("rule '{id}': 'autofix_safe' and 'autofix_unsafe' are mutually exclusive")]
    SafeAndUnsafeFix { id: RuleId },

    #[error("rule '{id}': test fixture files are only supported for metric rules")]
    FixturesOnAstRule { id: RuleId },

    #[error("rule '{id}': fixture path '{path}' must be relative and must not contain '..'")]
    InvalidFixturePath { id: RuleId, path: String },

    #[error("rule '{id}': fixture '{path}' not found")]
    FixtureNotFound { id: RuleId, path: String },

    #[error("duplicate rule id: '{id}'")]
    DuplicateId { id: RuleId },

    #[error("rule '{id}' from source '{origin}' reuses a builtin rule id; rename it (external sources may not shadow builtin rules)")]
    SourceReusesBuiltinId { id: RuleId, origin: String },

    #[error("failed to read rule file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: IoError,
    },

    #[error("rule file '{path}' is not valid UTF-8: {source}")]
    Utf8 {
        path: String,
        #[source]
        source: Utf8Error,
    },
}

impl RuleError {
    fn io(path: &Path, source: IoError) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Parse a single YAML string into a Rule, validating required fields.
///
/// A rule carries exactly one matcher: an ast-grep `rule`, a file-level
/// `metric` plus its `threshold`, or a project-wide `cross_file` kind.
pub fn parse_rule(yaml: &str) -> Result<Rule, RuleError> {
    let rule: Rule = serde_yaml::from_str(yaml)?;
    let has_rule = !rule.rule.is_null();
    let has_metric = rule.metric.is_some();
    let has_cross = rule.cross_file.is_some();
    let has_resolution = rule.resolution.is_some();
    if has_resolution {
        if has_rule {
            return Err(RuleError::ResolutionAndRule { id: rule.id });
        }
        if has_metric {
            return Err(RuleError::ResolutionAndMetric { id: rule.id });
        }
        if has_cross {
            return Err(RuleError::ResolutionAndCrossFile { id: rule.id });
        }
    }
    match (has_cross, has_metric, has_rule) {
        (true, _, true) => return Err(RuleError::CrossFileAndRule { id: rule.id }),
        (true, true, _) => return Err(RuleError::CrossFileAndMetric { id: rule.id }),
        (false, true, true) => return Err(RuleError::MetricAndRule { id: rule.id }),
        (false, true, false) if rule.threshold.is_none() => {
            return Err(RuleError::MissingThreshold { id: rule.id })
        }
        (false, false, false) if !has_resolution => {
            return Err(RuleError::EmptyRule { id: rule.id })
        }
        _ => {}
    }
    if rule.fixer.is_some() {
        if rule.rewrite.is_some() {
            return Err(RuleError::RewriteAndFixer { id: rule.id });
        }
        if !has_rule {
            return Err(RuleError::FixerWithoutRule { id: rule.id });
        }
    }
    if rule.autofix_safe && rule.autofix_unsafe {
        return Err(RuleError::SafeAndUnsafeFix { id: rule.id });
    }
    if !rule.is_metric() {
        if let Some(tests) = &rule.tests {
            if !tests.should_match_files.is_empty() || !tests.should_not_match_files.is_empty() {
                return Err(RuleError::FixturesOnAstRule { id: rule.id });
            }
        }
    }
    Ok(rule)
}

#[cfg(test)]
mod load_tests;
#[cfg(test)]
mod parse_tests;
