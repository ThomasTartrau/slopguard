use std::collections::HashSet;
use std::fmt;
use std::fs::read_to_string;
use std::io::Error as IoError;
use std::path::{Component, Path, PathBuf};
use std::str::{from_utf8, Utf8Error};

use ast_grep_language::SupportLang;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use slopguard_rules::BuiltinRules;
use strum::{Display, EnumIter, EnumString};
use thiserror::Error;

use crate::cross_file::CrossFileKind;
use crate::metric::Metric;
use crate::resolution::ResolutionKind;
use crate::source::{ResolvedSource, RuleOrigin};

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
    /// Opt-in marker that this rule's `rewrite` is safe to apply automatically
    /// (idempotent, no semantic change). `scan --fix` ignores the `rewrite` of
    /// any rule without it. Defaults to `false`. On a rule from `custom_dirs`
    /// or `[[rules.sources]]` it is not enough: the rule id must also be listed
    /// in the user config's `fix.allow_external`.
    #[serde(default)]
    pub autofix_safe: bool,
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

    /// Whether `scan --fix` may rewrite this rule's matches: it carries a
    /// `rewrite` template and is explicitly marked `autofix_safe`. An external
    /// (non-builtin) rule additionally needs its id in `fix.allow_external`,
    /// which `scan --fix` checks on top of this.
    pub fn is_autofixable(&self) -> bool {
        self.autofix_safe && self.rewrite.is_some()
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
    if !rule.is_metric() {
        if let Some(tests) = &rule.tests {
            if !tests.should_match_files.is_empty() || !tests.should_not_match_files.is_empty() {
                return Err(RuleError::FixturesOnAstRule { id: rule.id });
            }
        }
    }
    Ok(rule)
}

/// Read a whole-file test fixture referenced by `tests.should_match_files` or
/// `tests.should_not_match_files`. Builtin rules resolve against the embedded
/// ruleset; custom rules resolve against the directory they were loaded from.
pub fn read_fixture(rule: &Rule, relative: &str) -> Result<String, RuleError> {
    let path = Path::new(relative);
    let traverses = path.components().any(|c| matches!(c, Component::ParentDir));
    if path.is_absolute() || traverses {
        return Err(RuleError::InvalidFixturePath {
            id: rule.id.clone(),
            path: relative.to_string(),
        });
    }

    match &rule.source_dir {
        Some(dir) => {
            let full = dir.join(path);
            read_to_string(&full).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    RuleError::FixtureNotFound {
                        id: rule.id.clone(),
                        path: relative.to_string(),
                    }
                } else {
                    RuleError::io(&full, e)
                }
            })
        }
        None => {
            let file = BuiltinRules::get(relative).ok_or_else(|| RuleError::FixtureNotFound {
                id: rule.id.clone(),
                path: relative.to_string(),
            })?;
            from_utf8(&file.data)
                .map(str::to_string)
                .map_err(|e| RuleError::Utf8 {
                    path: relative.to_string(),
                    source: e,
                })
        }
    }
}

/// Parse a rule and fill in its category from the ruleset-relative path when
/// the YAML omits it.
fn parse_rule_at(yaml: &str, relative_path: &Path) -> Result<Rule, RuleError> {
    let mut rule = parse_rule(yaml)?;
    if rule.category.is_none() {
        rule.category = Category::from_rule_path(relative_path);
    }
    Ok(rule)
}

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
    )
}

/// Load all builtin rules embedded via rust-embed.
pub fn load_builtin_rules() -> Result<Vec<Rule>, RuleError> {
    BuiltinRules::iter()
        .filter(|path| is_rule_file(Path::new(path.as_ref())))
        .filter_map(|path| BuiltinRules::get(&path).map(|file| (path, file)))
        .map(|(path, file)| {
            let yaml = from_utf8(&file.data).map_err(|e| RuleError::Utf8 {
                path: path.to_string(),
                source: e,
            })?;
            parse_rule_at(yaml, Path::new(path.as_ref()))
        })
        .collect()
}

/// Load every rule YAML found under `dir`, stamping each with `dir` as its
/// fixture root and `origin` as its provenance. Subdirectories are searched
/// recursively.
fn load_rules_in_dir(dir: &Path, origin: &RuleOrigin) -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    // Rule directories are plain file trees: gitignore and hidden-file
    // filtering would silently drop rules.
    for entry in WalkBuilder::new(dir).standard_filters(false).build() {
        let entry = entry.map_err(|e| RuleError::io(dir, IoError::other(e)))?;
        let path = entry.path();
        let is_file = entry.file_type().is_some_and(|t| t.is_file());
        if !is_file || !is_rule_file(path) {
            continue;
        }
        let yaml = read_to_string(path).map_err(|e| RuleError::io(path, e))?;
        let relative = path.strip_prefix(dir).unwrap_or(path);
        let mut rule = parse_rule_at(&yaml, relative)?;
        rule.source_dir = Some(dir.to_path_buf());
        rule.origin = origin.clone();
        rules.push(rule);
    }
    Ok(rules)
}

/// Load rules from custom directories on the filesystem. Missing directories
/// are skipped; subdirectories are searched recursively.
pub fn load_custom_rules(dirs: &[PathBuf]) -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
        let origin = RuleOrigin::Local { path: dir.clone() };
        rules.extend(load_rules_in_dir(dir, &origin)?);
    }
    Ok(rules)
}

/// Load rules from resolved external sources (git clones and local paths),
/// stamping each rule with the source's provenance. A source directory that is
/// missing (e.g. a git `path` sub-directory that does not exist) is skipped.
pub fn load_source_rules(sources: &[ResolvedSource]) -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    for source in sources.iter().filter(|s| s.dir.is_dir()) {
        rules.extend(load_rules_in_dir(&source.dir, &source.origin)?);
    }
    Ok(rules)
}

/// Reject any external rule whose (id, language) collides with a builtin rule.
/// External sources extend the ruleset; they must never shadow a builtin id.
fn reject_builtin_id_reuse(external: &[Rule], builtin: &[Rule]) -> Result<(), RuleError> {
    let builtin_ids: HashSet<(&RuleId, &Language)> =
        builtin.iter().map(|r| (&r.id, &r.language)).collect();
    for rule in external {
        if builtin_ids.contains(&(&rule.id, &rule.language)) {
            return Err(RuleError::SourceReusesBuiltinId {
                id: rule.id.clone(),
                origin: rule.origin.label(),
            });
        }
    }
    Ok(())
}

/// Whether a rule (builtin or external) takes part in a scan under `config`.
///
/// A rule listed in `rules.enable` is always active. Otherwise it must be
/// enabled by default, belong to an active ruleset, and not be listed in
/// `rules.disable`.
pub fn is_rule_active(rule: &Rule, config: &crate::config::Config) -> bool {
    let listed = |ids: &[String]| ids.iter().any(|id| id == rule.id.as_str());
    if listed(&config.rules.enable) {
        return true;
    }
    let ruleset_on = match rule.effective_category() {
        Category::Slop => config.rulesets.slop,
        Category::Security => config.rulesets.security,
        Category::Correctness => config.rulesets.correctness,
    };
    ruleset_on && rule.enabled && !listed(&config.rules.disable)
}

/// Load the non-builtin rules (custom directories + external sources) and
/// reject any of them that reuses a builtin id: neither a custom directory nor
/// a source may shadow a builtin rule. Custom rules come first, then source
/// rules, matching the order both public loaders expose.
fn load_external_rules(
    config: &crate::config::Config,
    sources: &[ResolvedSource],
    builtin: &[Rule],
) -> Result<Vec<Rule>, RuleError> {
    let mut external = load_custom_rules(&config.rules.custom_dirs)?;
    external.extend(load_source_rules(sources)?);
    reject_builtin_id_reuse(&external, builtin)?;
    Ok(external)
}

/// Load all effective rules based on config: builtin, custom rules from
/// configured directories, and rules from resolved external sources, all
/// filtered by [`is_rule_active`] (rulesets, `enabled: false`, and the
/// enable/disable lists). An external rule reusing a builtin id is rejected
/// before any filtering.
pub fn load_effective_rules(
    config: &crate::config::Config,
    sources: &[ResolvedSource],
) -> Result<Vec<Rule>, RuleError> {
    let builtin = load_builtin_rules()?;
    let external = load_external_rules(config, sources, &builtin)?;

    let rules: Vec<Rule> = builtin
        .into_iter()
        .chain(external)
        .filter(|rule| is_rule_active(rule, config))
        .collect();
    validate_unique_ids(&rules)?;
    Ok(rules)
}

/// Load all rules (builtin + custom + external sources) without filtering by
/// activation status. Used by `explain` to look up any rule regardless of
/// config, so an opt-in or disabled rule can still be explained.
pub fn load_all_rules(
    config: &crate::config::Config,
    sources: &[ResolvedSource],
) -> Result<Vec<Rule>, RuleError> {
    let builtin = load_builtin_rules()?;
    let external = load_external_rules(config, sources, &builtin)?;

    let mut rules = builtin;
    rules.extend(external);
    Ok(rules)
}

/// Validate that all rule (id, language) pairs are unique. The same rule id
/// may appear for different languages (e.g. `no-todo-fixme` for both Rust and
/// TypeScript), so a single `rules.disable` entry covers both variants.
pub fn validate_unique_ids(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert((&rule.id, &rule.language)) {
            return Err(RuleError::DuplicateId {
                id: rule.id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod load_tests;
#[cfg(test)]
mod parse_tests;
