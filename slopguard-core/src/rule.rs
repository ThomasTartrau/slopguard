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

use crate::metric::Metric;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTests {
    #[serde(default)]
    pub should_match: Vec<String>,
    #[serde(default)]
    pub should_not_match: Vec<String>,
    /// Whole-file fixtures for metric rules, resolved against the embedded
    /// ruleset root (builtin rules) or the custom rule directory the rule was
    /// loaded from. A metric cannot be measured on a snippet.
    #[serde(default)]
    pub should_match_files: Vec<String>,
    #[serde(default)]
    pub should_not_match_files: Vec<String>,
}

/// Optional AI confirmation step for a rule. When present, the rule's `rule`
/// AST pattern acts as a cheap pre-filter: matches become candidates that an
/// LLM must confirm before they are reported. The AST layer never executes
/// this field; the AI pipeline in `slopguard-ai` reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiCheck {
    /// Prompt template sent to the model. Supports the variables `{{code}}`,
    /// `{{filename}}`, and `{{rule_context}}`.
    pub prompt: String,
    /// Model override for this rule. Falls back to `[ai].model` in config.
    #[serde(default)]
    pub model: Option<String>,
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
    #[serde(default)]
    pub rule: Value,
    /// File-level metric evaluated instead of `rule`. Mutually exclusive with it.
    #[serde(default)]
    pub metric: Option<Metric>,
    /// The value `metric` must exceed for the rule to fire. Required with `metric`.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Directory a custom rule was loaded from, used to resolve test fixture
    /// paths. `None` for builtin rules, which resolve against `BuiltinRules`.
    #[serde(skip)]
    pub source_dir: Option<PathBuf>,
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
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("failed to parse rule YAML: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("rule '{id}': rule field must not be empty")]
    EmptyRule { id: RuleId },

    #[error("rule '{id}': 'metric' and 'rule' are mutually exclusive")]
    MetricAndRule { id: RuleId },

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
/// A rule carries either an ast-grep `rule` matcher or a file-level `metric`
/// plus its `threshold`, never both and never neither.
pub fn parse_rule(yaml: &str) -> Result<Rule, RuleError> {
    let rule: Rule = serde_yaml::from_str(yaml)?;
    match (rule.metric.is_some(), rule.rule.is_null()) {
        (true, false) => return Err(RuleError::MetricAndRule { id: rule.id }),
        (true, true) if rule.threshold.is_none() => {
            return Err(RuleError::MissingThreshold { id: rule.id })
        }
        (false, true) => return Err(RuleError::EmptyRule { id: rule.id }),
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

/// Load rules from custom directories on the filesystem. Missing directories
/// are skipped; subdirectories are searched recursively.
pub fn load_custom_rules(dirs: &[PathBuf]) -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
        // Custom rule directories are plain file trees: gitignore and
        // hidden-file filtering would silently drop rules.
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
            rule.source_dir = Some(dir.clone());
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// Whether a builtin rule takes part in a scan under `config`.
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

/// Load all effective rules based on config: builtin (filtered by rulesets and
/// the enable/disable lists) plus custom rules from configured directories.
pub fn load_effective_rules(config: &crate::config::Config) -> Result<Vec<Rule>, RuleError> {
    let mut rules: Vec<Rule> = load_builtin_rules()?
        .into_iter()
        .filter(|rule| is_rule_active(rule, config))
        .collect();

    let custom = load_custom_rules(&config.rules.custom_dirs)?;
    rules.extend(custom);
    validate_unique_ids(&rules)?;
    Ok(rules)
}

/// Load all rules (builtin + custom) without filtering by activation status.
/// Used by `explain` to look up any rule regardless of config.
pub fn load_all_rules(config: &crate::config::Config) -> Result<Vec<Rule>, RuleError> {
    let mut rules = load_builtin_rules()?;
    let custom = load_custom_rules(&config.rules.custom_dirs)?;
    rules.extend(custom);
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
mod tests {
    use std::fs::{create_dir, write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parse_valid_rule_all_fields() {
        let yaml = r#"
id: test-rule
language: rust
severity: error
message: "Test message"
note: "Test note"
category: security
fix: "Use X instead"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
files:
  - "**/src/**/*.rs"
ignores:
  - "**/tests/**"
skip_test_code: true
tests:
  should_match:
    - "let x = foo().unwrap();"
  should_not_match:
    - "let x = foo()?;"
"#;
        let rule = parse_rule(yaml).unwrap();
        assert!(rule.skip_test_code);
        assert_eq!(rule.id, RuleId::from("test-rule"));
        assert_eq!(rule.language, Language::Rust);
        assert_eq!(rule.severity, Severity::Error);
        assert_eq!(rule.message, "Test message");
        assert_eq!(rule.note.as_deref(), Some("Test note"));
        assert_eq!(rule.category, Some(Category::Security));
        assert_eq!(rule.fix.as_deref(), Some("Use X instead"));
        assert!(!rule.rule.is_null());
        assert_eq!(rule.files.as_ref().unwrap().len(), 1);
        assert_eq!(rule.ignores.as_ref().unwrap().len(), 1);
        let tests = rule.tests.as_ref().unwrap();
        assert_eq!(tests.should_match.len(), 1);
        assert_eq!(tests.should_not_match.len(), 1);
    }

    #[test]
    fn parse_rule_with_ai_check() {
        let yaml = r#"
id: ai-rule
language: rust
severity: warning
category: slop
message: "needs AI confirmation"
rule:
  kind: line_comment
  regex: 'SAFETY'
ai_check:
  prompt: "Is this SAFETY comment meaningful?\n{{code}}"
  model: "claude-haiku-4-5"
"#;
        let rule = parse_rule(yaml).unwrap();
        let ai = rule.ai_check.as_ref().expect("ai_check should be present");
        assert_eq!(ai.prompt, "Is this SAFETY comment meaningful?\n{{code}}");
        assert_eq!(ai.model.as_deref(), Some("claude-haiku-4-5"));
    }

    #[test]
    fn parse_rule_ai_check_without_model() {
        let yaml = r#"
id: ai-rule-no-model
language: rust
severity: warning
category: slop
message: "needs AI confirmation"
rule:
  kind: line_comment
ai_check:
  prompt: "check {{filename}}"
"#;
        let rule = parse_rule(yaml).unwrap();
        let ai = rule.ai_check.as_ref().unwrap();
        assert_eq!(ai.prompt, "check {{filename}}");
        assert!(
            ai.model.is_none(),
            "model falls back to config when omitted"
        );
    }

    #[test]
    fn parse_minimal_rule() {
        let yaml = r#"
id: minimal-rule
language: rust
severity: warning
message: "Minimal"
rule:
  pattern: $X.unwrap()
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.id, RuleId::from("minimal-rule"));
        assert_eq!(rule.severity, Severity::Warning);
        assert!(rule.note.is_none());
        assert!(rule.category.is_none());
        assert!(rule.fix.is_none());
        assert!(rule.files.is_none());
        assert!(rule.ignores.is_none());
        assert!(!rule.skip_test_code);
        assert!(rule.tests.is_none());
        assert!(rule.enabled);
        assert!(rule.ai_check.is_none());
    }

    #[test]
    fn rule_activation_precedence() {
        let opt_in = parse_rule(
            r#"
id: opt-in
language: rust
severity: warning
category: slop
enabled: false
message: "Opt-in"
rule:
  pattern: $X.unwrap()
"#,
        )
        .unwrap();
        let mut config = crate::config::Config::default();

        assert!(!is_rule_active(&opt_in, &config), "enabled: false is off");

        config.rules.enable.push("opt-in".to_string());
        assert!(is_rule_active(&opt_in, &config), "enable list turns it on");

        config.rules.disable.push("opt-in".to_string());
        assert!(is_rule_active(&opt_in, &config), "enable wins over disable");

        config.rulesets.slop = false;
        assert!(is_rule_active(&opt_in, &config), "enable wins over ruleset");

        config.rules.enable.clear();
        config.rules.disable.clear();
        config.rulesets.slop = true;
        let mut default_on = opt_in.clone();
        default_on.enabled = true;
        assert!(is_rule_active(&default_on, &config));

        config.rules.disable.push("opt-in".to_string());
        assert!(!is_rule_active(&default_on, &config), "disable list");

        config.rules.disable.clear();
        config.rulesets.slop = false;
        assert!(!is_rule_active(&default_on, &config), "ruleset off");
    }

    #[test]
    fn reject_missing_id() {
        let yaml = r#"
language: rust
severity: error
message: "No id"
rule:
  pattern: $X
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing field"),
            "expected missing field error, got: {msg}"
        );
    }

    #[test]
    fn reject_unsupported_language() {
        let yaml = r#"
id: bad-lang
language: python
severity: error
message: "Bad lang"
rule:
  pattern: $X
"#;
        let err = parse_rule(yaml).unwrap_err();
        assert!(matches!(err, RuleError::Parse(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("unknown variant"),
            "expected unknown variant error, got: {msg}"
        );
    }

    #[test]
    fn reject_empty_rule() {
        let yaml = r#"
id: empty-rule
language: rust
severity: error
message: "Empty rule"
rule:
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must not be empty"),
            "expected empty rule error, got: {msg}"
        );
    }

    #[test]
    fn reject_malformed_yaml() {
        let yaml = "this is: [not: valid: yaml: {{{";
        let err = parse_rule(yaml).unwrap_err();
        assert!(matches!(err, RuleError::Parse(_)));
    }

    #[test]
    fn load_all_builtin_rules() {
        let rules = load_builtin_rules().unwrap();
        assert_eq!(
            rules.len(),
            94,
            "expected 94 builtin rules, got {}",
            rules.len()
        );

        let slop_count = rules
            .iter()
            .filter(|r| r.category == Some(Category::Slop))
            .count();
        let security_count = rules
            .iter()
            .filter(|r| r.category == Some(Category::Security))
            .count();
        let correctness_count = rules
            .iter()
            .filter(|r| r.category == Some(Category::Correctness))
            .count();
        assert_eq!(slop_count, 36, "expected 36 slop rules");
        assert_eq!(security_count, 20, "expected 20 security rules");
        assert_eq!(correctness_count, 38, "expected 38 correctness rules");

        assert!(rules
            .iter()
            .any(|r| r.id == RuleId::from("no-unwrap-in-prod")));
        assert!(rules
            .iter()
            .any(|r| r.id == RuleId::from("no-debug-on-secrets")));
        assert!(rules.iter().any(|r| r.id == RuleId::from("no-slop-words")));
        assert!(
            rules
                .iter()
                .any(|r| r.id == RuleId::from("max-file-lines") && r.is_metric()),
            "max-file-lines should be loaded as a metric rule"
        );

        validate_unique_ids(&rules).unwrap();
    }

    #[test]
    fn load_custom_rules_from_dir() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"
id: custom-rule
language: rust
severity: warning
message: "Custom rule"
rule:
  pattern: $X.clone()
"#;
        write(dir.path().join("custom.yml"), rule_yaml).unwrap();

        let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, RuleId::from("custom-rule"));
    }

    #[test]
    fn reject_duplicate_ids_same_language() {
        let rule1 = parse_rule(
            r#"
id: same-id
language: rust
severity: error
message: "First"
rule:
  pattern: $X
"#,
        )
        .unwrap();
        let rule2 = parse_rule(
            r#"
id: same-id
language: rust
severity: warning
message: "Second"
rule:
  pattern: $Y
"#,
        )
        .unwrap();
        let err = validate_unique_ids(&[rule1, rule2]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate rule id"),
            "expected duplicate id error, got: {msg}"
        );
        assert!(
            msg.contains("same-id"),
            "expected same-id in error, got: {msg}"
        );
    }

    #[test]
    fn allow_same_id_different_language() {
        let rust_rule = parse_rule(
            r#"
id: shared-rule
language: rust
severity: error
message: "Rust variant"
rule:
  pattern: $X
"#,
        )
        .unwrap();
        let ts_rule = parse_rule(
            r#"
id: shared-rule
language: typescript
severity: error
message: "TypeScript variant"
rule:
  pattern: $X
"#,
        )
        .unwrap();
        validate_unique_ids(&[rust_rule, ts_rule]).unwrap();
    }

    #[test]
    fn category_from_rule_path() {
        let category = |p: &str| Category::from_rule_path(Path::new(p));
        assert_eq!(category("slop/no-slop-words.yml"), Some(Category::Slop));
        assert_eq!(category("security/no-debug.yml"), Some(Category::Security));
        assert_eq!(
            category("correctness/no-unwrap.yml"),
            Some(Category::Correctness)
        );
        assert_eq!(category("unknown/something.yml"), None);
        assert_eq!(category("rule.yml"), None);
    }

    #[test]
    fn all_builtin_rules_valid_messages() {
        for path in BuiltinRules::iter() {
            if !is_rule_file(Path::new(path.as_ref())) {
                continue;
            }
            let file = BuiltinRules::get(&path).unwrap();
            let yaml = from_utf8(&file.data).unwrap();
            let rule: Rule = serde_yaml::from_str(yaml).unwrap();
            assert!(
                !rule.message.contains('\u{2014}'),
                "rule '{}' message contains em dash: {}",
                rule.id,
                rule.message
            );
            assert!(
                !rule.message.contains('\u{2013}'),
                "rule '{}' message contains en dash: {}",
                rule.id,
                rule.message
            );
            assert!(
                rule.message.is_ascii() || rule.message.chars().all(|c| c.is_ascii() || c == '\''),
                "rule '{}' message contains non-ASCII characters: {}",
                rule.id,
                rule.message
            );
        }
    }

    #[test]
    fn all_builtin_rules_have_tests() {
        for path in BuiltinRules::iter() {
            if !is_rule_file(Path::new(path.as_ref())) {
                continue;
            }
            let file = BuiltinRules::get(&path).unwrap();
            let yaml = from_utf8(&file.data).unwrap();
            let rule: Rule = serde_yaml::from_str(yaml).unwrap();
            let tests = rule.tests.as_ref().unwrap_or_else(|| {
                panic!("rule '{}' (at {path}) is missing `tests` block", rule.id)
            });
            if rule.is_metric() {
                // Two near-identical whole-file fixtures add no coverage, so a
                // metric rule only needs one case per direction.
                assert!(
                    tests.should_match.len() + tests.should_match_files.len() >= 1,
                    "metric rule '{}' (at {path}) needs >= 1 should_match case",
                    rule.id
                );
                assert!(
                    tests.should_not_match.len() + tests.should_not_match_files.len() >= 1,
                    "metric rule '{}' (at {path}) needs >= 1 should_not_match case",
                    rule.id
                );
                continue;
            }
            assert!(
                tests.should_match.len() >= 2,
                "rule '{}' (at {path}) needs >= 2 should_match, got {}",
                rule.id,
                tests.should_match.len()
            );
            assert!(
                tests.should_not_match.len() >= 2,
                "rule '{}' (at {path}) needs >= 2 should_not_match, got {}",
                rule.id,
                tests.should_not_match.len()
            );
        }
    }

    #[test]
    fn all_builtin_rules_have_explicit_category() {
        for path in BuiltinRules::iter() {
            if !is_rule_file(Path::new(path.as_ref())) {
                continue;
            }
            let file = BuiltinRules::get(&path).unwrap();
            let yaml = from_utf8(&file.data).unwrap();
            let rule: Rule = serde_yaml::from_str(yaml).unwrap();
            assert!(
                rule.category.is_some(),
                "rule '{}' (at {path}) is missing an explicit `category` field",
                rule.id
            );
        }
    }

    #[test]
    fn parse_metric_rule() {
        let yaml = r#"
id: max-lines
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "File exceeds 500 lines ($value lines)."
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.metric, Some(Metric::FileLines));
        assert_eq!(rule.threshold, Some(500.0));
        assert!(rule.is_metric());
        assert_eq!(rule.metric_spec(), Some((Metric::FileLines, 500.0)));
        assert!(rule.rule.is_null());
    }

    #[test]
    fn reject_metric_with_rule() {
        let yaml = r#"
id: both
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "m"
rule:
  pattern: $X
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive"),
            "expected mutually exclusive error, got: {msg}"
        );
    }

    #[test]
    fn reject_metric_without_threshold() {
        let yaml = r#"
id: no-threshold
language: rust
severity: warning
category: slop
metric: file_lines
message: "m"
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("threshold"),
            "expected threshold error, got: {msg}"
        );
    }

    #[test]
    fn reject_fixture_files_on_ast_rule() {
        let yaml = r#"
id: ast-with-fixture
language: rust
severity: warning
category: slop
message: "m"
rule:
  pattern: $X
tests:
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("only supported for metric rules"),
            "expected fixture-on-ast-rule error, got: {msg}"
        );
    }

    #[test]
    fn parse_metric_rule_with_fixture_files() {
        let yaml = r#"
id: metric-with-fixtures
language: rust
severity: warning
category: slop
metric: import_count
threshold: 40
message: "m"
tests:
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
  should_not_match_files:
    - "fixtures/metrics/rust_small.rs"
"#;
        let rule = parse_rule(yaml).unwrap();
        let tests = rule.tests.as_ref().unwrap();
        assert_eq!(
            tests.should_match_files,
            vec!["fixtures/metrics/rust_large.rs".to_string()]
        );
        assert_eq!(
            tests.should_not_match_files,
            vec!["fixtures/metrics/rust_small.rs".to_string()]
        );
    }

    fn fixture_metric_rule() -> Rule {
        parse_rule(
            r#"
id: fixture-reader
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "m"
"#,
        )
        .unwrap()
    }

    #[test]
    fn read_fixture_rejects_parent_dir() {
        let rule = fixture_metric_rule();
        let err = read_fixture(&rule, "../secrets.rs").unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidFixturePath { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn read_fixture_rejects_absolute_path() {
        let rule = fixture_metric_rule();
        let err = read_fixture(&rule, "/etc/passwd").unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidFixturePath { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn read_fixture_from_custom_dir() {
        let dir = tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        create_dir(&fixtures).unwrap();
        write(fixtures.join("big.rs"), "fn a() {}
fn b() {}
").unwrap();
        write(
            dir.path().join("metric.yml"),
            r#"
id: custom-metric
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 1
message: "m"
tests:
  should_match_files:
    - "fixtures/big.rs"
"#,
        )
        .unwrap();

        let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].source_dir.as_deref(), Some(dir.path()));
        let content = read_fixture(&rules[0], "fixtures/big.rs").unwrap();
        assert_eq!(content, "fn a() {}
fn b() {}
");
    }

    #[test]
    fn read_fixture_missing_in_custom_dir() {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("metric.yml"),
            r#"
id: custom-metric-missing
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 1
message: "m"
"#,
        )
        .unwrap();
        let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
        let err = read_fixture(&rules[0], "fixtures/nope.rs").unwrap_err();
        assert!(matches!(err, RuleError::FixtureNotFound { .. }), "{err:?}");
    }

    #[test]
    fn read_builtin_fixture() {
        let rules = load_builtin_rules().unwrap();
        let rule = rules
            .iter()
            .find(|r| r.id == RuleId::from("max-file-lines"))
            .expect("max-file-lines should be a builtin rule");
        let content = read_fixture(rule, "fixtures/metrics/rust_large.rs").unwrap();
        assert!(
            content.lines().count() > 500,
            "the large fixture should exceed 500 lines, got {}",
            content.lines().count()
        );
    }

    #[test]
    fn custom_rules_category_from_subdir() {
        let dir = tempdir().unwrap();
        let security_dir = dir.path().join("security");
        create_dir(&security_dir).unwrap();
        let rule_yaml = r#"
id: custom-sec
language: rust
severity: error
message: "Custom security"
rule:
  pattern: $X
"#;
        write(security_dir.join("rule.yml"), rule_yaml).unwrap();

        let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].category, Some(Category::Security));
    }
}
