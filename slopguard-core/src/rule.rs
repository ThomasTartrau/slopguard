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

#[derive(Debug, Display, EnumIter, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub rule: Value,
    #[serde(default)]
    pub files: Option<Vec<String>>,
    #[serde(default)]
    pub ignores: Option<Vec<String>>,
    #[serde(default)]
    pub tests: Option<RuleTests>,
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("failed to parse rule YAML: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("rule '{id}': rule field must not be empty")]
    EmptyRule { id: RuleId },

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
pub fn parse_rule(yaml: &str) -> Result<Rule, RuleError> {
    let rule: Rule = serde_yaml::from_str(yaml)?;
    if rule.rule.is_null() {
        return Err(RuleError::EmptyRule { id: rule.id });
    }
    Ok(rule)
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
            rules.push(parse_rule_at(&yaml, relative)?);
        }
    }
    Ok(rules)
}

/// Validate that all rule ids are unique.
pub fn validate_unique_ids(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(&rule.id) {
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
tests:
  should_match:
    - "let x = foo().unwrap();"
  should_not_match:
    - "let x = foo()?;"
"#;
        let rule = parse_rule(yaml).unwrap();
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
        assert!(rule.tests.is_none());
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
            34,
            "expected 34 builtin rules, got {}",
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
        assert_eq!(slop_count, 9, "expected 9 slop rules");
        assert_eq!(security_count, 8, "expected 8 security rules");
        assert_eq!(correctness_count, 17, "expected 17 correctness rules");

        assert!(rules
            .iter()
            .any(|r| r.id == RuleId::from("no-unwrap-in-prod")));
        assert!(rules
            .iter()
            .any(|r| r.id == RuleId::from("no-debug-on-secrets")));
        assert!(rules.iter().any(|r| r.id == RuleId::from("no-slop-words")));

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
    fn reject_duplicate_ids() {
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
