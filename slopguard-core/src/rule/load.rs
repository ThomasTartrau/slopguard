//! Rule loading: the embedded builtin ruleset, custom directories and external
//! sources, their activation under a config, and whole-file test fixtures.

use std::collections::HashSet;
use std::fs::read_to_string;
use std::io::Error as IoError;
use std::path::{Component, Path, PathBuf};
use std::str::from_utf8;

use ignore::WalkBuilder;
use slopguard_rules::BuiltinRules;

use super::{parse_rule, Category, Language, Rule, RuleError, RuleId};
use crate::config::Config;
use crate::source::{ResolvedSource, RuleOrigin};

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

pub(super) fn is_rule_file(path: &Path) -> bool {
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
pub fn is_rule_active(rule: &Rule, config: &Config) -> bool {
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
    config: &Config,
    sources: &[ResolvedSource],
    builtin: &[Rule],
) -> Result<(Vec<Rule>, Vec<Rule>), RuleError> {
    let custom = load_custom_rules(&config.rules.custom_dirs)?;
    let from_sources = load_source_rules(sources)?;
    reject_builtin_id_reuse(&custom, builtin)?;
    reject_builtin_id_reuse(&from_sources, builtin)?;
    Ok((custom, from_sources))
}

/// Load all effective rules based on config: builtin, custom rules from
/// configured directories, and rules from resolved external sources, all
/// filtered by [`is_rule_active`] (rulesets, `enabled: false`, and the
/// enable/disable lists). An external rule reusing a builtin id is rejected
/// before any filtering.
pub fn load_effective_rules(
    config: &Config,
    sources: &[ResolvedSource],
) -> Result<Vec<Rule>, RuleError> {
    let builtin = load_builtin_rules()?;
    let (custom, from_sources) = load_external_rules(config, sources, &builtin)?;

    // Rules from `custom_dirs` are an explicit opt-in and are not gated by
    // rulesets or `enabled`; builtin and source rules are.
    let mut rules: Vec<Rule> = builtin
        .into_iter()
        .chain(from_sources)
        .filter(|rule| is_rule_active(rule, config))
        .collect();
    rules.extend(custom);
    validate_unique_ids(&rules)?;
    Ok(rules)
}

/// Load all rules (builtin + custom + external sources) without filtering by
/// activation status. Used by `explain` to look up any rule regardless of
/// config, so an opt-in or disabled rule can still be explained.
pub fn load_all_rules(config: &Config, sources: &[ResolvedSource]) -> Result<Vec<Rule>, RuleError> {
    let builtin = load_builtin_rules()?;
    let (custom, from_sources) = load_external_rules(config, sources, &builtin)?;

    let mut rules = builtin;
    rules.extend(custom);
    rules.extend(from_sources);
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
