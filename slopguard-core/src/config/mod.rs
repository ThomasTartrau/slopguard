use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use smart_default::SmartDefault;
use strum::{Display, EnumString};
use thiserror::Error;
use toml::de;
use toml::{Table, Value};

#[derive(Debug, Display, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, Default)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
    Html,
}

/// Transport used to reach the LLM.
#[derive(Debug, Display, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, Default)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AiTransport {
    /// Direct HTTP calls to a provider API (default).
    #[default]
    Api,
    /// Shell out to the local `claude` CLI (uses the Claude subscription).
    Cli,
}

/// Vendor used when `provider = "api"`.
#[derive(Debug, Display, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, Default)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AiVendor {
    #[default]
    Anthropic,
    OpenAI,
}

/// How the System One classifier (Jev) reaches the TypeSafe API.
#[derive(
    Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Default,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ClassifierTransport {
    /// Native TypeSafe endpoint, authenticated with `TYPESAFE_API_KEY`.
    #[default]
    Direct,
    /// OpenRouter's Decisions endpoint, authenticated with `OPENROUTER_API_KEY`.
    Openrouter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
pub struct RulesetsConfig {
    #[default = true]
    pub slop: bool,
    #[default = true]
    pub security: bool,
    #[default = true]
    pub correctness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesConfig {
    pub disable: Vec<String>,
    /// Rule ids to activate regardless of `disable`, the rulesets switches,
    /// or the rule's own `enabled: false` (opt-in rules).
    pub enable: Vec<String>,
    pub custom_dirs: Vec<PathBuf>,
    /// External rule sources: git repositories (cloned and cached) and extra
    /// local paths. Loaded as custom rules, with their provenance tracked.
    pub sources: Vec<RuleSource>,
    /// Per-rule options, one `[rules.options.<id>]` table per rule that reads
    /// any. An unknown rule id or key is a config error, not a silent no-op.
    pub options: RuleOptions,
}

/// The options of the builtin rules that take some, keyed by rule id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RuleOptions {
    #[serde(rename = "no-assertion-free-test")]
    pub no_assertion_free_test: AssertionFreeTestOptions,
}

/// `[rules.options.no-assertion-free-test]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AssertionFreeTestOptions {
    /// Bare names of functions, methods or macros that assert but live outside
    /// the scanned project (test support from a dependency). `*` is a wildcard:
    /// `["run", "check_*"]`. A test calling one of them is not reported.
    pub assert_functions: Vec<String>,
}

/// One external rule source declared as `[[rules.sources]]`.
///
/// A source is either a git repository (`git` set, optional `ref` and `path`
/// sub-directory) or a local directory (`path` set, no `git`). `ref` is only
/// meaningful for a git source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RuleSource {
    /// Git URL to clone. `None` for a local source.
    pub git: Option<String>,
    /// Tag, branch or sha to check out. Defaults to the repository's default
    /// branch. Only valid alongside `git`.
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    /// For a git source, the sub-directory inside the repository to load rules
    /// from (defaults to the root). For a local source, the directory to load.
    pub path: Option<PathBuf>,
}

impl RuleSource {
    /// Whether this source is a git repository (as opposed to a local path).
    pub fn is_git(&self) -> bool {
        self.git.is_some()
    }

    /// Reject a source that declares neither `git` nor `path`, or a `ref`
    /// without a `git` (a ref is meaningless for a local path).
    fn validate(&self) -> Result<(), String> {
        match (&self.git, &self.path, &self.git_ref) {
            (None, None, _) => Err("a rule source needs either 'git' or 'path'".to_string()),
            (None, Some(_), Some(_)) => {
                Err("'ref' is only valid on a git source, not a local 'path'".to_string())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ScanConfig {
    pub ignores: Vec<String>,
    /// Extra glob patterns marking whole files as test code, on top of the
    /// built-in layout heuristic. Findings from `skip_test_code` rules are
    /// suppressed in matching files.
    pub test_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
pub struct OutputConfig {
    pub format: OutputFormat,
    #[default = true]
    pub colors: bool,
}

/// The optional System One classifier (Jev / TypeSafe), on a separate axis from
/// the generative LLM. Off by default: opt-in strict, since Jev is a proprietary
/// SaaS and slopguard's deterministic AST mode stays the offline socle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
pub struct ClassifierConfig {
    /// Whether the classifier is active. Never on by default.
    pub enabled: bool,
    /// How to reach TypeSafe: `direct` or `openrouter`.
    pub transport: ClassifierTransport,
    /// Model route (e.g. `jev-latest` direct, `typesafe/jev-1.13` on OpenRouter).
    /// When omitted, the transport's default slug is used.
    pub model: Option<String>,
    /// Global probability threshold: a candidate fires when `p >= threshold`.
    /// Overridden per rule by `ai_check.threshold`.
    #[default = 0.7]
    pub threshold: f64,
    /// Batch cache-miss candidates whose context windows overlap into a single
    /// multi-noul request per cluster. `false` falls back to one call per
    /// candidate.
    #[default = true]
    pub batch: bool,
    /// Maximum number of candidates (nouls) grouped into one batched request.
    #[default = 8]
    pub batch_max_questions: usize,
    /// Maximum number of source lines carried in one batched request `state`.
    #[default = 200]
    pub batch_max_state_lines: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    /// Transport: `api` (HTTP) or `cli` (local `claude`).
    pub provider: AiTransport,
    /// Vendor used when `provider = "api"`.
    pub vendor: AiVendor,
    pub model: Option<String>,
    /// Maximum number of concurrent LLM calls.
    #[default = 4]
    pub concurrency: usize,
    /// API key. When omitted, read from the vendor's env var
    /// (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`).
    pub api_key: Option<String>,
    /// Optional System One classifier (Jev), on a separate axis from the LLM.
    pub classifier: ClassifierConfig,
}

/// Severity escalation: when one rule fires repeatedly in a single file, its
/// warnings become errors. Opt-in so existing CI results do not change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
pub struct EscalationConfig {
    /// Off by default.
    pub enabled: bool,
    /// Findings of the same rule in the same file needed to escalate.
    #[default = 5]
    pub threshold: usize,
    /// Per-rule thresholds, overriding `threshold`. Keys are rule ids.
    pub rules: HashMap<String, usize>,
}

/// `scan --fix` policy. Builtin rules marked `autofix_safe` are always
/// rewritten; a rule from `rules.custom_dirs` or `[[rules.sources]]` is
/// rewritten only when its id is listed in `allow_external`, so a third-party
/// ruleset cannot rewrite source files on its own say-so. User-only: an
/// untrusted repo `slopguard.toml` cannot set it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FixConfig {
    /// Ids of external rules whose `autofix_safe` rewrite `--fix` may apply.
    pub allow_external: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub rulesets: RulesetsConfig,
    pub rules: RulesConfig,
    pub scan: ScanConfig,
    pub output: OutputConfig,
    pub ai: AiConfig,
    pub escalation: EscalationConfig,
    pub fix: FixConfig,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse config file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: de::Error,
    },

    #[error("invalid merged config: {0}")]
    Invalid(#[source] de::Error),

    #[error("invalid rule source: {0}")]
    InvalidSource(String),

    #[error("[ai].concurrency must be between 1 and {max}, got {0}", max = MAX_AI_CONCURRENCY)]
    InvalidConcurrency(usize),

    #[error("'{key}' = '{path}' resolves outside the repository root '{root}'")]
    PathOutsideRepo {
        key: String,
        path: String,
        root: String,
    },
}

/// Upper bound of `[ai].concurrency`. Keeps the AI pass far below the
/// semaphore permit limit and the provider's rate limits.
pub const MAX_AI_CONCURRENCY: usize = 64;

/// Whether the scanned repository's `slopguard.toml` is trusted.
///
/// An untrusted repo file cannot set the user-only keys (`[ai]`, `[fix]`,
/// `scan.cache_dir`) and its rule paths must stay inside the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProjectTrust {
    #[default]
    Untrusted,
    Trusted,
}

/// A resolved config plus the warnings raised while loading it (reserved
/// keys dropped from an untrusted repo file).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Reject an `[ai].concurrency` outside `1..=MAX_AI_CONCURRENCY`.
fn validate_concurrency(config: &Config) -> Result<(), ConfigError> {
    let concurrency = config.ai.concurrency;
    if (1..=MAX_AI_CONCURRENCY).contains(&concurrency) {
        Ok(())
    } else {
        Err(ConfigError::InvalidConcurrency(concurrency))
    }
}

/// Keys an untrusted repo file cannot set, as dotted paths into its table.
const RESERVED_KEYS: [&str; 3] = ["ai", "fix", "scan.cache_dir"];

/// Remove the user-only keys from an untrusted repo table and return a single
/// warning naming every removed leaf key, sorted. Values are never echoed:
/// `api_key` is a secret.
fn strip_reserved_keys(project: &mut Table) -> Option<String> {
    let mut removed = Vec::new();
    for key in RESERVED_KEYS {
        if let Some(value) = remove_dotted(project, key) {
            push_leaf_keys(key.to_string(), value, &mut removed);
        }
    }
    if removed.is_empty() {
        return None;
    }
    removed.sort();
    let keys = removed
        .iter()
        .map(|key| format!("'{key}'"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "ignored {keys} in slopguard.toml: reserved to the user config \
         (set them in ~/.config/slopguard/config.toml or with CLI flags, or pass --trust-repo-config)"
    ))
}

/// Remove the value at a dotted `path` (`"scan.cache_dir"`) from `table`.
fn remove_dotted(table: &mut Table, path: &str) -> Option<Value> {
    match path.split_once('.') {
        None => table.remove(path),
        Some((head, rest)) => match table.get_mut(head)? {
            Value::Table(sub) => remove_dotted(sub, rest),
            _ => None,
        },
    }
}

/// Push the dotted path of every leaf under `value` (itself when not a table).
fn push_leaf_keys(prefix: String, value: Value, out: &mut Vec<String>) {
    match value {
        Value::Table(table) => {
            for (key, sub) in table {
                push_leaf_keys(format!("{prefix}.{key}"), sub, out);
            }
        }
        _ => out.push(prefix),
    }
}

/// Reject a repo-supplied rule path that resolves outside `root`.
///
/// Only `rules.custom_dirs` and local `[[rules.sources]]` are checked: the
/// `path` of a git source is a sub-directory of the clone, not of the
/// filesystem.
fn check_repo_paths(rules: &RulesConfig, root: &Path) -> Result<(), ConfigError> {
    let custom_dirs = rules
        .custom_dirs
        .iter()
        .map(|dir| ("rules.custom_dirs", dir.as_path()));
    let sources = rules
        .sources
        .iter()
        .filter(|source| !source.is_git())
        .filter_map(|source| source.path.as_deref())
        .map(|path| ("rules.sources.path", path));
    let mut paths = custom_dirs.chain(sources).peekable();
    if paths.peek().is_none() {
        return Ok(());
    }
    let canonical_root = root.canonicalize().map_err(|source| ConfigError::Io {
        path: root.display().to_string(),
        source,
    })?;
    for (key, path) in paths {
        let inside = resolves_inside(path, &canonical_root).map_err(|source| ConfigError::Io {
            path: canonical_root.join(path).display().to_string(),
            source,
        })?;
        if !inside {
            return Err(ConfigError::PathOutsideRepo {
                key: key.to_string(),
                path: path.display().to_string(),
                root: canonical_root.display().to_string(),
            });
        }
    }
    Ok(())
}

/// Whether `path`, taken relative to the canonical `root`, stays inside it.
///
/// An existing path is canonicalized, so a symlink escaping the root is caught.
/// A missing one (skipped at load time) gets a lexical check: no `..`
/// component, and an absolute path must sit under the root.
fn resolves_inside(path: &Path, root: &Path) -> io::Result<bool> {
    let joined = root.join(path);
    match joined.canonicalize() {
        Ok(canonical) => Ok(canonical.starts_with(root)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let has_parent = path.components().any(|c| c == Component::ParentDir);
            Ok(!has_parent && joined.starts_with(root))
        }
        Err(err) => Err(err),
    }
}

/// Validate every `[[rules.sources]]` entry, returning the first invalid one.
fn validate_sources(config: &Config) -> Result<(), ConfigError> {
    for source in &config.rules.sources {
        source.validate().map_err(ConfigError::InvalidSource)?;
    }
    Ok(())
}

/// Overlay `over` onto `base`: nested tables are merged key by key, every
/// other value in `over` replaces the one in `base`.
fn merge_tables(base: &mut Table, over: Table) {
    for (key, over_value) in over {
        match (base.get_mut(&key), over_value) {
            (Some(Value::Table(base_table)), Value::Table(over_table)) => {
                merge_tables(base_table, over_table);
            }
            (_, over_value) => {
                base.insert(key, over_value);
            }
        }
    }
}

/// Read one config file as a raw table, plus the config it alone describes.
/// A missing file yields an empty table and the default config. The file is
/// validated on its own so that errors name the file they come from.
fn load_table(path: &Path) -> Result<(Table, Config), ConfigError> {
    if !path.is_file() {
        return Ok((Table::new(), Config::default()));
    }
    let display = path.display().to_string();
    let content = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: display.clone(),
        source,
    })?;
    let table: Table = toml::from_str(&content).map_err(|source| ConfigError::Parse {
        path: display.clone(),
        source,
    })?;
    let config = table
        .clone()
        .try_into::<Config>()
        .map_err(|source| ConfigError::Parse {
            path: display,
            source,
        })?;
    Ok((table, config))
}

/// Load config with explicit paths (for testing).
///
/// With [`ProjectTrust::Untrusted`], the repo file's rule paths must stay
/// inside `project_root` and its user-only keys (`[ai]`, `[fix]`, `scan.cache_dir`)
/// are dropped with a warning. The global file is always trusted.
pub fn load_config_from(
    global_dir: Option<&Path>,
    project_root: &Path,
    trust: ProjectTrust,
) -> Result<LoadedConfig, ConfigError> {
    let mut merged = Table::new();
    if let Some(dir) = global_dir {
        let (global, _) = load_table(&dir.join("slopguard").join("config.toml"))?;
        merge_tables(&mut merged, global);
    }
    let (mut project, project_config) = load_table(&project_root.join("slopguard.toml"))?;
    let warnings = match trust {
        ProjectTrust::Untrusted => {
            check_repo_paths(&project_config.rules, project_root)?;
            strip_reserved_keys(&mut project).into_iter().collect()
        }
        ProjectTrust::Trusted => Vec::new(),
    };
    merge_tables(&mut merged, project);
    let config: Config = merged.try_into().map_err(ConfigError::Invalid)?;
    validate_sources(&config)?;
    validate_concurrency(&config)?;
    Ok(LoadedConfig { config, warnings })
}

/// Load configuration from a single file, skipping hierarchical resolution.
///
/// The file is chosen explicitly by the user (`--config`), so it is trusted:
/// no key is reserved and rule paths may point anywhere.
pub fn load_config_file(path: &Path) -> Result<Config, ConfigError> {
    let display = path.display().to_string();
    let content = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: display.clone(),
        source,
    })?;
    let config: Config = toml::from_str(&content).map_err(|source| ConfigError::Parse {
        path: display,
        source,
    })?;
    validate_sources(&config)?;
    validate_concurrency(&config)?;
    Ok(config)
}

/// Load configuration with hierarchical resolution.
///
/// Resolution order (later overrides earlier):
/// 1. `~/.config/slopguard/config.toml` (global defaults)
/// 2. `slopguard.toml` at `project_root` (project overrides)
///
/// Unless `trust` is [`ProjectTrust::Trusted`], the project file cannot set
/// the user-only keys (`[ai]`, `[fix]`, `scan.cache_dir`) and its rule paths must stay
/// inside `project_root`. See [`load_config_from`].
pub fn load_config(project_root: &Path, trust: ProjectTrust) -> Result<LoadedConfig, ConfigError> {
    let global_dir = dirs::config_dir();
    load_config_from(global_dir.as_deref(), project_root, trust)
}

#[cfg(test)]
mod tests;
