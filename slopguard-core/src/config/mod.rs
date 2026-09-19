use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub rulesets: RulesetsConfig,
    pub rules: RulesConfig,
    pub scan: ScanConfig,
    pub output: OutputConfig,
    pub ai: AiConfig,
    pub escalation: EscalationConfig,
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

/// Read one config file as a raw table. A missing file yields an empty table.
/// The file is validated on its own so that errors name the file they come from.
fn load_table(path: &Path) -> Result<Table, ConfigError> {
    if !path.is_file() {
        return Ok(Table::new());
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
    table
        .clone()
        .try_into::<Config>()
        .map_err(|source| ConfigError::Parse {
            path: display,
            source,
        })?;
    Ok(table)
}

/// Load config with explicit paths (for testing).
pub fn load_config_from(
    global_dir: Option<&Path>,
    project_root: &Path,
) -> Result<Config, ConfigError> {
    let mut merged = Table::new();
    if let Some(dir) = global_dir {
        let global = load_table(&dir.join("slopguard").join("config.toml"))?;
        merge_tables(&mut merged, global);
    }
    let project = load_table(&project_root.join("slopguard.toml"))?;
    merge_tables(&mut merged, project);
    merged.try_into().map_err(ConfigError::Invalid)
}

/// Load configuration from a single file, skipping hierarchical resolution.
pub fn load_config_file(path: &Path) -> Result<Config, ConfigError> {
    let display = path.display().to_string();
    let content = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: display.clone(),
        source,
    })?;
    toml::from_str(&content).map_err(|source| ConfigError::Parse {
        path: display,
        source,
    })
}

/// Load configuration with hierarchical resolution.
///
/// Resolution order (later overrides earlier):
/// 1. `~/.config/slopguard/config.toml` (global defaults)
/// 2. `slopguard.toml` at `project_root` (project overrides)
pub fn load_config(project_root: &Path) -> Result<Config, ConfigError> {
    let global_dir = dirs::config_dir();
    load_config_from(global_dir.as_deref(), project_root)
}

#[cfg(test)]
mod tests;
