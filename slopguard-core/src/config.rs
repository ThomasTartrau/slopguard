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

fn default_concurrency() -> usize {
    4
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
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
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// API key. When omitted, read from the vendor's env var
    /// (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`).
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub rulesets: RulesetsConfig,
    pub rules: RulesConfig,
    pub scan: ScanConfig,
    pub output: OutputConfig,
    pub ai: AiConfig,
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
mod tests {
    use std::fs::{create_dir_all, write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parse_complete_config() {
        let dir = tempdir().unwrap();
        let toml = r#"
[rulesets]
slop = false
security = true
correctness = false

[rules]
disable = ["pub-fn-needs-tracing", "no-glob-reexport"]
enable = ["test-needs-timeout"]
custom_dirs = ["./my-rules"]

[scan]
ignores = ["target/", "generated/"]

[output]
format = "json"
colors = false

[ai]
enabled = true
provider = "cli"
vendor = "openai"
model = "claude-sonnet-5"
concurrency = 8
api_key = "sk-test"
"#;
        write(dir.path().join("slopguard.toml"), toml).unwrap();

        let cfg = load_config_from(None, dir.path()).unwrap();
        assert!(!cfg.rulesets.slop);
        assert!(cfg.rulesets.security);
        assert!(!cfg.rulesets.correctness);
        assert_eq!(
            cfg.rules.disable,
            vec!["pub-fn-needs-tracing", "no-glob-reexport"]
        );
        assert_eq!(cfg.rules.enable, vec!["test-needs-timeout"]);
        assert_eq!(cfg.rules.custom_dirs, vec![PathBuf::from("./my-rules")]);
        assert_eq!(cfg.scan.ignores, vec!["target/", "generated/"]);
        assert_eq!(cfg.output.format, OutputFormat::Json);
        assert!(!cfg.output.colors);
        assert!(cfg.ai.enabled);
        assert_eq!(cfg.ai.provider, AiTransport::Cli);
        assert_eq!(cfg.ai.vendor, AiVendor::OpenAI);
        assert_eq!(cfg.ai.model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(cfg.ai.concurrency, 8);
        assert_eq!(cfg.ai.api_key.as_deref(), Some("sk-test"));
    }

    #[test]
    fn parse_partial_config() {
        let dir = tempdir().unwrap();
        let toml = r#"
[rulesets]
slop = false
"#;
        write(dir.path().join("slopguard.toml"), toml).unwrap();

        let cfg = load_config_from(None, dir.path()).unwrap();
        assert!(!cfg.rulesets.slop);
        assert!(cfg.rulesets.security);
        assert!(cfg.rulesets.correctness);
        assert!(cfg.rules.disable.is_empty());
        assert_eq!(cfg.output.format, OutputFormat::Text);
        assert!(cfg.output.colors);
        assert!(!cfg.ai.enabled);
        // defaults hold when [ai] is absent
        assert_eq!(cfg.ai.provider, AiTransport::Api);
        assert_eq!(cfg.ai.vendor, AiVendor::Anthropic);
        assert_eq!(cfg.ai.concurrency, 4);
    }

    #[test]
    fn merge_project_overrides_global() {
        let global_dir = tempdir().unwrap();
        let project_dir = tempdir().unwrap();

        let slopguard_config_dir = global_dir.path().join("slopguard");
        create_dir_all(&slopguard_config_dir).unwrap();

        let global_toml = r#"
[rulesets]
slop = false
security = true

[rules]
disable = ["no-glob-reexport"]

[output]
format = "json"
colors = false
"#;
        write(slopguard_config_dir.join("config.toml"), global_toml).unwrap();

        let project_toml = r#"
[rulesets]
slop = true

[output]
format = "sarif"
"#;
        write(project_dir.path().join("slopguard.toml"), project_toml).unwrap();

        let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();

        // project overrides global for slop
        assert!(cfg.rulesets.slop);
        // global value kept for security (not in project)
        assert!(cfg.rulesets.security);
        // default kept for correctness (in neither)
        assert!(cfg.rulesets.correctness);
        // global value kept for rules.disable (not in project)
        assert_eq!(cfg.rules.disable, vec!["no-glob-reexport"]);
        // project overrides global for format
        assert_eq!(cfg.output.format, OutputFormat::Sarif);
        // global value kept for colors (not in project)
        assert!(!cfg.output.colors);
    }

    #[test]
    fn invalid_toml_error() {
        let dir = tempdir().unwrap();
        let bad_toml = "this is not [valid toml {{{";
        write(dir.path().join("slopguard.toml"), bad_toml).unwrap();

        let err = load_config_from(None, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("slopguard.toml"),
            "error should mention the file path, got: {msg}"
        );
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected Parse error, got: {err:?}"
        );
    }

    #[test]
    fn unknown_format_error() {
        let dir = tempdir().unwrap();
        let toml = r#"
[output]
format = "xml"
"#;
        write(dir.path().join("slopguard.toml"), toml).unwrap();

        let err = load_config_from(None, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected Parse error for unknown format, got: {msg}"
        );
        assert!(
            msg.contains("slopguard.toml") && msg.contains("output.format"),
            "error should name the file and the key, got: {msg}"
        );
    }

    #[test]
    fn load_config_with_temp_dirs() {
        let global_dir = tempdir().unwrap();
        let project_dir = tempdir().unwrap();

        let slopguard_config_dir = global_dir.path().join("slopguard");
        create_dir_all(&slopguard_config_dir).unwrap();

        write(
            slopguard_config_dir.join("config.toml"),
            "[rulesets]\nslop = false\n",
        )
        .unwrap();
        write(
            project_dir.path().join("slopguard.toml"),
            "[output]\nformat = \"json\"\n",
        )
        .unwrap();

        let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();
        assert!(!cfg.rulesets.slop);
        assert_eq!(cfg.output.format, OutputFormat::Json);
        assert!(cfg.output.colors);
    }

    #[test]
    fn load_config_global_only() {
        let global_dir = tempdir().unwrap();
        let project_dir = tempdir().unwrap();

        let slopguard_config_dir = global_dir.path().join("slopguard");
        create_dir_all(&slopguard_config_dir).unwrap();

        write(
            slopguard_config_dir.join("config.toml"),
            "[rulesets]\ncorrectness = false\n\n[output]\nformat = \"sarif\"\n",
        )
        .unwrap();

        // No slopguard.toml in project dir
        let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();
        assert!(cfg.rulesets.slop);
        assert!(cfg.rulesets.security);
        assert!(!cfg.rulesets.correctness);
        assert_eq!(cfg.output.format, OutputFormat::Sarif);
        assert!(cfg.output.colors);
    }

    #[test]
    fn default_config() {
        let cfg = Config::default();
        assert!(cfg.rulesets.slop);
        assert!(cfg.rulesets.security);
        assert!(cfg.rulesets.correctness);
        assert!(cfg.rules.disable.is_empty());
        assert!(cfg.rules.custom_dirs.is_empty());
        assert!(cfg.scan.ignores.is_empty());
        assert_eq!(cfg.output.format, OutputFormat::Text);
        assert!(cfg.output.colors);
        assert!(!cfg.ai.enabled);
        assert_eq!(cfg.ai.provider, AiTransport::Api);
        assert_eq!(cfg.ai.vendor, AiVendor::Anthropic);
        assert_eq!(cfg.ai.concurrency, 4);
        assert!(cfg.ai.model.is_none());
        assert!(cfg.ai.api_key.is_none());
    }

    #[test]
    fn parse_cache_dir() {
        let dir = tempdir().unwrap();
        let toml = r#"
[scan]
cache_dir = ".cache/slopguard"
"#;
        write(dir.path().join("slopguard.toml"), toml).unwrap();

        let cfg = load_config_from(None, dir.path()).unwrap();
        assert_eq!(cfg.scan.cache_dir, Some(PathBuf::from(".cache/slopguard")));
    }

    #[test]
    fn parse_cache_dir_absent() {
        let dir = tempdir().unwrap();
        let toml = r#"
[scan]
ignores = ["target/"]
"#;
        write(dir.path().join("slopguard.toml"), toml).unwrap();

        let cfg = load_config_from(None, dir.path()).unwrap();
        assert!(cfg.scan.cache_dir.is_none());
    }

    #[test]
    fn enum_string_roundtrip() {
        assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(AiVendor::OpenAI.to_string(), "openai");
        assert_eq!("openai".parse::<AiVendor>().unwrap(), AiVendor::OpenAI);
        assert_eq!(AiTransport::Cli.to_string(), "cli");
        assert_eq!("api".parse::<AiTransport>().unwrap(), AiTransport::Api);
    }
}
