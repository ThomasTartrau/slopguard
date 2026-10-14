//! Plumbing shared by every subcommand: the error type, config and rule source
//! resolution, the cache directory, and the repo trust set from the CLI.

use std::cmp::Ordering;
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use strsim::normalized_levenshtein;
use thiserror::Error;

use slopguard_core::baseline::BaselineError;
use slopguard_core::cache::project_cache_dir;
use slopguard_core::config::{load_config, load_config_file, Config, ConfigError, ProjectTrust};
use slopguard_core::git::GitError;
use slopguard_core::rule::{Rule, RuleError};
use slopguard_core::scanner::ScanError;
use slopguard_core::source::{
    default_allowed_protocols, default_cache_root, git_token_from_env, resolve_sources,
    unpinned_source_warnings, ResolvedSource, SourceError, SourceOptions,
};
use slopguard_core::testing::TestError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Rule(#[from] RuleError),
    #[error("{0}")]
    Scan(#[from] ScanError),
    #[error("{0}")]
    Test(#[from] TestError),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Baseline(#[from] BaselineError),
    #[error("{0}")]
    Git(#[from] GitError),
    #[error("{0}")]
    Source(#[from] SourceError),
}

/// Resolve the external rule sources declared in `config`, cloning or
/// refreshing git sources (unless `offline`). Shared by every subcommand that
/// loads rules. Each git source not pinned to a commit sha is reported on
/// stderr first, and the token is only bound to the user's trusted host.
pub(crate) fn resolve_config_sources(
    config: &Config,
    offline: bool,
) -> Result<Vec<ResolvedSource>, AppError> {
    for warning in unpinned_source_warnings(&config.rules.sources) {
        // CLI diagnostic to stderr, not application logging.
        // slopguard-disable-next-line no-println-in-prod
        eprintln!("warning: {warning}");
    }
    let opts = SourceOptions {
        cache_root: default_cache_root(),
        offline,
        git_token: git_token_from_env(config.git.token_host.as_deref()),
        allowed_protocols: default_allowed_protocols(),
    };
    Ok(resolve_sources(&config.rules.sources, &opts)?)
}

/// The closest rule id to `id` by normalized edit distance, if one clears the
/// 0.6 similarity bar. Powers the "did you mean" hint for unknown rule ids.
pub(crate) fn suggest_similar<'a>(id: &str, rules: &'a [Rule]) -> Option<&'a str> {
    rules
        .iter()
        .map(|r| (r.id.as_str(), normalized_levenshtein(id, r.id.as_str())))
        .filter(|(_, score)| *score >= 0.6)
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal))
        .map(|(id, _)| id)
}

pub(crate) fn resolve_cache_dir(cli_flag: Option<PathBuf>, config: &Config) -> PathBuf {
    cli_flag
        .or_else(|| {
            env::var("SLOPGUARD_CACHE_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| config.scan.cache_dir.clone())
        .unwrap_or_else(|| {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            project_cache_dir(&cwd)
        })
}

/// Trust granted to the scanned repo's `slopguard.toml`, set once from
/// `--trust-repo-config` so every subcommand loads config the same way.
static REPO_TRUST: OnceLock<ProjectTrust> = OnceLock::new();

/// Record the trust from `--trust-repo-config`. Called once, before any
/// subcommand loads config; later calls keep the first value.
pub(crate) fn set_repo_trust(trust: ProjectTrust) {
    REPO_TRUST.get_or_init(|| trust);
}

/// The trust set by `--trust-repo-config`, untrusted by default.
fn repo_trust() -> ProjectTrust {
    REPO_TRUST.get().copied().unwrap_or_default()
}

/// Load the config: the explicit `--config` file (trusted, chosen by the
/// user), or the global config merged with the repo's `slopguard.toml`.
/// Reserved keys dropped from an untrusted repo file are reported on stderr.
pub(crate) fn resolve_config(config_path: Option<&Path>) -> Result<Config, AppError> {
    match config_path {
        Some(path) => Ok(load_config_file(path)?),
        None => {
            let cwd = env::current_dir().map_err(|e| {
                AppError::Config(ConfigError::Io {
                    path: ".".to_string(),
                    source: e,
                })
            })?;
            let loaded = load_config(&cwd, repo_trust())?;
            for warning in &loaded.warnings {
                // CLI diagnostic to stderr, not application logging.
                // slopguard-disable-next-line no-println-in-prod
                eprintln!("warning: {warning}");
            }
            Ok(loaded.config)
        }
    }
}
