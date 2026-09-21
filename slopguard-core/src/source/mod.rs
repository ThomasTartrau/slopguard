//! External rule sources: git repositories cloned into a local cache, plus
//! extra local directories. Each configured `[[rules.sources]]` is resolved to
//! a directory of rule YAML and the provenance stamped on the rules loaded
//! from it.
//!
//! Git auth is delegated to the machine's own git (ssh-agent, credential
//! helper, `~/.gitconfig`). `SLOPGUARD_GIT_TOKEN` overrides that for https URLs
//! by injecting the token into the transient `git fetch <url>` argument only,
//! never into the persisted remote, so no token is written to disk.

use std::fs::create_dir_all;
use std::io::Error as IoError;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::RuleSource;

/// Environment variable holding an https token that overrides git's own
/// credential resolution. Empty means "unset".
const GIT_TOKEN_ENV: &str = "SLOPGUARD_GIT_TOKEN";

const HTTPS_PREFIX: &str = "https://";

/// Where a rule came from, tracked so `slopguard list` can show provenance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RuleOrigin {
    /// Embedded in the binary.
    #[default]
    Builtin,
    /// A git source, identified by its clone URL.
    Git { url: String },
    /// A local directory (`rules.custom_dirs` or a local `[[rules.sources]]`).
    Local { path: PathBuf },
}

impl RuleOrigin {
    /// The `source` string shown by `slopguard list`: `"builtin"`, the git URL,
    /// or the local path.
    pub fn label(&self) -> String {
        match self {
            RuleOrigin::Builtin => "builtin".to_string(),
            RuleOrigin::Git { url } => url.clone(),
            RuleOrigin::Local { path } => path.display().to_string(),
        }
    }
}

/// A source resolved to a directory on disk plus the provenance of its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    /// Directory to load rule YAML from.
    pub dir: PathBuf,
    /// Provenance to stamp on every rule loaded from `dir`.
    pub origin: RuleOrigin,
}

/// How git sources are cached and whether the network may be used.
#[derive(Debug, Clone)]
pub struct SourceOptions {
    /// Base directory holding one sub-directory per cached git source.
    pub cache_root: PathBuf,
    /// Never touch the network: reuse the cache, and fail if it is missing.
    pub offline: bool,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            cache_root: default_cache_root(),
            offline: false,
        }
    }
}

/// Environment override for the git source cache root, taking precedence over
/// the default user cache location. Useful in CI and tests.
const CACHE_ENV: &str = "SLOPGUARD_SOURCES_CACHE";

/// Default cache location for git sources: `$SLOPGUARD_SOURCES_CACHE` when set,
/// otherwise `<user cache>/slopguard/sources`.
pub fn default_cache_root() -> PathBuf {
    if let Ok(dir) = std::env::var(CACHE_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("slopguard")
        .join("sources")
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("failed to run git (is it installed and on PATH?): {source}")]
    Spawn {
        #[source]
        source: IoError,
    },

    #[error("git {args} failed for source '{url}': {stderr}")]
    Git {
        url: String,
        args: String,
        stderr: String,
    },

    #[error("offline: no cached clone for git source '{url}' (expected at '{path}')")]
    OfflineNoCache { url: String, path: String },

    #[error("failed to prepare cache directory '{path}': {source}")]
    Cache {
        path: String,
        #[source]
        source: IoError,
    },

    #[error("local rule source '{path}' does not exist or is not a directory")]
    LocalMissing { path: String },
}

/// The cache sub-directory for a git source, keyed by a hash of its URL and
/// ref so two refs of the same repository never share a checkout.
fn cache_dir_for(root: &Path, url: &str, git_ref: Option<&str>) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    hasher.update([0u8]);
    if let Some(git_ref) = git_ref {
        hasher.update(git_ref.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    root.join(hex)
}

/// The URL passed to a transient `git fetch`. When `SLOPGUARD_GIT_TOKEN` is set
/// and the URL is https, the token is injected as basic auth; otherwise the URL
/// is returned unchanged and git resolves credentials itself.
fn fetch_url(url: &str) -> String {
    match std::env::var(GIT_TOKEN_ENV) {
        Ok(token) if !token.is_empty() && url.starts_with(HTTPS_PREFIX) => {
            format!(
                "{HTTPS_PREFIX}oauth2:{token}@{}",
                &url[HTTPS_PREFIX.len()..]
            )
        }
        _ => url.to_string(),
    }
}

fn run_git(dir: &Path, args: &[&str]) -> Result<Output, SourceError> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|source| SourceError::Spawn { source })
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

/// Shallow-fetch `git_ref` from `url` into an existing repo at `dir` and check
/// it out detached. The token (if any) lives only in this fetch argument, never
/// in the repo's persisted remote.
fn fetch_and_checkout(dir: &Path, url: &str, git_ref: Option<&str>) -> Result<(), SourceError> {
    let refspec = git_ref.unwrap_or("HEAD");
    let tokened = fetch_url(url);
    let fetch = run_git(dir, &["fetch", "--depth", "1", &tokened, refspec])?;
    if !fetch.status.success() {
        return Err(SourceError::Git {
            url: url.to_string(),
            args: format!("fetch {refspec}"),
            stderr: stderr_of(&fetch),
        });
    }
    let checkout = run_git(
        dir,
        &[
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "--force",
            "FETCH_HEAD",
        ],
    )?;
    if !checkout.status.success() {
        return Err(SourceError::Git {
            url: url.to_string(),
            args: "checkout FETCH_HEAD".to_string(),
            stderr: stderr_of(&checkout),
        });
    }
    Ok(())
}

/// Ensure a git source is present in the cache and checked out at `git_ref`,
/// returning the repository directory.
///
/// A missing cache is cloned (unless offline). An existing cache is refreshed
/// best-effort when online: a failed refresh keeps the cached checkout, so a
/// scan does not break when the remote is unreachable.
fn ensure_git_source(
    url: &str,
    git_ref: Option<&str>,
    cache_root: &Path,
    offline: bool,
) -> Result<PathBuf, SourceError> {
    let dir = cache_dir_for(cache_root, url, git_ref);
    let is_repo = dir.join(".git").is_dir();

    if !is_repo {
        if offline {
            return Err(SourceError::OfflineNoCache {
                url: url.to_string(),
                path: dir.display().to_string(),
            });
        }
        create_dir_all(&dir).map_err(|source| SourceError::Cache {
            path: dir.display().to_string(),
            source,
        })?;
        let init = run_git(&dir, &["init", "--quiet"])?;
        if !init.status.success() {
            return Err(SourceError::Git {
                url: url.to_string(),
                args: "init".to_string(),
                stderr: stderr_of(&init),
            });
        }
        fetch_and_checkout(&dir, url, git_ref)?;
    } else if !offline {
        // Refresh best-effort: a moving branch is picked up, but an unreachable
        // remote falls back to the existing checkout, so a scan does not break.
        // slopguard-disable-next-line no-ignored-result
        let _ = fetch_and_checkout(&dir, url, git_ref);
    }

    Ok(dir)
}

/// Resolve every configured source to a directory and its provenance.
///
/// Sources are validated at config load, so each entry has a `git` URL or a
/// local `path`. Git sources are cloned/refreshed under `opts.cache_root`;
/// local sources must already exist.
pub fn resolve_sources(
    sources: &[RuleSource],
    opts: &SourceOptions,
) -> Result<Vec<ResolvedSource>, SourceError> {
    let mut resolved = Vec::with_capacity(sources.len());
    for source in sources {
        if let Some(url) = &source.git {
            let repo = ensure_git_source(
                url,
                source.git_ref.as_deref(),
                &opts.cache_root,
                opts.offline,
            )?;
            let dir = match &source.path {
                Some(sub) => repo.join(sub),
                None => repo,
            };
            resolved.push(ResolvedSource {
                dir,
                origin: RuleOrigin::Git { url: url.clone() },
            });
        } else if let Some(path) = &source.path {
            if !path.is_dir() {
                return Err(SourceError::LocalMissing {
                    path: path.display().to_string(),
                });
            }
            resolved.push(ResolvedSource {
                dir: path.clone(),
                origin: RuleOrigin::Local { path: path.clone() },
            });
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests;
