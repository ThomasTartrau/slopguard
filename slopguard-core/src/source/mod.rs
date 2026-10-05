//! External rule sources: git repositories cloned into a local cache, plus
//! extra local directories. Each configured `[[rules.sources]]` is resolved to
//! a directory of rule YAML and the provenance stamped on the rules loaded
//! from it.
//!
//! External sources are untrusted input, so every git call is hardened:
//!
//! - A URL or ref starting with `-` is rejected before git runs (git would
//!   parse it as an option such as `--upload-pack=...`), and the fetch passes
//!   `--` before its positional arguments.
//! - `GIT_ALLOW_PROTOCOL` restricts git to `https` and `ssh` (no `file://`,
//!   `ext::` or other transports). `SLOPGUARD_GIT_ALLOW_PROTOCOL` overrides the
//!   list; it exists for tests and CI that serve rules from `file://` remotes.
//! - A ref that is not a full 40-character commit sha is floating: the rules
//!   it loads can change under the user, so the CLI warns about it
//!   ([`unpinned_source_warnings`]). A pinned sha already checked out in the
//!   cache is reused without touching the network.
//! - Refreshing an existing cache when online must succeed: a failed fetch
//!   fails the resolution instead of silently scanning with stale rules.
//!
//! Git auth is delegated to the machine's own git (ssh-agent, credential
//! helper, `~/.gitconfig`). `SLOPGUARD_GIT_TOKEN` overrides that for https URLs
//! of a single trusted host (`SLOPGUARD_GIT_TOKEN_HOST`, else `[git]
//! token_host` in the user config): the token is injected into the transient
//! `git fetch <url>` argument only, never into the persisted remote, so no
//! token is written to disk. Without a configured host, no token is injected.

use std::env;
use std::fmt;
use std::fs::create_dir_all;
use std::io::Error as IoError;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::RuleSource;
use crate::sanitize::sanitize_control;

/// Environment variable holding an https token that overrides git's own
/// credential resolution. Empty means "unset".
const GIT_TOKEN_ENV: &str = "SLOPGUARD_GIT_TOKEN";

/// Environment variable naming the only host the token may be sent to. Takes
/// precedence over `[git] token_host`. Empty means "unset".
const GIT_TOKEN_HOST_ENV: &str = "SLOPGUARD_GIT_TOKEN_HOST";

/// Environment override of the protocols git may use for sources, in
/// `GIT_ALLOW_PROTOCOL` syntax (colon-separated). Meant for tests and CI that
/// serve rules from `file://` remotes. Empty means "unset".
const ALLOW_PROTOCOL_ENV: &str = "SLOPGUARD_GIT_ALLOW_PROTOCOL";

/// Protocols git may use to fetch a source unless overridden.
pub const DEFAULT_ALLOWED_PROTOCOLS: &str = "https:ssh";

const HTTPS_PREFIX: &str = "https://";

/// Replacement for secrets in error text.
const REDACTED: &str = "<redacted>";

/// An https token together with the single host it may be sent to.
#[derive(Clone, PartialEq, Eq)]
pub struct GitToken {
    /// The secret, injected as `oauth2:<token>@` basic auth.
    pub token: String,
    /// The only host (port excluded, compared case-insensitively) that may
    /// receive the token.
    pub host: String,
}

impl fmt::Debug for GitToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret never appears in debug output.
        f.debug_struct("GitToken")
            .field("token", &REDACTED)
            .field("host", &self.host)
            .finish()
    }
}

/// Read the git token from `SLOPGUARD_GIT_TOKEN`, bound to the host named by
/// `SLOPGUARD_GIT_TOKEN_HOST`, else `config_host` (`[git] token_host`).
///
/// Returns `None` when the token or the host is missing: a token is never sent
/// to a host the user did not name.
pub fn git_token_from_env(config_host: Option<&str>) -> Option<GitToken> {
    let token = non_empty_env(GIT_TOKEN_ENV)?;
    let config_host = config_host.filter(|h| !h.is_empty()).map(str::to_string);
    let host = non_empty_env(GIT_TOKEN_HOST_ENV).or(config_host)?;
    Some(GitToken { token, host })
}

/// The protocols git may use for sources: `$SLOPGUARD_GIT_ALLOW_PROTOCOL` when
/// set, otherwise [`DEFAULT_ALLOWED_PROTOCOLS`].
pub fn default_allowed_protocols() -> String {
    non_empty_env(ALLOW_PROTOCOL_ENV).unwrap_or_else(|| DEFAULT_ALLOWED_PROTOCOLS.to_string())
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

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
            RuleOrigin::Git { url } => sanitize_control(url).into_owned(),
            RuleOrigin::Local { path } => {
                sanitize_control(&path.display().to_string()).into_owned()
            }
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

/// How git sources are cached, fetched and authenticated.
#[derive(Debug, Clone)]
pub struct SourceOptions {
    /// Base directory holding one sub-directory per cached git source.
    pub cache_root: PathBuf,
    /// Never touch the network: reuse the cache, and fail if it is missing.
    pub offline: bool,
    /// Token injected into https fetches of its host only.
    pub git_token: Option<GitToken>,
    /// `GIT_ALLOW_PROTOCOL` value set on every git call (colon-separated).
    pub allowed_protocols: String,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            cache_root: default_cache_root(),
            offline: false,
            git_token: git_token_from_env(None),
            allowed_protocols: default_allowed_protocols(),
        }
    }
}

/// Environment override for the git source cache root, taking precedence over
/// the default user cache location. Useful in CI and tests.
const CACHE_ENV: &str = "SLOPGUARD_SOURCES_CACHE";

/// Default cache location for git sources: `$SLOPGUARD_SOURCES_CACHE` when set,
/// otherwise `<user cache>/slopguard/sources`.
pub fn default_cache_root() -> PathBuf {
    if let Ok(dir) = env::var(CACHE_ENV) {
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

    #[error("git source {what} '{value}' must not start with '-'")]
    InvalidArgument { what: &'static str, value: String },
}

/// Whether `git_ref` is a full 40-character hex commit sha, i.e. a pinned ref
/// whose content cannot change.
pub fn is_pinned_sha(git_ref: &str) -> bool {
    git_ref.len() == 40 && git_ref.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One warning per git source whose ref is missing or is not a pinned commit
/// sha. The URL is printed without its userinfo, so no credential leaks.
pub fn unpinned_source_warnings(sources: &[RuleSource]) -> Vec<String> {
    sources
        .iter()
        .filter_map(|source| {
            let url = source.git.as_deref()?;
            let reason = match source.git_ref.as_deref() {
                Some(git_ref) if is_pinned_sha(git_ref) => return None,
                Some(git_ref) => format!(
                    "ref '{}' is not a 40-character commit sha",
                    sanitize_control(git_ref)
                ),
                None => "no ref set, the default branch is used".to_string(),
            };
            Some(format!(
                "unpinned rule source '{}': {reason}; pin it to a commit sha so its rules cannot change unnoticed",
                sanitize_control(&without_userinfo(url))
            ))
        })
        .collect()
}

/// The authority of a `scheme://authority/path` URL, or `None` without `://`.
fn url_authority(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    Some(rest.split('/').next().unwrap_or(rest))
}

/// The host of a URL: the authority after its last `@` (userinfo is never the
/// host), without `:port`. `https://trusted.com@evil.com/x` yields `evil.com`.
fn url_host(url: &str) -> Option<&str> {
    let authority = url_authority(url)?;
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    Some(host_port.split(':').next().unwrap_or(host_port))
}

/// `url` with any userinfo replaced by a placeholder, for messages.
fn without_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once('@') {
        Some((_, host)) => {
            let path = &rest[authority.len()..];
            format!("{scheme}://{REDACTED}@{host}{path}")
        }
        None => url.to_string(),
    }
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

/// The URL passed to a transient `git fetch`. The token is injected as basic
/// auth only for an https URL without userinfo whose host is the token's host;
/// otherwise the URL is returned unchanged and git resolves credentials itself.
fn fetch_url(url: &str, token: Option<&GitToken>) -> String {
    let (Some(token), Some(rest)) = (token, url.strip_prefix(HTTPS_PREFIX)) else {
        return url.to_string();
    };
    let has_userinfo = url_authority(url).is_some_and(|authority| authority.contains('@'));
    let trusted = url_host(url).is_some_and(|host| host.eq_ignore_ascii_case(&token.host));
    if has_userinfo || !trusted {
        return url.to_string();
    }
    format!("{HTTPS_PREFIX}oauth2:{}@{rest}", token.token)
}

/// Reject a URL or ref that git would parse as an option (`--upload-pack=...`).
fn validate_git_arg(what: &'static str, value: &str) -> Result<(), SourceError> {
    if value.starts_with('-') {
        return Err(SourceError::InvalidArgument {
            what,
            value: sanitize_control(value).into_owned(),
        });
    }
    Ok(())
}

/// Run git in `dir`, restricted to the `allowed_protocols` transports.
fn run_git(dir: &Path, args: &[&str], allowed_protocols: &str) -> Result<Output, SourceError> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_ALLOW_PROTOCOL", allowed_protocols)
        .output()
        .map_err(|source| SourceError::Spawn { source })
}

fn raw_stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

/// The trimmed stderr of a git call with control characters neutralized.
fn stderr_of(output: &Output) -> String {
    sanitize_control(&raw_stderr_of(output)).into_owned()
}

/// Shallow-fetch `git_ref` from `url` into an existing repo at `dir` and check
/// it out detached. The token (if any) lives only in this fetch argument, never
/// in the repo's persisted remote, and is redacted from the error text.
fn fetch_and_checkout(
    dir: &Path,
    url: &str,
    git_ref: Option<&str>,
    opts: &SourceOptions,
) -> Result<(), SourceError> {
    let refspec = git_ref.unwrap_or("HEAD");
    validate_git_arg("url", url)?;
    validate_git_arg("ref", refspec)?;
    let token = opts.git_token.as_ref();
    let tokened = fetch_url(url, token);
    let fetch = run_git(
        dir,
        &["fetch", "--depth", "1", "--", &tokened, refspec],
        &opts.allowed_protocols,
    )?;
    if !fetch.status.success() {
        let mut stderr = raw_stderr_of(&fetch);
        if let Some(token) = token {
            stderr = stderr.replace(&token.token, REDACTED);
        }
        return Err(SourceError::Git {
            url: sanitize_control(url).into_owned(),
            args: format!("fetch {}", sanitize_control(refspec)),
            stderr: sanitize_control(&stderr).into_owned(),
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
        &opts.allowed_protocols,
    )?;
    if !checkout.status.success() {
        return Err(SourceError::Git {
            url: sanitize_control(url).into_owned(),
            args: "checkout FETCH_HEAD".to_string(),
            stderr: stderr_of(&checkout),
        });
    }
    Ok(())
}

/// Whether the cached repo at `dir` already has the pinned `sha` checked out.
fn is_checked_out(dir: &Path, sha: &str, allowed_protocols: &str) -> bool {
    let Ok(output) = run_git(dir, &["rev-parse", "HEAD"], allowed_protocols) else {
        return false;
    };
    let head = String::from_utf8_lossy(&output.stdout);
    output.status.success() && head.trim().eq_ignore_ascii_case(sha)
}

/// Ensure a git source is present in the cache and checked out at `git_ref`,
/// returning the repository directory.
///
/// The URL and ref are validated before any git process runs. A missing cache
/// is cloned (unless offline). An existing cache is refreshed when online, and
/// a failed refresh is an error: scanning with stale rules would hide that the
/// source can no longer be verified. A pinned sha already checked out is
/// reused as is, without touching the network.
fn ensure_git_source(
    url: &str,
    git_ref: Option<&str>,
    opts: &SourceOptions,
) -> Result<PathBuf, SourceError> {
    validate_git_arg("url", url)?;
    if let Some(git_ref) = git_ref {
        validate_git_arg("ref", git_ref)?;
    }
    let dir = cache_dir_for(&opts.cache_root, url, git_ref);
    let is_repo = dir.join(".git").is_dir();

    if !is_repo {
        if opts.offline {
            return Err(SourceError::OfflineNoCache {
                url: sanitize_control(url).into_owned(),
                path: sanitize_control(&dir.display().to_string()).into_owned(),
            });
        }
        create_dir_all(&dir).map_err(|source| SourceError::Cache {
            path: dir.display().to_string(),
            source,
        })?;
        let init = run_git(&dir, &["init", "--quiet"], &opts.allowed_protocols)?;
        if !init.status.success() {
            return Err(SourceError::Git {
                url: sanitize_control(url).into_owned(),
                args: "init".to_string(),
                stderr: stderr_of(&init),
            });
        }
        fetch_and_checkout(&dir, url, git_ref, opts)?;
    } else if !opts.offline {
        let pinned_present = git_ref.is_some_and(|sha| {
            is_pinned_sha(sha) && is_checked_out(&dir, sha, &opts.allowed_protocols)
        });
        if !pinned_present {
            fetch_and_checkout(&dir, url, git_ref, opts)?;
        }
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
            let repo = ensure_git_source(url, source.git_ref.as_deref(), opts)?;
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
                    path: sanitize_control(&path.display().to_string()).into_owned(),
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
