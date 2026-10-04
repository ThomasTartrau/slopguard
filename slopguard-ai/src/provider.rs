//! Build an [`AgentProvider`] from slopguard's `[ai]` configuration.
//!
//! Two transports are supported, matching `[ai].provider`:
//! - `api`: direct HTTP calls via `ironflow-core`'s `AnthropicApiProvider` or
//!   `OpenAiProvider` (selected by `[ai].vendor`).
//! - `cli`: the local `claude` binary via `ClaudeCodeProvider`.

use std::env;
use std::path::Path;

use ironflow_core::provider::AgentProvider;
use ironflow_core::providers::claude::ClaudeCodeProvider;
use ironflow_core::providers::http::{AnthropicApiProvider, OpenAiProvider};
#[cfg(test)]
use slopguard_core::config::ClassifierConfig;
use slopguard_core::config::{AiConfig, AiTransport, AiVendor};
use thiserror::Error;

/// The environment variable holding the OAuth token for the `cli` transport.
const OAUTH_TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// Why an AI provider could not be built. All variants are non-fatal at the
/// call site: the scan continues without AI, emitting a single clear warning
/// that names the missing credential.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    /// `[ai].enabled` is `false`.
    #[error("AI is disabled ([ai].enabled = false)")]
    Disabled,

    /// No API key was found for the `api` transport.
    #[error("no API key: set [ai].api_key or the {env} environment variable")]
    MissingApiKey {
        /// The environment variable that was checked.
        env: &'static str,
    },

    /// The `claude` binary is not on `PATH` for the `cli` transport.
    #[error("claude CLI not found on PATH (required for [ai].provider = \"cli\")")]
    ClaudeNotFound,

    /// No OAuth token was found for the `cli` transport.
    #[error("no OAuth token: set the {env} environment variable ([ai].provider = \"cli\")", env = OAUTH_TOKEN_ENV)]
    MissingOauthToken,
}

/// The concrete provider that [`build_provider`] would construct. Exposed so
/// selection logic can be unit-tested without network access or real keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Local `claude` CLI.
    ClaudeCli,
    /// Anthropic Messages API over HTTP.
    AnthropicApi,
    /// OpenAI Chat Completions API over HTTP.
    OpenAiApi,
}

/// The environment variable holding the API key for a vendor.
fn vendor_env(vendor: &AiVendor) -> &'static str {
    match vendor {
        AiVendor::Anthropic => "ANTHROPIC_API_KEY",
        AiVendor::OpenAI => "OPENAI_API_KEY",
    }
}

/// Read `name` from the process environment, treating unset and empty the
/// same: an empty credential is a common misconfiguration, not a value.
pub(crate) fn non_empty_env(name: &str) -> Option<String> {
    // env::var().ok() is idiomatic: an unset var is a valid absence, not an
    // error to propagate.
    // slopguard-disable-next-line no-ok-chain
    env::var(name).ok().filter(|s| !s.is_empty())
}

/// Resolve the API key from config first, then the vendor's env var. Empty
/// strings are rejected in both places (a common misconfiguration).
fn resolve_api_key(ai: &AiConfig) -> Result<String, ProviderError> {
    let env = vendor_env(&ai.vendor);
    if let Some(key) = ai.api_key.as_deref().filter(|s| !s.is_empty()) {
        return Ok(key.to_string());
    }
    non_empty_env(env).ok_or(ProviderError::MissingApiKey { env })
}

/// Whether an executable file named `name` exists in any `PATH` directory.
fn binary_in_path(name: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&paths).any(|dir| Path::new(&dir).join(name).is_file())
}

/// Credential prerequisites read from the process environment.
///
/// Passed explicitly to [`resolve_kind`] so provider selection is unit-testable
/// without mutating real environment variables (which is racy under parallel
/// tests).
struct Prereqs {
    /// The vendor API key found in the environment, if non-empty.
    api_key_env: Option<String>,
    /// Whether the `claude` binary is on `PATH`.
    claude_in_path: bool,
    /// The `CLAUDE_CODE_OAUTH_TOKEN` value, if non-empty.
    oauth_token: Option<String>,
}

/// Read the credential prerequisites for `ai` from the process environment.
fn read_prereqs(ai: &AiConfig) -> Prereqs {
    Prereqs {
        api_key_env: non_empty_env(vendor_env(&ai.vendor)),
        claude_in_path: binary_in_path("claude"),
        oauth_token: non_empty_env(OAUTH_TOKEN_ENV),
    }
}

/// Decide which provider a config selects, validating prerequisites against the
/// supplied [`Prereqs`] without touching the real environment or constructing
/// anything. This is the pure core of [`provider_kind`].
fn resolve_kind(ai: &AiConfig, prereqs: &Prereqs) -> Result<ProviderKind, ProviderError> {
    if !ai.enabled {
        return Err(ProviderError::Disabled);
    }
    match ai.provider {
        AiTransport::Cli => {
            if !prereqs.claude_in_path {
                return Err(ProviderError::ClaudeNotFound);
            }
            if prereqs.oauth_token.is_none() {
                return Err(ProviderError::MissingOauthToken);
            }
            Ok(ProviderKind::ClaudeCli)
        }
        AiTransport::Api => {
            let has_key =
                ai.api_key.as_ref().is_some_and(|s| !s.is_empty()) || prereqs.api_key_env.is_some();
            if !has_key {
                return Err(ProviderError::MissingApiKey {
                    env: vendor_env(&ai.vendor),
                });
            }
            Ok(match ai.vendor {
                AiVendor::Anthropic => ProviderKind::AnthropicApi,
                AiVendor::OpenAI => ProviderKind::OpenAiApi,
            })
        }
    }
}

/// Decide which provider a config selects, validating prerequisites (enabled,
/// API key for `api`, `claude` on PATH and an OAuth token for `cli`) against
/// the process environment, without constructing anything.
pub fn provider_kind(ai: &AiConfig) -> Result<ProviderKind, ProviderError> {
    resolve_kind(ai, &read_prereqs(ai))
}

/// Build a boxed [`AgentProvider`] from `[ai]` config.
///
/// `ai` must come from a trusted source (user config, `--config`, CLI flags):
/// it picks the endpoint and the credentials. The config loader drops `[ai]`
/// from an untrusted repo `slopguard.toml` for that reason.
///
/// # Errors
///
/// Returns [`ProviderError::Disabled`] when AI is off, or
/// [`ProviderError::MissingApiKey`] when the `api` transport has no key.
pub fn build_provider(ai: &AiConfig) -> Result<Box<dyn AgentProvider>, ProviderError> {
    match provider_kind(ai)? {
        ProviderKind::ClaudeCli => Ok(Box::new(ClaudeCodeProvider::new())),
        ProviderKind::AnthropicApi => {
            let key = resolve_api_key(ai)?;
            Ok(Box::new(AnthropicApiProvider::with_api_key(key)))
        }
        ProviderKind::OpenAiApi => {
            let key = resolve_api_key(ai)?;
            let base_url = non_empty_env("OPENAI_BASE_URL")
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
            Ok(Box::new(OpenAiProvider::with_credentials(key, base_url)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(provider: AiTransport, vendor: AiVendor, key: Option<&str>) -> AiConfig {
        AiConfig {
            enabled: true,
            provider,
            vendor,
            model: None,
            concurrency: 4,
            api_key: key.map(str::to_string),
            classifier: ClassifierConfig::default(),
            ..AiConfig::default()
        }
    }

    /// Prerequisites with everything satisfied: use as a base and clear one
    /// field to test a specific missing-credential path.
    fn all_present() -> Prereqs {
        Prereqs {
            api_key_env: Some("sk-env".to_string()),
            claude_in_path: true,
            oauth_token: Some("tok".to_string()),
        }
    }

    fn none_present() -> Prereqs {
        Prereqs {
            api_key_env: None,
            claude_in_path: false,
            oauth_token: None,
        }
    }

    #[test]
    fn cli_transport_selects_claude_cli_with_binary_and_token() {
        let ai = cfg(AiTransport::Cli, AiVendor::Anthropic, None);
        assert_eq!(
            resolve_kind(&ai, &all_present()).unwrap(),
            ProviderKind::ClaudeCli
        );
    }

    #[test]
    fn cli_transport_without_claude_binary_errors() {
        let ai = cfg(AiTransport::Cli, AiVendor::Anthropic, None);
        let prereqs = Prereqs {
            claude_in_path: false,
            ..all_present()
        };
        assert_eq!(
            resolve_kind(&ai, &prereqs).unwrap_err(),
            ProviderError::ClaudeNotFound
        );
    }

    #[test]
    fn cli_transport_without_oauth_token_errors() {
        // WHY: the issue requires a clear error when the cli provider is
        // configured but CLAUDE_CODE_OAUTH_TOKEN is missing.
        let ai = cfg(AiTransport::Cli, AiVendor::Anthropic, None);
        let prereqs = Prereqs {
            oauth_token: None,
            ..all_present()
        };
        assert_eq!(
            resolve_kind(&ai, &prereqs).unwrap_err(),
            ProviderError::MissingOauthToken
        );
    }

    #[test]
    fn api_anthropic_with_config_key() {
        let ai = cfg(AiTransport::Api, AiVendor::Anthropic, Some("sk-ant"));
        assert_eq!(
            resolve_kind(&ai, &none_present()).unwrap(),
            ProviderKind::AnthropicApi
        );
    }

    #[test]
    fn api_openai_with_config_key() {
        let ai = cfg(AiTransport::Api, AiVendor::OpenAI, Some("sk-oai"));
        assert_eq!(
            resolve_kind(&ai, &none_present()).unwrap(),
            ProviderKind::OpenAiApi
        );
    }

    #[test]
    fn api_anthropic_with_env_key_only() {
        let ai = cfg(AiTransport::Api, AiVendor::Anthropic, None);
        assert_eq!(
            resolve_kind(&ai, &all_present()).unwrap(),
            ProviderKind::AnthropicApi
        );
    }

    #[test]
    fn api_without_any_key_errors() {
        let ai = cfg(AiTransport::Api, AiVendor::Anthropic, None);
        assert_eq!(
            resolve_kind(&ai, &none_present()).unwrap_err(),
            ProviderError::MissingApiKey {
                env: "ANTHROPIC_API_KEY"
            }
        );
    }

    #[test]
    fn disabled_config_is_an_error() {
        let mut ai = cfg(AiTransport::Cli, AiVendor::Anthropic, None);
        ai.enabled = false;
        assert_eq!(
            resolve_kind(&ai, &all_present()).unwrap_err(),
            ProviderError::Disabled
        );
    }

    #[test]
    fn empty_config_key_falls_through_to_env() {
        // An empty string is a misconfiguration, not a valid key: with no env
        // key either, resolution must fail rather than use the empty string.
        let ai = cfg(AiTransport::Api, AiVendor::Anthropic, Some(""));
        assert_eq!(
            resolve_kind(&ai, &none_present()).unwrap_err(),
            ProviderError::MissingApiKey {
                env: "ANTHROPIC_API_KEY"
            }
        );
    }
}
