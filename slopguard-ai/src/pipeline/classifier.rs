//! The System One (Jev / TypeSafe) classification pass.
//!
//! On a separate axis from the generative LLM: instead of asking an LLM to
//! confirm each candidate in free text, a [`DecisionProvider`] answers a typed
//! `noul` (yes/no) question `is_issue` with a calibrated probability. The raw
//! probability is cached; the threshold is applied in-process, after the cache,
//! so retuning it does not invalidate cached decisions.
//!
//! Hybrid reason: a `static` rule uses its own note; a `generated` rule
//! escalates to the generative LLM to write a per-instance reason. When the
//! classifier fires a `generated` rule but no LLM provider is available, it
//! falls back to the static note with a warning.
//!
//! Enabled by the `provider-typesafe` feature.

use std::collections::BTreeMap;

use ironflow_core::decision::{DecisionProvider, DecisionQuestion, DecisionRequest, NoulCriteria};
use ironflow_core::provider::AgentProvider;
use ironflow_core::providers::http::typesafe::{
    DEFAULT_MODEL as JEV_DEFAULT_MODEL, OPENROUTER_MODEL,
};
use ironflow_core::providers::http::TypeSafeProvider;
use serde_json::json;
use slopguard_core::config::{ClassifierConfig, ClassifierTransport};
use slopguard_core::finding::Finding;
use slopguard_core::rule::ReasonMode;
use thiserror::Error;

use crate::cache::{cache_key, AiCache};
use crate::provider::non_empty_env;

use super::context::{extract_context, CONTEXT_RADIUS};
use super::prompt::render_prompt;
use super::{call_llm, run_bounded, AiCandidate};

/// The name of the noul question asked for every candidate.
pub(crate) const QUESTION: &str = "is_issue";

/// What replaces `{{code}}` in the noul instructions: the code itself travels
/// as the request `state`, not inline in the instructions.
const CODE_PLACEHOLDER: &str = "the code under review (provided as the state)";

/// Environment variable holding the direct TypeSafe API key.
pub const TYPESAFE_API_KEY_ENV: &str = "TYPESAFE_API_KEY";

/// Environment variable holding the OpenRouter API key.
pub const OPENROUTER_API_KEY_ENV: &str = "OPENROUTER_API_KEY";

/// Why the classifier could not be built. Non-fatal at the call site: the scan
/// continues without classification, emitting a single warning that names the
/// missing credential (mirroring [`crate::provider::ProviderError`]).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClassifierError {
    /// `[ai.classifier].enabled` is `false`.
    #[error("classifier is disabled ([ai.classifier].enabled = false)")]
    Disabled,

    /// No API key was found for the selected transport.
    #[error(
        "no API key: set the {env} environment variable ([ai.classifier].transport = \"{transport}\")"
    )]
    MissingApiKey {
        /// The environment variable that was checked.
        env: &'static str,
        /// The transport that was configured.
        transport: ClassifierTransport,
    },
}

/// Build a boxed [`DecisionProvider`] from `[ai.classifier]` config.
///
/// # Errors
///
/// Returns [`ClassifierError::Disabled`] when the classifier is off, or
/// [`ClassifierError::MissingApiKey`] when the transport's key env var is unset
/// or empty.
pub fn build_classifier(
    cfg: &ClassifierConfig,
) -> Result<Box<dyn DecisionProvider>, ClassifierError> {
    if !cfg.enabled {
        return Err(ClassifierError::Disabled);
    }
    let transport = cfg.transport;
    let env = match transport {
        ClassifierTransport::Direct => TYPESAFE_API_KEY_ENV,
        ClassifierTransport::Openrouter => OPENROUTER_API_KEY_ENV,
    };
    let key = non_empty_env(env).ok_or(ClassifierError::MissingApiKey { env, transport })?;
    Ok(Box::new(match transport {
        ClassifierTransport::Direct => TypeSafeProvider::new(key),
        ClassifierTransport::Openrouter => TypeSafeProvider::openrouter(key),
    }))
}

/// The Jev model route a config selects: the explicit `model`, else the
/// transport's default slug (`jev-latest` direct, `typesafe/jev-1.13` on
/// OpenRouter, which rejects the `jev-latest` alias).
pub fn resolve_jev_model(cfg: &ClassifierConfig) -> String {
    cfg.model.clone().unwrap_or_else(|| {
        match cfg.transport {
            ClassifierTransport::Direct => JEV_DEFAULT_MODEL,
            ClassifierTransport::Openrouter => OPENROUTER_MODEL,
        }
        .to_string()
    })
}

/// Build the decision request for one candidate: the code as `state`, and a
/// single noul question with the rule's calibration criteria.
fn build_request(
    code: &str,
    candidate: &AiCandidate,
    instructions: String,
    jev_model: &str,
) -> DecisionRequest {
    let criteria = NoulCriteria {
        if_true: candidate.if_true.clone(),
        if_false: candidate.if_false.clone(),
    };
    let mut questions = BTreeMap::new();
    questions.insert(
        QUESTION.to_string(),
        DecisionQuestion::Noul {
            instructions: json!(instructions),
            criteria,
        },
    );
    DecisionRequest {
        state: json!(code),
        model: jev_model.into(),
        questions,
    }
}

/// Ask the LLM to write a per-instance reason for a `generated` rule. `None`
/// when no LLM is available or the call fails, so the caller can fall back.
async fn generate_reason(
    llm: Option<&dyn AgentProvider>,
    candidate: &AiCandidate,
    code: &str,
    filename: &str,
) -> Option<String> {
    let llm = llm?;
    let prompt = render_prompt(
        &candidate.prompt_template,
        code,
        filename,
        &candidate.rule_context,
    );
    let verdict = call_llm(llm, &candidate.model, &prompt).await?;
    Some(verdict.reason)
}

/// Classify a single candidate: consult the cache, else call Jev; apply the
/// threshold; and, on a fire, attach the reason (static note or LLM-generated).
async fn classify_one(
    decider: &dyn DecisionProvider,
    llm: Option<&dyn AgentProvider>,
    candidate: &AiCandidate,
    jev_model: &str,
    global_threshold: f64,
    cache: Option<&AiCache>,
) -> Option<Finding> {
    let filename = candidate.finding.file.display().to_string();
    let code = extract_context(
        &candidate.file_content,
        candidate.finding.line,
        CONTEXT_RADIUS,
    );
    // The noul instructions: the rule prompt with the code left out, since the
    // code is carried by the request `state`.
    let instructions = render_prompt(
        &candidate.prompt_template,
        CODE_PLACEHOLDER,
        &filename,
        &candidate.rule_context,
    );
    let key = cache_key(&[
        &candidate.file_content,
        candidate.finding.rule_id.as_str(),
        &instructions,
        jev_model,
    ]);

    let probability = match cache.and_then(|c| c.get_probability(&key)) {
        Some(p) => p,
        None => {
            let request = build_request(&code, candidate, instructions, jev_model);
            let output = decider.decide(&request).await.ok()?;
            let p = output.noul(QUESTION).ok()?;
            if let Some(cache) = cache {
                // A cache write failure must not drop the finding.
                // slopguard-disable-next-line no-ignored-result
                let _ = cache.put_probability(&key, p);
            }
            p
        }
    };

    // Threshold applied after the cache read, so retuning it does not force a
    // new call: the raw probability is what is cached.
    let threshold = candidate.threshold.unwrap_or(global_threshold);
    if probability < threshold {
        return None;
    }

    let mut finding = candidate.finding.clone();
    finding.confidence = Some(probability);
    let note = match candidate.reason_mode {
        ReasonMode::Static => candidate.rule_context.clone(),
        ReasonMode::Generated => match generate_reason(llm, candidate, &code, &filename).await {
            Some(reason) => reason,
            None => {
                // CLI diagnostic to stderr, not application logging.
                // slopguard-disable-next-line no-println-in-prod
                eprintln!(
                    "warning: rule '{}' requires a generated reason but no LLM provider is available; using the static note",
                    finding.rule_id
                );
                candidate.rule_context.clone()
            }
        },
    };
    finding.note = Some(note);
    Some(finding)
}

/// Run the classification pass over `candidates`, bounded to `concurrency`
/// simultaneous decisions. Returns only findings whose probability meets the
/// threshold. Blocks the calling thread on a private multi-thread runtime, like
/// [`run_ai_pass`](super::run_ai_pass).
pub fn run_classifier_pass(
    decider: &dyn DecisionProvider,
    llm: Option<&dyn AgentProvider>,
    candidates: Vec<AiCandidate>,
    jev_model: &str,
    global_threshold: f64,
    concurrency: usize,
    cache: Option<&AiCache>,
) -> Vec<Finding> {
    run_bounded(&candidates, concurrency, |candidate| {
        classify_one(decider, llm, candidate, jev_model, global_threshold, cache)
    })
}

#[cfg(test)]
#[path = "classifier_tests.rs"]
mod tests;
