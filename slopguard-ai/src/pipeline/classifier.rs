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
use std::path::Path;
use std::sync::Arc;

use futures::future::join_all;
use ironflow_core::decision::{DecisionProvider, DecisionQuestion, DecisionRequest, NoulCriteria};
use ironflow_core::provider::AgentProvider;
use ironflow_core::providers::http::typesafe::{
    DEFAULT_MODEL as JEV_DEFAULT_MODEL, OPENROUTER_MODEL,
};
use ironflow_core::providers::http::TypeSafeProvider;
use serde_json::json;
use slopguard_core::config::{ClassifierConfig, ClassifierTransport, MAX_AI_CONCURRENCY};
use slopguard_core::finding::Finding;
use slopguard_core::rule::ReasonMode;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::sync::Semaphore;

use crate::cache::{cache_key, AiCache};
use crate::provider::non_empty_env;

use super::context::{extract_context, extract_numbered, CONTEXT_RADIUS};
use super::prompt::render_prompt;
use super::{call_llm, match_identity, AiCandidate};

/// What replaces `{{code}}` in the noul instructions: the code itself travels
/// as the request `state` (line-numbered), not inline in the instructions.
const CODE_PLACEHOLDER: &str =
    "the code under review (provided as the state, each line prefixed with its absolute line number)";

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

/// Batching configuration for [`run_classifier_pass`], mirrored from
/// `[ai.classifier]`.
pub struct BatchConfig {
    /// Whether overlapping cache-miss candidates are grouped into one request.
    pub batch: bool,
    /// Maximum number of nouls (candidates) in one batched request.
    pub max_questions: usize,
    /// Maximum number of source lines carried in one batched request `state`.
    pub max_state_lines: usize,
}

/// Resolved caps used while clustering: the context radius that decides window
/// overlap, plus the two size limits.
struct ClusterCaps {
    radius: usize,
    max_questions: usize,
    max_state_lines: usize,
}

/// A group of cache-miss candidates from one file whose context windows overlap,
/// answered by a single multi-noul request over the merged `[region_start,
/// region_end]` line range (1-based, inclusive).
struct Cluster<'a> {
    members: Vec<&'a AiCandidate>,
    region_start: usize,
    region_end: usize,
}

/// The noul instructions for one candidate: the rule prompt with the code left
/// out (it travels as the request `state`), plus the candidate's absolute line
/// so the model evaluates the right spot inside a shared region. Carrying the
/// line here also makes the cache key unique per candidate, so two matches of
/// the same rule in one file no longer collide.
fn cluster_instructions(candidate: &AiCandidate) -> String {
    let filename = candidate.finding.file.display().to_string();
    let base = render_prompt(
        &candidate.prompt_template,
        CODE_PLACEHOLDER,
        &filename,
        &candidate.rule_context,
    );
    format!(
        "{base}\n\nEvaluate only the code at line {}.",
        candidate.finding.line
    )
}

/// The per-candidate cache key: `[file_content, rule_id, instructions,
/// jev_model]` followed by the match identity (path and line/column span, see
/// [`match_identity`]), so two matches of one rule in one file never share a
/// cached probability, even on the same line.
fn candidate_key(candidate: &AiCandidate, jev_model: &str) -> String {
    let instructions = cluster_instructions(candidate);
    let mut parts = vec![
        candidate.file_content.as_str(),
        candidate.finding.rule_id.as_str(),
        instructions.as_str(),
        jev_model,
    ];
    let identity = match_identity(&candidate.finding);
    // The rule id is already part of the structure above.
    parts.extend(identity[1..].iter().map(String::as_str));
    cache_key(&parts)
}

/// The deterministic question key for the `index`th member of a cluster.
fn question_key(index: usize) -> String {
    format!("q{index}")
}

/// Start a cluster from a single candidate: its context window is the region.
fn new_cluster(candidate: &AiCandidate, radius: usize) -> Cluster<'_> {
    Cluster {
        region_start: candidate.finding.line.saturating_sub(radius).max(1),
        region_end: candidate.finding.line + radius,
        members: vec![candidate],
    }
}

/// Group cache-miss candidates into clusters: by file, sorted by line, merging
/// while the next candidate's `[line-R, line+R]` window overlaps the current
/// region and no cap is exceeded, otherwise starting a new cluster.
fn build_clusters<'a>(misses: &[&'a AiCandidate], caps: &ClusterCaps) -> Vec<Cluster<'a>> {
    let mut by_file: BTreeMap<&Path, Vec<&'a AiCandidate>> = BTreeMap::new();
    for &candidate in misses {
        by_file
            .entry(candidate.finding.file.as_path())
            .or_default()
            .push(candidate);
    }

    let mut clusters = Vec::new();
    for (_file, mut candidates) in by_file {
        candidates.sort_by_key(|candidate| candidate.finding.line);
        let mut iter = candidates.into_iter();
        let Some(first) = iter.next() else {
            continue;
        };
        let mut current = new_cluster(first, caps.radius);
        for candidate in iter {
            let window_start = candidate.finding.line.saturating_sub(caps.radius).max(1);
            let window_end = candidate.finding.line + caps.radius;
            let merged_start = current.region_start.min(window_start);
            let merged_end = current.region_end.max(window_end);
            // Sorted ascending, so the window can only extend downward: overlap
            // reduces to "does its start fall within the current region".
            let overlaps = window_start <= current.region_end;
            let over_questions = current.members.len() + 1 > caps.max_questions;
            let over_lines = merged_end - merged_start + 1 > caps.max_state_lines;
            if overlaps && !over_questions && !over_lines {
                current.region_start = merged_start;
                current.region_end = merged_end;
                current.members.push(candidate);
            } else {
                clusters.push(current);
                current = new_cluster(candidate, caps.radius);
            }
        }
        clusters.push(current);
    }
    clusters
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

/// Build a finding for a classified candidate, or `None` when its probability
/// is below the (per-rule or global) threshold. On a fire, the reason is the
/// static note or, for a `generated` rule, an LLM-written per-instance note.
///
/// The threshold is applied here, after the cache read, so retuning it never
/// forces a new call: the raw probability is what is cached.
async fn finding_for(
    candidate: &AiCandidate,
    probability: f64,
    llm: Option<&dyn AgentProvider>,
    global_threshold: f64,
) -> Option<Finding> {
    let threshold = candidate.threshold.unwrap_or(global_threshold);
    if probability < threshold {
        return None;
    }

    let mut finding = candidate.finding.clone();
    finding.confidence = Some(probability);
    let note = match candidate.reason_mode {
        ReasonMode::Static => candidate.rule_context.clone(),
        ReasonMode::Generated => {
            let filename = candidate.finding.file.display().to_string();
            let code = extract_context(
                &candidate.file_content,
                candidate.finding.line,
                CONTEXT_RADIUS,
            );
            match generate_reason(llm, candidate, &code, &filename).await {
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
            }
        }
    };
    finding.note = Some(note);
    Some(finding)
}

/// Classify one cluster with a single multi-noul request: the merged region as
/// line-numbered `state`, one `qN` noul per member. Remaps each answer to its
/// candidate, caches the raw probability, and applies the threshold per member.
///
/// A request error skips every member (no per-candidate fallback), and a
/// missing or mistyped answer skips just that member, matching the existing
/// silent-skip behavior.
async fn classify_cluster(
    decider: &dyn DecisionProvider,
    llm: Option<&dyn AgentProvider>,
    cluster: &Cluster<'_>,
    jev_model: &str,
    global_threshold: f64,
    cache: Option<&AiCache>,
) -> Vec<Finding> {
    // Members are grouped by file, so any member's content is the file's.
    let Some(first) = cluster.members.first() else {
        return Vec::new();
    };
    let state = extract_numbered(
        &first.file_content,
        cluster.region_start,
        cluster.region_end,
    );

    let mut questions = BTreeMap::new();
    for (index, candidate) in cluster.members.iter().enumerate() {
        let criteria = NoulCriteria {
            if_true: candidate.if_true.clone(),
            if_false: candidate.if_false.clone(),
        };
        questions.insert(
            question_key(index),
            DecisionQuestion::Noul {
                instructions: json!(cluster_instructions(candidate)),
                criteria,
            },
        );
    }
    let request = DecisionRequest {
        state: json!(state),
        model: jev_model.into(),
        questions,
    };
    let output = match decider.decide(&request).await {
        Ok(output) => output,
        // A cluster-level failure (network, rate limit) skips all its members.
        // slopguard-disable-next-line no-swallowed-error
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    for (index, candidate) in cluster.members.iter().enumerate() {
        let probability = match output.noul(&question_key(index)) {
            Ok(probability) => probability,
            // A missing/mistyped answer skips just that member.
            // slopguard-disable-next-line no-swallowed-error
            Err(_) => continue,
        };
        if let Some(cache) = cache {
            // A cache write failure must not drop the finding.
            // slopguard-disable-next-line no-ignored-result
            let _ = cache.put_probability(&candidate_key(candidate, jev_model), probability);
        }
        if let Some(finding) = finding_for(candidate, probability, llm, global_threshold).await {
            findings.push(finding);
        }
    }
    findings
}

/// Run the classification pass over `candidates`, bounded to `concurrency`
/// simultaneous decision requests. Cache-miss candidates whose context windows
/// overlap are batched into one multi-noul request per cluster; cache hits skip
/// the network entirely. Returns only findings whose probability meets the
/// threshold. Blocks the calling thread on a private multi-thread runtime, like
/// [`run_ai_pass`](super::run_ai_pass).
#[allow(clippy::too_many_arguments)]
pub fn run_classifier_pass(
    decider: &dyn DecisionProvider,
    llm: Option<&dyn AgentProvider>,
    candidates: Vec<AiCandidate>,
    jev_model: &str,
    global_threshold: f64,
    concurrency: usize,
    caps: BatchConfig,
    cache: Option<&AiCache>,
) -> Vec<Finding> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let runtime = match Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        // If a runtime cannot be built, skip AI rather than crashing the scan.
        Err(_) => return Vec::new(),
    };

    let cluster_caps = ClusterCaps {
        radius: CONTEXT_RADIUS,
        // batch = false collapses every candidate into its own single-noul call.
        max_questions: if caps.batch {
            caps.max_questions.max(1)
        } else {
            1
        },
        max_state_lines: caps.max_state_lines.max(1),
    };

    runtime.block_on(async {
        // Read the cache per candidate: hits carry their probability, misses go
        // to clustering.
        let mut hits: Vec<(&AiCandidate, f64)> = Vec::new();
        let mut misses: Vec<&AiCandidate> = Vec::new();
        for candidate in &candidates {
            match cache.and_then(|c| c.get_probability(&candidate_key(candidate, jev_model))) {
                Some(probability) => hits.push((candidate, probability)),
                None => misses.push(candidate),
            }
        }

        let clusters = build_clusters(&misses, &cluster_caps);
        let permits = Arc::new(Semaphore::new(concurrency.clamp(1, MAX_AI_CONCURRENCY)));

        // Batched decision calls: one request per cluster, bounded on clusters.
        let cluster_tasks = clusters.iter().map(|cluster| {
            let permits = Arc::clone(&permits);
            async move {
                let _permit = match permits.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => return Vec::new(),
                };
                classify_cluster(decider, llm, cluster, jev_model, global_threshold, cache).await
            }
        });
        let mut findings: Vec<Finding> = join_all(cluster_tasks)
            .await
            .into_iter()
            .flatten()
            .collect();

        // Cache hits need no network call, only the threshold and (rarely) an
        // LLM-written reason.
        let hit_tasks = hits.iter().map(|(candidate, probability)| {
            let permits = Arc::clone(&permits);
            async move {
                let _permit = match permits.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => return None,
                };
                finding_for(candidate, *probability, llm, global_threshold).await
            }
        });
        findings.extend(join_all(hit_tasks).await.into_iter().flatten());
        findings
    })
}

#[cfg(test)]
#[path = "classifier_tests.rs"]
mod tests;
