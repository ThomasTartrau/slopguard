//! The AI confirmation pipeline.
//!
//! An `ai_check` rule's AST pattern is a cheap pre-filter run by the AST layer
//! in `slopguard-core`. Each resulting match is an [`AiCandidate`] here: the
//! surrounding code is extracted ([`context`]), a prompt is rendered
//! ([`prompt`]), and the LLM is asked to confirm the issue with a structured
//! [`AiVerdict`] ([`verdict`]). Only confirmed candidates become findings.

mod context;
mod prompt;
mod verdict;

pub use verdict::AiVerdict;

use std::sync::Arc;

use tokio::runtime::Builder;

use futures::future::join_all;
use ironflow_core::operations::agent::Agent;
use ironflow_core::provider::AgentProvider;
use slopguard_core::finding::Finding;
use tokio::sync::Semaphore;

use crate::cache::{cache_key, AiCache};
use context::{extract_context, CONTEXT_RADIUS};
use prompt::render_prompt;

/// The model used when neither the rule nor `[ai].model` specifies one.
pub const DEFAULT_MODEL: &str = "claude-haiku-4-5";

/// A pre-filter match awaiting AI confirmation.
pub struct AiCandidate {
    /// The AST finding produced by the pre-filter. Cloned into the confirmed
    /// finding, with `note`/`confidence` filled from the verdict.
    pub finding: Finding,
    /// Full source of `finding.file`, used for context extraction and caching.
    pub file_content: String,
    /// The `ai_check.prompt` template.
    pub prompt_template: String,
    /// Resolved model (rule override, else config, else [`DEFAULT_MODEL`]).
    pub model: String,
    /// Value substituted for `{{rule_context}}` (typically the rule message).
    pub rule_context: String,
}

/// Call the LLM for one rendered prompt. Returns `None` on any provider or
/// deserialization error: a candidate we cannot confirm is silently skipped
/// rather than crashing the scan or emitting a false positive.
///
/// The output schema is derived from [`AiVerdict`] via `output::<T>()`, so the
/// schema and the Rust type stay in sync.
async fn call_llm(provider: &dyn AgentProvider, model: &str, prompt: &str) -> Option<AiVerdict> {
    let result = Agent::new()
        .prompt(prompt)
        .model(model)
        // Structured output requires max_turns >= 2 (see ironflow docs).
        .max_turns(2)
        .output::<AiVerdict>()
        .run(provider)
        .await
        .ok()?;
    result.json::<AiVerdict>().ok()
}

/// Confirm a single candidate, consulting the cache first when provided.
async fn confirm(
    provider: &dyn AgentProvider,
    candidate: &AiCandidate,
    cache: Option<&AiCache>,
) -> Option<Finding> {
    let filename = candidate.finding.file.display().to_string();
    let code = extract_context(
        &candidate.file_content,
        candidate.finding.line,
        CONTEXT_RADIUS,
    );
    let prompt = render_prompt(
        &candidate.prompt_template,
        &code,
        &filename,
        &candidate.rule_context,
    );
    let key = cache_key(&candidate.file_content, &prompt, &candidate.model);

    let verdict = match cache.and_then(|c| c.get(&key)) {
        Some(cached) => cached,
        None => {
            let fresh = call_llm(provider, &candidate.model, &prompt).await?;
            if let Some(cache) = cache {
                // A cache write failure must not drop the finding.
                // slopguard-disable-next-line no-ignored-result
                let _ = cache.put(&key, &fresh);
            }
            fresh
        }
    };

    if !verdict.is_issue {
        return None;
    }
    let mut finding = candidate.finding.clone();
    finding.note = Some(verdict.reason);
    finding.confidence = Some(verdict.confidence);
    Some(finding)
}

/// Run the AI confirmation pass over `candidates`, bounded to `concurrency`
/// simultaneous LLM calls. Returns only confirmed findings.
///
/// This blocks the calling thread on a private multi-thread Tokio runtime, so
/// callers stay synchronous (the AST scanner and CLI are sync).
pub fn run_ai_pass(
    provider: &dyn AgentProvider,
    candidates: Vec<AiCandidate>,
    concurrency: usize,
    cache: Option<&AiCache>,
) -> Vec<Finding> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let runtime = match Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        // If a runtime cannot be built, skip AI rather than crashing the scan.
        Err(_) => return Vec::new(),
    };

    runtime.block_on(async {
        let permits = Arc::new(Semaphore::new(concurrency.max(1)));
        let tasks = candidates.iter().map(|candidate| {
            let permits = permits.clone();
            async move {
                // Closed only on shutdown; if acquisition fails, skip.
                let _permit = permits.acquire().await.ok()?;
                confirm(provider, candidate, cache).await
            }
        });
        join_all(tasks).await.into_iter().flatten().collect()
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ironflow_core::error::AgentError;
    use ironflow_core::provider::{AgentConfig, AgentOutput, AgentProvider, InvokeFuture};
    use serde_json::json;
    use slopguard_core::rule::{Category, RuleId, Severity};
    use tempfile::tempdir;

    use super::*;

    /// A provider that returns a fixed verdict and counts invocations. No
    /// network: this stubs the LLM at the `AgentProvider` boundary.
    struct MockProvider {
        verdict: serde_json::Value,
        calls: AtomicUsize,
    }

    impl MockProvider {
        fn new(verdict: serde_json::Value) -> Self {
            Self {
                verdict,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl AgentProvider for MockProvider {
        fn invoke<'a>(&'a self, _config: &'a AgentConfig) -> InvokeFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let value = self.verdict.clone();
            Box::pin(async move { Ok(AgentOutput::new(value)) })
        }
    }

    /// A provider whose invocation always fails.
    struct FailingProvider;

    impl AgentProvider for FailingProvider {
        fn invoke<'a>(&'a self, _config: &'a AgentConfig) -> InvokeFuture<'a> {
            Box::pin(async move {
                Err(AgentError::ProcessFailed {
                    exit_code: 1,
                    stderr: "boom".to_string(),
                })
            })
        }
    }

    fn candidate(line: usize, content: &str) -> AiCandidate {
        AiCandidate {
            finding: Finding {
                rule_id: RuleId::from("ai-rule"),
                severity: Severity::Warning,
                category: Category::Slop,
                message: "candidate".to_string(),
                note: None,
                fix: None,
                file: PathBuf::from("src/main.rs"),
                line,
                column: 1,
                end_line: line,
                end_column: 2,
                matched_text: "x".to_string(),
                confidence: None,
            },
            file_content: content.to_string(),
            prompt_template: "check {{filename}} at:\n{{code}}\ncontext={{rule_context}}"
                .to_string(),
            model: DEFAULT_MODEL.to_string(),
            rule_context: "no meaningful SAFETY comment".to_string(),
        }
    }

    #[test]
    fn confirmed_candidate_becomes_finding_with_note_and_confidence() {
        let provider = MockProvider::new(json!({
            "is_issue": true,
            "reason": "the SAFETY comment says nothing",
            "confidence": 0.82
        }));
        let findings = run_ai_pass(
            &provider,
            vec![candidate(1, "// SAFETY: trust me\n")],
            4,
            None,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].note.as_deref(),
            Some("the SAFETY comment says nothing")
        );
        assert_eq!(findings[0].confidence, Some(0.82));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejected_candidate_is_dropped() {
        let provider = MockProvider::new(json!({
            "is_issue": false,
            "reason": "comment is fine",
            "confidence": 0.1
        }));
        let findings = run_ai_pass(
            &provider,
            vec![candidate(1, "// SAFETY: locked\n")],
            4,
            None,
        );
        assert!(findings.is_empty(), "is_issue=false must drop the finding");
    }

    #[test]
    fn provider_error_skips_candidate_without_panicking() {
        let findings = run_ai_pass(&FailingProvider, vec![candidate(1, "code\n")], 4, None);
        assert!(findings.is_empty(), "a failed LLM call skips the candidate");
    }

    #[test]
    fn cache_prevents_second_llm_call() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path());
        let provider = MockProvider::new(json!({
            "is_issue": true,
            "reason": "cached",
            "confidence": 0.5
        }));

        let first = run_ai_pass(
            &provider,
            vec![candidate(1, "// SAFETY: x\n")],
            4,
            Some(&cache),
        );
        assert_eq!(first.len(), 1);
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "first pass calls LLM"
        );

        let second = run_ai_pass(
            &provider,
            vec![candidate(1, "// SAFETY: x\n")],
            4,
            Some(&cache),
        );
        assert_eq!(second.len(), 1, "cached verdict still yields the finding");
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "second pass must be served from cache, no new LLM call"
        );
    }
}
