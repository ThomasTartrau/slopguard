//! Tests for the System One classification pass. Kept in a sibling file so the
//! implementation module stays small (repo convention: `config/tests.rs`,
//! `rule/parse_tests.rs`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ironflow_core::decision::{
    DecideFuture, DecisionAnswer, DecisionOutput, DecisionUsage, NoulAnswer,
};
use ironflow_core::error::AgentError;
use ironflow_core::provider::{AgentConfig, AgentOutput, InvokeFuture};
use serde_json::json;
use slopguard_core::rule::{Category, RuleId, Severity};
use tempfile::tempdir;

use super::*;

/// A decider that returns a fixed noul probability and counts calls. No
/// network: stubs Jev at the `DecisionProvider` boundary.
struct MockDecider {
    noul: f64,
    calls: AtomicUsize,
}

impl MockDecider {
    fn new(noul: f64) -> Self {
        Self {
            noul,
            calls: AtomicUsize::new(0),
        }
    }
}

impl DecisionProvider for MockDecider {
    fn decide<'a>(&'a self, _request: &'a DecisionRequest) -> DecideFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let p = self.noul;
        Box::pin(async move {
            let mut answers = BTreeMap::new();
            answers.insert(
                QUESTION.to_string(),
                DecisionAnswer::Noul(NoulAnswer { noul: p }),
            );
            Ok(DecisionOutput {
                model: None,
                answers,
                usage: DecisionUsage::default(),
            })
        })
    }
}

/// A decider that answers with no `is_issue`, so `noul(QUESTION)` is a lookup
/// error: the candidate must be skipped, not panic.
struct EmptyDecider;

impl DecisionProvider for EmptyDecider {
    fn decide<'a>(&'a self, _request: &'a DecisionRequest) -> DecideFuture<'a> {
        Box::pin(async move {
            Ok(DecisionOutput {
                model: None,
                answers: BTreeMap::new(),
                usage: DecisionUsage::default(),
            })
        })
    }
}

/// An LLM stub returning a fixed reason, for `generated` rules.
struct MockLlm {
    reason: String,
}

impl AgentProvider for MockLlm {
    fn invoke<'a>(&'a self, _config: &'a AgentConfig) -> InvokeFuture<'a> {
        let value = json!({ "is_issue": true, "reason": self.reason, "confidence": 0.9 });
        Box::pin(async move { Ok(AgentOutput::new(value)) })
    }
}

/// An LLM stub that always fails, to exercise the generated-reason fallback.
struct FailingLlm;

impl AgentProvider for FailingLlm {
    fn invoke<'a>(&'a self, _config: &'a AgentConfig) -> InvokeFuture<'a> {
        Box::pin(async move {
            Err(AgentError::ProcessFailed {
                exit_code: 1,
                stderr: "boom".to_string(),
            })
        })
    }
}

fn candidate(reason_mode: ReasonMode, threshold: Option<f64>) -> AiCandidate {
    AiCandidate {
        finding: Finding {
            rule_id: RuleId::from("ai-rule"),
            severity: Severity::Warning,
            category: Category::Slop,
            message: "candidate".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from("src/main.rs"),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
            escalated: false,
        },
        file_content: "let url = user_input;\nclient.get(url).send().await?;\n".to_string(),
        prompt_template: "audit {{filename}}\n{{code}}\nctx={{rule_context}}".to_string(),
        model: super::super::DEFAULT_MODEL.to_string(),
        rule_context: "static note for this rule".to_string(),
        reason_mode,
        threshold,
        if_true: None,
        if_false: None,
    }
}

#[test]
fn fires_when_probability_meets_threshold() {
    let decider = MockDecider::new(0.82);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(findings.len(), 1, "p=0.82 >= 0.7 must fire");
}

#[test]
fn drops_when_probability_below_threshold() {
    let decider = MockDecider::new(0.55);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert!(findings.is_empty(), "p=0.55 < 0.7 must not fire");
}

#[test]
fn per_rule_threshold_overrides_global() {
    // Global would drop (0.7 > 0.6), the per-rule override (0.5) fires.
    let decider = MockDecider::new(0.6);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, Some(0.5))],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "per-rule threshold 0.5 must win over global 0.7"
    );
}

#[test]
fn confidence_is_the_raw_probability() {
    let decider = MockDecider::new(0.82);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings[0].confidence,
        Some(0.82),
        "confidence must be the raw Jev probability, not a derived value"
    );
}

#[test]
fn static_reason_uses_the_rule_note() {
    let decider = MockDecider::new(0.9);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings[0].note.as_deref(),
        Some("static note for this rule"),
        "a static rule uses its own note, no LLM"
    );
}

#[test]
fn raw_probability_cached_threshold_applied_after_cache() {
    // First pass: high global threshold drops the candidate, but the raw
    // probability is still cached. Second pass: a lower threshold fires from
    // the cache, with NO new decider call. This proves the threshold is
    // applied after the cache, not baked into it.
    let dir = tempdir().unwrap();
    let cache = AiCache::new(dir.path());
    let decider = MockDecider::new(0.8);

    let first = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.9,
        4,
        Some(&cache),
    );
    assert!(first.is_empty(), "p=0.8 < 0.9 drops on the first pass");
    assert_eq!(
        decider.calls.load(Ordering::SeqCst),
        1,
        "first pass calls Jev"
    );

    let second = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.5,
        4,
        Some(&cache),
    );
    assert_eq!(second.len(), 1, "retuned threshold 0.5 fires from cache");
    assert_eq!(
        decider.calls.load(Ordering::SeqCst),
        1,
        "second pass must be served from cache: no new Jev call"
    );
}

#[test]
fn generated_reason_written_by_llm() {
    let decider = MockDecider::new(0.9);
    let llm = MockLlm {
        reason: "url comes from an unvalidated query parameter".to_string(),
    };
    let findings = run_classifier_pass(
        &decider,
        Some(&llm),
        vec![candidate(ReasonMode::Generated, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings[0].note.as_deref(),
        Some("url comes from an unvalidated query parameter"),
        "a generated rule uses the LLM-written per-instance reason"
    );
}

#[test]
fn generated_reason_falls_back_to_static_without_llm() {
    let decider = MockDecider::new(0.9);
    let findings = run_classifier_pass(
        &decider,
        None,
        vec![candidate(ReasonMode::Generated, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings[0].note.as_deref(),
        Some("static note for this rule"),
        "no LLM available: a generated rule falls back to the static note"
    );
}

#[test]
fn generated_reason_falls_back_when_llm_fails() {
    let decider = MockDecider::new(0.9);
    let findings = run_classifier_pass(
        &decider,
        Some(&FailingLlm),
        vec![candidate(ReasonMode::Generated, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert_eq!(
        findings[0].note.as_deref(),
        Some("static note for this rule"),
        "a failed LLM call falls back to the static note"
    );
}

#[test]
fn missing_answer_skips_candidate_without_panicking() {
    let findings = run_classifier_pass(
        &EmptyDecider,
        None,
        vec![candidate(ReasonMode::Static, None)],
        "jev-latest",
        0.7,
        4,
        None,
    );
    assert!(
        findings.is_empty(),
        "a missing is_issue answer skips the candidate"
    );
}

#[test]
fn build_classifier_disabled_is_an_error() {
    // Box<dyn DecisionProvider> is not Debug, so match instead of unwrap_err.
    let cfg = ClassifierConfig::default();
    match build_classifier(&cfg) {
        Err(ClassifierError::Disabled) => {}
        Err(other) => panic!("expected Disabled, got {other:?}"),
        Ok(_) => panic!("a disabled classifier must not build a provider"),
    }
}

#[test]
fn resolve_jev_model_defaults_per_transport() {
    let direct = ClassifierConfig {
        enabled: true,
        transport: ClassifierTransport::Direct,
        model: None,
        threshold: 0.7,
    };
    assert_eq!(resolve_jev_model(&direct), "jev-latest");

    let openrouter = ClassifierConfig {
        transport: ClassifierTransport::Openrouter,
        ..direct.clone()
    };
    assert_eq!(resolve_jev_model(&openrouter), "typesafe/jev-1.13");

    let explicit = ClassifierConfig {
        model: Some("jev-2".to_string()),
        ..direct
    };
    assert_eq!(resolve_jev_model(&explicit), "jev-2");
}
