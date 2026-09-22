//! Live A/B calibration for the System One classifier, run against the real Jev
//! API over OpenRouter. Ignored by default: it needs `OPENROUTER_API_KEY` and
//! makes billable network calls, so it never runs in CI.
//!
//! Run it with:
//!
//! ```sh
//! OPENROUTER_API_KEY=... cargo test -p slopguard-ai --features provider-typesafe \
//!     --test calibration -- --ignored --nocapture
//! ```
//!
//! It measures, on the labeled fixtures under
//! `tests/fixtures/classifier_calibration/`:
//!   1. the radius A/B: probability and decision at radius 50 (before) vs the
//!      new radius 25 (after), so a threshold drift from the smaller window is
//!      visible;
//!   2. the batching effect: the same fixtures classified with `batch = true`
//!      (multi-noul per cluster) vs `batch = false` (one call each). Batching
//!      shares one `state` (the merged region) across every noul by design, so
//!      it is not decision-neutral; this reports which borderline candidates
//!      flip, as a calibration signal.
#![cfg(feature = "provider-typesafe")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ironflow_core::decision::{DecisionProvider, DecisionQuestion, DecisionRequest, NoulCriteria};
use serde_json::{json, Value};
use slopguard_ai::{
    build_classifier, resolve_jev_model, run_classifier_pass, AiCandidate, BatchConfig,
};
use slopguard_core::config::{ClassifierConfig, ClassifierTransport};
use slopguard_core::finding::Finding;
use slopguard_core::rule::{Category, ReasonMode, RuleId, Severity};

/// Global decision threshold under evaluation.
const THRESHOLD: f64 = 0.7;

/// The current (new) context radius, mirrored from the pipeline.
const RADIUS_AFTER: usize = 25;
/// The previous context radius, for the A/B.
const RADIUS_BEFORE: usize = 50;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/classifier_calibration")
}

/// Plain context extraction (no line numbers), matching the pre-batching state
/// format used to measure the "before" side.
fn extract_context(source: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = line.saturating_sub(1).min(lines.len() - 1);
    let start = idx.saturating_sub(radius);
    let end = (idx + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn render(template: &str, code: &str, filename: &str, rule_context: &str) -> String {
    template
        .replace("{{code}}", code)
        .replace("{{filename}}", filename)
        .replace("{{rule_context}}", rule_context)
}

struct Case {
    file: String,
    line: usize,
    rule: String,
    label: bool,
    note: String,
    prompt: String,
    rule_context: String,
}

fn load_cases() -> Vec<Case> {
    let manifest = fs::read_to_string(fixtures_dir().join("labels.json")).unwrap();
    let root: Value = serde_json::from_str(&manifest).unwrap();
    let rules = root["rules"].as_object().unwrap();
    root["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let rule = c["rule"].as_str().unwrap().to_string();
            let spec = &rules[&rule];
            Case {
                file: c["file"].as_str().unwrap().to_string(),
                line: c["line"].as_u64().unwrap() as usize,
                rule: rule.clone(),
                label: c["label"].as_bool().unwrap(),
                note: c["note"].as_str().unwrap().to_string(),
                prompt: spec["prompt"].as_str().unwrap().to_string(),
                rule_context: spec["rule_context"].as_str().unwrap().to_string(),
            }
        })
        .collect()
}

fn candidate(case: &Case) -> AiCandidate {
    let path = fixtures_dir().join(&case.file);
    let content = fs::read_to_string(&path).unwrap();
    AiCandidate {
        finding: Finding {
            rule_id: RuleId::from(case.rule.as_str()),
            severity: Severity::Warning,
            category: Category::Slop,
            message: "calibration candidate".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from(&case.file),
            line: case.line,
            column: 1,
            end_line: case.line,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
            escalated: false,
        },
        file_content: content,
        prompt_template: case.prompt.clone(),
        model: "claude-haiku-4-5".to_string(),
        rule_context: case.rule_context.clone(),
        reason_mode: ReasonMode::Static,
        threshold: None,
        if_true: None,
        if_false: None,
    }
}

fn candidates(cases: &[Case]) -> Vec<AiCandidate> {
    cases.iter().map(candidate).collect()
}

/// The pre-batching single-noul probability at `radius`, plain state, keyed
/// `is_issue`, no line hint. Mirrors the code path before this change.
async fn probability_before(
    decider: &dyn DecisionProvider,
    case: &Case,
    model: &str,
    radius: usize,
) -> Option<f64> {
    let content = fs::read_to_string(fixtures_dir().join(&case.file)).ok()?;
    let code = extract_context(&content, case.line, radius);
    let instructions = render(
        &case.prompt,
        "the code under review (provided as the state)",
        &case.file,
        &case.rule_context,
    );
    let mut questions = BTreeMap::new();
    questions.insert(
        "is_issue".to_string(),
        DecisionQuestion::Noul {
            instructions: json!(instructions),
            criteria: NoulCriteria::default(),
        },
    );
    let request = DecisionRequest {
        state: json!(code),
        model: model.into(),
        questions,
    };
    decider.decide(&request).await.ok()?.noul("is_issue").ok()
}

/// The (file, line) identity of a fired finding.
fn fired_set(findings: &[Finding]) -> BTreeSet<(String, usize)> {
    findings
        .iter()
        .map(|f| (f.file.display().to_string(), f.line))
        .collect()
}

fn config() -> ClassifierConfig {
    ClassifierConfig {
        enabled: true,
        transport: ClassifierTransport::Openrouter,
        ..ClassifierConfig::default()
    }
}

#[test]
#[ignore = "hits the live TypeSafe/Jev API via OPENROUTER_API_KEY"]
// Fixed-width column headers are literal by nature; inlining them is not useful.
#[allow(clippy::print_literal)]
fn calibration_ab_radius_and_batching() {
    let cases = load_cases();
    let cfg = config();
    let decider = match build_classifier(&cfg) {
        Ok(decider) => decider,
        Err(err) => panic!("set OPENROUTER_API_KEY to run calibration: {err}"),
    };
    let model = resolve_jev_model(&cfg);

    // 1. Radius A/B: per-case probability at radius 50 (before) and 25 (after).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let before: Vec<(f64, f64)> = runtime.block_on(async {
        let mut out = Vec::new();
        for case in &cases {
            let p50 = probability_before(&*decider, case, &model, RADIUS_BEFORE)
                .await
                .unwrap_or(-1.0);
            let p25 = probability_before(&*decider, case, &model, RADIUS_AFTER)
                .await
                .unwrap_or(-1.0);
            out.push((p50, p25));
        }
        out
    });

    println!("\n=== Radius A/B (single-noul, threshold {THRESHOLD}) ===");
    println!(
        "{:<9} {:>4} {:<8} {:>7} {:>7} {:>8} {:>8}  {}",
        "file", "line", "label", "p@r50", "p@r25", "dec@50", "dec@25", "note"
    );
    let mut acc_before = 0usize;
    let mut acc_after_single = 0usize;
    for (case, (p50, p25)) in cases.iter().zip(&before) {
        let d50 = *p50 >= THRESHOLD;
        let d25 = *p25 >= THRESHOLD;
        if d50 == case.label {
            acc_before += 1;
        }
        if d25 == case.label {
            acc_after_single += 1;
        }
        println!(
            "{:<9} {:>4} {:<8} {:>7.3} {:>7.3} {:>8} {:>8}  {}",
            case.file, case.line, case.label, p50, p25, d50, d25, case.note
        );
    }
    let n = cases.len();
    println!(
        "accuracy: before(r50)={}/{}  after(r25 single)={}/{}",
        acc_before, n, acc_after_single, n
    );

    // 2. Batching fidelity: batch=true vs batch=false over the same candidates,
    //    through the real integrated path. Both must fire the same set.
    let batched = run_classifier_pass(
        &*decider,
        None,
        candidates(&cases),
        &model,
        THRESHOLD,
        4,
        BatchConfig {
            batch: true,
            max_questions: 8,
            max_state_lines: 200,
        },
        None,
    );
    let single = run_classifier_pass(
        &*decider,
        None,
        candidates(&cases),
        &model,
        THRESHOLD,
        4,
        BatchConfig {
            batch: false,
            max_questions: 8,
            max_state_lines: 200,
        },
        None,
    );

    let batched_fired = fired_set(&batched);
    let single_fired = fired_set(&single);
    let mut acc_after_batched = 0usize;
    let mut acc_after_single_integrated = 0usize;
    for case in &cases {
        let id = (case.file.clone(), case.line);
        if batched_fired.contains(&id) == case.label {
            acc_after_batched += 1;
        }
        if single_fired.contains(&id) == case.label {
            acc_after_single_integrated += 1;
        }
    }
    println!("\n=== Batching effect (integrated path, radius 25) ===");
    println!("batched fired: {batched_fired:?}");
    println!("single  fired: {single_fired:?}");
    let diverged: Vec<_> = cases
        .iter()
        .map(|c| (c.file.clone(), c.line))
        .filter(|id| batched_fired.contains(id) != single_fired.contains(id))
        .collect();
    // Batching shares one `state` (the merged cluster region) across every noul,
    // by design, so a member sees the whole region instead of its own window.
    // That is not decision-neutral: borderline candidates can flip. This lists
    // the candidates that flipped, as a calibration signal, not a failure.
    println!("diverged (batched != single): {diverged:?}");
    println!(
        "accuracy: after(r25 single)={}/{}  after(r25 batched)={}/{}",
        acc_after_single_integrated, n, acc_after_batched, n
    );

    // Sanity floor only: the model must clearly beat a coin flip on the labeled
    // set. The A/B numbers above are the calibration artifact, not an assertion.
    assert!(
        acc_after_batched * 4 >= n * 3,
        "classifier accuracy too low on the labeled set: {acc_after_batched}/{n}"
    );
}
