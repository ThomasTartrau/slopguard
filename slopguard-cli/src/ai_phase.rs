//! The AI phase of a scan: the AST pre-filter candidates of `ai_check` rules,
//! confirmed by the System One classifier or the generative LLM, under the
//! `ai.max_calls` cap and the signed verdict cache.

use std::collections::HashMap;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

use slopguard_ai::{
    build_classifier, build_provider, cap_candidates, resolve_jev_model, run_ai_pass,
    run_classifier_pass, AiCache, AiCandidate, BatchConfig, DEFAULT_MODEL,
};
use slopguard_core::cache::CacheKey;
use slopguard_core::config::Config;
use slopguard_core::finding::Finding;
use slopguard_core::rule::{ReasonMode, Rule};

use crate::scan_exec::{find_rule, ScanTargets};
use crate::AppError;

/// Turn AST candidate findings into AI candidates: attach each rule's prompt,
/// resolved model, and the file content used for context and cache keys. Files
/// are read once each; unreadable files or unmatched findings are skipped.
fn build_candidates(
    findings: Vec<Finding>,
    ai_rules: &[Rule],
    config: &Config,
) -> Vec<AiCandidate> {
    let mut contents: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut candidates = Vec::new();
    for finding in findings {
        let Some(rule) = find_rule(ai_rules, &finding) else {
            continue;
        };
        let Some(ai_check) = rule.ai_check.as_ref() else {
            continue;
        };
        let content = contents
            .entry(finding.file.clone())
            .or_insert_with(|| fs::read_to_string(&finding.file).ok());
        let Some(file_content) = content.clone() else {
            continue;
        };
        let model = ai_check
            .model
            .clone()
            .or_else(|| config.ai.model.clone())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        let rule_context = rule.note.clone().unwrap_or_else(|| rule.message.clone());
        candidates.push(AiCandidate {
            finding,
            file_content,
            prompt_template: ai_check.prompt.clone(),
            model,
            rule_context,
            reason_mode: ai_check.reason,
            threshold: ai_check.threshold,
            if_true: ai_check.if_true.clone(),
            if_false: ai_check.if_false.clone(),
        });
    }
    candidates
}

/// Run the AI phase for `ai_rules`: the System One classifier when
/// `[ai.classifier].enabled`, otherwise the generative LLM confirmation.
pub(crate) fn run_ai_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    if config.ai.classifier.enabled {
        return run_classifier_phase(targets, ai_rules, config, no_cache, cache_dir);
    }
    run_llm_phase(targets, ai_rules, config, no_cache, cache_dir)
}

/// Collect the AST pre-filter candidates for `ai_rules`, reading each matched
/// file once. Shared by the LLM and classifier phases.
fn collect_ai_candidates(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    cache_dir: &Path,
) -> Result<Vec<AiCandidate>, AppError> {
    let candidate_result = targets.run(ai_rules, config, true, cache_dir)?;
    Ok(build_candidates(
        candidate_result.findings,
        ai_rules,
        config,
    ))
}

/// The single non-fatal warning for AI rules skipped because no provider could
/// be built: a clear, credential-specific reason (disabled, missing API key,
/// missing claude binary, missing OAuth token). The AST findings still stand.
fn warn_ai_skipped(ai_rules: &[Rule], err: &dyn Display) {
    // CLI diagnostic to stderr, not application logging.
    // slopguard-disable-next-line no-println-in-prod
    eprintln!("warning: {} AI rules skipped ({err})", ai_rules.len());
}

/// The single warning for external `ai_check` rules dropped because the user
/// config does not set `ai.allow_external_rules`. Silent when none was dropped.
pub(crate) fn warn_external_ai_skipped(skipped: usize) {
    if skipped > 0 {
        // slopguard-disable-next-line no-println-in-prod
        eprintln!(
            "warning: {skipped} external AI rules skipped \
             (set ai.allow_external_rules = true in the user config to allow them)"
        );
    }
}

/// Keep at most `ai.max_calls` candidates for the AI pass, warning when some
/// exceed it. Returns the kept candidates and the overflow, reported as plain
/// AST findings without AI verification.
fn cap_ai_candidates(
    candidates: Vec<AiCandidate>,
    config: &Config,
) -> (Vec<AiCandidate>, Vec<Finding>) {
    let max_calls = config.ai.max_calls;
    let (kept, overflow) = cap_candidates(candidates, max_calls);
    if !overflow.is_empty() {
        // slopguard-disable-next-line no-println-in-prod
        eprintln!(
            "warning: {} AI candidates exceed ai.max_calls ({max_calls}); \
             reported without AI verification",
            overflow.len()
        );
    }
    (kept, overflow)
}

/// The AI verdict cache, unless `--no-cache` is set. Entries are signed with
/// the user's cache key; when that key is unavailable the cache is skipped and
/// verdicts are recomputed rather than read unsigned.
fn ai_cache(no_cache: bool, cache_dir: &Path) -> Option<AiCache> {
    if no_cache {
        return None;
    }
    match CacheKey::load_or_create_default() {
        Ok(key) => Some(AiCache::new(cache_dir, key)),
        Err(err) => {
            // CLI diagnostic to stderr, not application logging.
            // slopguard-disable-next-line no-println-in-prod
            eprintln!("warning: AI cache disabled ({err})");
            None
        }
    }
}

/// Classify candidates with the System One provider (Jev).
///
/// When the classifier cannot be built (disabled, missing key), a single
/// warning is emitted and no call is made. `generated` rules escalate to the
/// LLM for a per-instance reason when one is available.
fn run_classifier_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    let decider = match build_classifier(&config.ai.classifier) {
        Ok(decider) => decider,
        Err(err) => {
            warn_ai_skipped(ai_rules, &err);
            return Ok(Vec::new());
        }
    };

    let candidates = collect_ai_candidates(targets, ai_rules, config, cache_dir)?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let (candidates, mut findings) = cap_ai_candidates(candidates, config);

    // The LLM writes reasons for `generated` rules, so it is only built when
    // one is present. Optional: without it, those rules fall back to their
    // static note (handled inside the pass).
    let needs_llm = candidates
        .iter()
        .any(|c| c.reason_mode == ReasonMode::Generated);
    let llm = needs_llm.then(|| build_provider(&config.ai).ok()).flatten();
    let cache = ai_cache(no_cache, cache_dir);
    let jev_model = resolve_jev_model(&config.ai.classifier);
    findings.extend(run_classifier_pass(
        &*decider,
        llm.as_deref(),
        candidates,
        &jev_model,
        config.ai.classifier.threshold,
        config.ai.concurrency,
        BatchConfig {
            batch: config.ai.classifier.batch,
            max_questions: config.ai.classifier.batch_max_questions,
            max_state_lines: config.ai.classifier.batch_max_state_lines,
        },
        cache.as_ref(),
    ));
    Ok(findings)
}

/// Run the generative LLM confirmation phase for `ai_rules`.
///
/// When the provider cannot be built (disabled, missing credentials), a single
/// warning is emitted and no LLM call is made. Otherwise the AST pre-filter
/// produces candidates that the LLM confirms.
fn run_llm_phase(
    targets: &ScanTargets,
    ai_rules: &[Rule],
    config: &Config,
    no_cache: bool,
    cache_dir: &Path,
) -> Result<Vec<Finding>, AppError> {
    let provider = match build_provider(&config.ai) {
        Ok(provider) => provider,
        Err(err) => {
            warn_ai_skipped(ai_rules, &err);
            return Ok(Vec::new());
        }
    };

    let candidates = collect_ai_candidates(targets, ai_rules, config, cache_dir)?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let (candidates, mut findings) = cap_ai_candidates(candidates, config);
    let cache = ai_cache(no_cache, cache_dir);
    findings.extend(run_ai_pass(
        &*provider,
        candidates,
        config.ai.concurrency,
        cache.as_ref(),
    ));
    Ok(findings)
}
