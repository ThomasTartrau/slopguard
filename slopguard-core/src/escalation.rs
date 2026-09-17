//! Severity escalation: a warning that fires once is noise, the same warning
//! firing many times in one file is a quality problem. When a rule produces at
//! least `threshold` findings in a single file, its warnings in that file
//! become errors.
//!
//! Applied after baseline filtering and outside the scan cache, so only
//! findings that are actually reported take part in the count.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::EscalationConfig;
use crate::finding::{Finding, ScanResult};
use crate::rule::{RuleId, Severity};
use crate::scanner::count_severities;

/// The threshold that applies to `rule_id`: the per-rule override when set,
/// otherwise the global one. A configured 0 behaves as 1, so escalation can
/// never fire on an empty group.
fn threshold_for(config: &EscalationConfig, rule_id: &str) -> usize {
    let configured = config.rules.get(rule_id).copied();
    configured.unwrap_or(config.threshold).max(1)
}

/// Escalate warnings to errors in place and return how many were escalated.
///
/// Findings are grouped by (file, rule id). Every finding of the group counts
/// toward the threshold, but only warnings are raised: escalation is one level
/// only, and an error stays an error.
pub fn escalate(findings: &mut [Finding], config: &EscalationConfig) -> usize {
    let mut counts: HashMap<(PathBuf, RuleId), usize> = HashMap::new();
    for f in findings.iter() {
        let key = (f.file.clone(), f.rule_id.clone());
        *counts.entry(key).or_insert(0) += 1;
    }

    let mut escalated = 0;
    for f in findings.iter_mut() {
        if f.severity != Severity::Warning {
            continue;
        }
        let key = (f.file.clone(), f.rule_id.clone());
        let count = counts.get(&key).copied().unwrap_or(0);
        if count >= threshold_for(config, f.rule_id.as_str()) {
            f.severity = Severity::Error;
            f.escalated = true;
            escalated += 1;
        }
    }
    escalated
}

/// Apply escalation to a scan result and keep `stats` consistent.
///
/// A no-op when `config.enabled` is false. Returns the number of escalated
/// findings. `files_scanned` and `baseline_filtered` are preserved.
pub fn apply_escalation(result: &mut ScanResult, config: &EscalationConfig) -> usize {
    if !config.enabled {
        return 0;
    }
    let escalated = escalate(&mut result.findings, config);
    if escalated > 0 {
        let (errors, warnings) = count_severities(&result.findings);
        result.stats.errors = errors;
        result.stats.warnings = warnings;
        result.stats.total = errors + warnings;
    }
    escalated
}

#[cfg(test)]
mod tests {
    use crate::finding::ScanStats;
    use crate::rule::Category;

    use super::*;

    fn finding(rule_id: &str, severity: Severity, file: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category: Category::Correctness,
            message: "m".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from(file),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
            escalated: false,
        }
    }

    fn config(enabled: bool, threshold: usize, rules: &[(&str, usize)]) -> EscalationConfig {
        let mut overrides = HashMap::new();
        for (id, n) in rules {
            overrides.insert((*id).to_string(), *n);
        }
        EscalationConfig {
            enabled,
            threshold,
            rules: overrides,
        }
    }

    fn repeated(rule_id: &str, severity: Severity, file: &str, n: usize) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(n);
        for _ in 0..n {
            findings.push(finding(rule_id, severity.clone(), file));
        }
        findings
    }

    fn result_of(findings: Vec<Finding>) -> ScanResult {
        let (errors, warnings) = count_severities(&findings);
        ScanResult {
            findings,
            stats: ScanStats {
                errors,
                warnings,
                total: errors + warnings,
                files_scanned: 3,
                baseline_filtered: 0,
                diff_base: None,
                files_changed: None,
            },
            cache_stats: None,
        }
    }

    #[test]
    fn below_threshold_is_untouched() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 4);

        assert_eq!(escalate(&mut findings, &config(true, 5, &[])), 0);
        assert!(findings.iter().all(|f| f.severity == Severity::Warning));
        assert!(findings.iter().all(|f| !f.escalated));
    }

    #[test]
    fn at_threshold_escalates_every_finding_of_the_rule() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 5);

        assert_eq!(escalate(&mut findings, &config(true, 5, &[])), 5);
        assert!(findings.iter().all(|f| f.severity == Severity::Error));
        assert!(findings.iter().all(|f| f.escalated));
    }

    #[test]
    fn counting_is_per_file() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 3);
        findings.extend(repeated("a", Severity::Warning, "b.rs", 3));

        assert_eq!(escalate(&mut findings, &config(true, 5, &[])), 0);
    }

    #[test]
    fn counting_is_per_rule() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 3);
        findings.extend(repeated("b", Severity::Warning, "a.rs", 3));

        assert_eq!(escalate(&mut findings, &config(true, 5, &[])), 0);
    }

    #[test]
    fn errors_are_not_escalated_further() {
        let mut findings = repeated("a", Severity::Error, "a.rs", 5);

        assert_eq!(escalate(&mut findings, &config(true, 5, &[])), 0);
        assert!(findings.iter().all(|f| f.severity == Severity::Error));
        assert!(findings.iter().all(|f| !f.escalated));
    }

    #[test]
    fn per_rule_override_lowers_threshold() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 3);

        assert_eq!(escalate(&mut findings, &config(true, 5, &[("a", 3)])), 3);
        assert!(findings.iter().all(|f| f.severity == Severity::Error));
    }

    #[test]
    fn per_rule_override_raises_threshold() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 5);

        assert_eq!(escalate(&mut findings, &config(true, 5, &[("a", 10)])), 0);
        assert!(findings.iter().all(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn zero_threshold_behaves_as_one() {
        let mut findings = repeated("a", Severity::Warning, "a.rs", 1);

        assert_eq!(escalate(&mut findings, &config(true, 0, &[])), 1);
        assert_eq!(findings[0].severity, Severity::Error);

        let mut empty: Vec<Finding> = Vec::new();
        assert_eq!(escalate(&mut empty, &config(true, 0, &[])), 0);
    }

    #[test]
    fn disabled_config_is_a_no_op() {
        let mut result = result_of(repeated("a", Severity::Warning, "a.rs", 5));

        assert_eq!(apply_escalation(&mut result, &config(false, 5, &[])), 0);
        assert_eq!(result.stats.errors, 0);
        assert_eq!(result.stats.warnings, 5);
        assert!(result.findings.iter().all(|f| !f.escalated));
    }

    #[test]
    fn apply_escalation_recomputes_stats() {
        let mut result = result_of(repeated("a", Severity::Warning, "a.rs", 5));

        assert_eq!(apply_escalation(&mut result, &config(true, 5, &[])), 5);
        assert_eq!(result.stats.errors, 5);
        assert_eq!(result.stats.warnings, 0);
        assert_eq!(result.stats.total, 5);
        assert_eq!(result.stats.files_scanned, 3);
    }
}
