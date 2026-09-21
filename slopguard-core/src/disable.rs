use std::path::Path;

use crate::finding::Finding;
use crate::rule::{Category, RuleId, Severity};

const DISABLE_MARKER: &str = "slopguard-disable-next-line";

/// Internal rule id for a disable directive that suppressed nothing, reported
/// only when `--report-unused-disable` is set. Not a YAML rule.
pub const UNUSED_DISABLE_RULE_ID: &str = "unused-disable";

struct DisableDirective {
    /// 1-based line of the `// slopguard-disable-next-line` comment itself.
    comment_line: usize,
    /// 1-based line the directive suppresses findings on (the line after it).
    target_line: usize,
    rule_id: Option<RuleId>,
    /// The trimmed comment text, used as `matched_text` when reporting the
    /// directive itself as unused.
    comment_text: String,
}

fn parse_directives(source: &str) -> Vec<DisableDirective> {
    source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let rest = line
                .trim()
                .strip_prefix("//")?
                .trim()
                .strip_prefix(DISABLE_MARKER)?;
            let rest = rest.trim();
            Some(DisableDirective {
                comment_line: idx + 1,
                target_line: idx + 2,
                rule_id: (!rest.is_empty()).then(|| RuleId::from(rest)),
                comment_text: line.trim().to_string(),
            })
        })
        .collect()
}

/// Whether a `// slopguard-disable-next-line` directive suppresses `rule_id`
/// on 1-based `line` of `source`. A directive with no rule id suppresses every
/// rule; one naming a rule suppresses only that rule. Mirrors the filtering in
/// [`filter_disabled`] for callers that hold a position rather than a finding
/// (the `--fix` pass).
pub fn is_disabled(source: &str, line: usize, rule_id: &RuleId) -> bool {
    parse_directives(source)
        .iter()
        .any(|d| d.target_line == line && d.rule_id.as_ref().is_none_or(|id| id == rule_id))
}

/// Filter out findings that are suppressed by `// slopguard-disable-next-line`
/// comments in the source code.
pub fn filter_disabled(findings: Vec<Finding>, source: &str) -> Vec<Finding> {
    let directives = parse_directives(source);
    if directives.is_empty() {
        return findings;
    }
    findings
        .into_iter()
        .filter(|finding| {
            !directives.iter().any(|d| {
                d.target_line == finding.line
                    && d.rule_id.as_ref().is_none_or(|id| *id == finding.rule_id)
            })
        })
        .collect()
}

/// Report the disable directives in `source` that suppressed nothing, given the
/// file's raw (pre-suppression) findings.
///
/// A targeted directive (`// slopguard-disable-next-line rule-x`) is unused when
/// no raw finding for `rule-x` lands on the following line; a blanket directive
/// (no rule id) is unused when no raw finding at all lands there. Consumption is
/// judged against the raw findings, so for an AI rule it reflects the AST
/// pre-filter match, not the LLM verdict, and stays independent of the provider.
///
/// Each unused directive becomes a `warning`/`slop` [`Finding`] with rule id
/// [`UNUSED_DISABLE_RULE_ID`], anchored on the comment line.
pub fn unused_disable_findings(file: &Path, source: &str, raw: &[Finding]) -> Vec<Finding> {
    parse_directives(source)
        .into_iter()
        .filter(|d| {
            !raw.iter().any(|f| {
                f.line == d.target_line && d.rule_id.as_ref().is_none_or(|id| *id == f.rule_id)
            })
        })
        .map(|d| {
            let message = match &d.rule_id {
                Some(id) => format!(
                    "unused slopguard-disable-next-line for '{id}': it suppresses no finding"
                ),
                None => "unused slopguard-disable-next-line: it suppresses no finding".to_string(),
            };
            Finding {
                rule_id: RuleId::from(UNUSED_DISABLE_RULE_ID),
                severity: Severity::Warning,
                category: Category::Slop,
                message,
                note: None,
                fix: None,
                file: file.to_path_buf(),
                line: d.comment_line,
                column: 1,
                end_line: d.comment_line,
                end_column: d.comment_text.chars().count() + 1,
                matched_text: d.comment_text,
                confidence: None,
                escalated: false,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::finding::Finding;
    use crate::rule::{Category, RuleId, Severity};

    use super::{filter_disabled, unused_disable_findings, UNUSED_DISABLE_RULE_ID};

    fn make_finding(rule_id: &str, line: usize) -> Finding {
        Finding {
            rule_id: RuleId::from(rule_id),
            severity: Severity::Error,
            category: Category::Correctness,
            message: "test".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from("test.rs"),
            line,
            column: 1,
            end_line: line,
            end_column: 10,
            matched_text: "test".to_string(),
            confidence: None,
            escalated: false,
        }
    }

    #[test]
    fn disable_without_rule_id_suppresses_all_findings() {
        let source = "fn main() {\n    // slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings = vec![
            make_finding("no-unwrap-in-prod", 3),
            make_finding("no-expect-in-prod", 3),
        ];
        let result = filter_disabled(findings, source);
        assert!(
            result.is_empty(),
            "all findings on the disabled line should be suppressed"
        );
    }

    #[test]
    fn disable_with_rule_id_suppresses_only_that_rule() {
        let source = "fn main() {\n    // slopguard-disable-next-line no-unwrap-in-prod\n    foo().unwrap();\n}\n";
        let findings = vec![
            make_finding("no-unwrap-in-prod", 3),
            make_finding("other-rule", 3),
        ];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, RuleId::from("other-rule"));
    }

    #[test]
    fn disable_with_unknown_rule_id_suppresses_nothing() {
        let source = "fn main() {\n    // slopguard-disable-next-line nonexistent-rule\n    foo().unwrap();\n}\n";
        let findings = vec![make_finding("no-unwrap-in-prod", 3)];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, RuleId::from("no-unwrap-in-prod"));
    }

    #[test]
    fn disable_on_wrong_line_suppresses_nothing() {
        let source = "// slopguard-disable-next-line\nfn main() {\n    foo().unwrap();\n}\n";
        let findings = vec![make_finding("no-unwrap-in-prod", 3)];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn disable_with_spacing_variants() {
        let source_no_space =
            "fn main() {\n    //slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings1 = vec![make_finding("no-unwrap-in-prod", 3)];
        assert!(filter_disabled(findings1, source_no_space).is_empty());

        let source_extra_spaces =
            "fn main() {\n    //  slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings2 = vec![make_finding("no-unwrap-in-prod", 3)];
        assert!(filter_disabled(findings2, source_extra_spaces).is_empty());

        let source_leading_space =
            "fn main() {\n      // slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings3 = vec![make_finding("no-unwrap-in-prod", 3)];
        assert!(filter_disabled(findings3, source_leading_space).is_empty());
    }

    #[test]
    fn disable_without_rule_id_multiple_findings_same_line() {
        let source = "fn main() {\n    // slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings = vec![
            make_finding("rule-a", 3),
            make_finding("rule-b", 3),
            make_finding("rule-c", 3),
        ];
        let result = filter_disabled(findings, source);
        assert!(result.is_empty());
    }

    #[test]
    fn disable_with_rule_id_multiple_findings_same_line() {
        let source =
            "fn main() {\n    // slopguard-disable-next-line rule-b\n    foo().unwrap();\n}\n";
        let findings = vec![
            make_finding("rule-a", 3),
            make_finding("rule-b", 3),
            make_finding("rule-c", 3),
        ];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].rule_id, RuleId::from("rule-a"));
        assert_eq!(result[1].rule_id, RuleId::from("rule-c"));
    }

    #[test]
    fn no_disable_comments_returns_all_findings() {
        let source = "fn main() {\n    foo().unwrap();\n}\n";
        let findings = vec![make_finding("no-unwrap-in-prod", 2)];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn disable_on_last_line_no_panic() {
        let source = "fn main() {}\n// slopguard-disable-next-line";
        let findings: Vec<Finding> = vec![];
        let result = filter_disabled(findings, source);
        assert!(result.is_empty());
    }

    #[test]
    fn unused_targeted_directive_is_reported() {
        // Directive targets a rule, but no raw finding for that rule lands on the
        // next line: the directive suppresses nothing.
        let source = "fn main() {\n    // slopguard-disable-next-line no-unwrap-in-prod\n    let x = 1;\n}\n";
        let unused = unused_disable_findings(Path::new("test.rs"), source, &[]);
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].rule_id, RuleId::from(UNUSED_DISABLE_RULE_ID));
        assert_eq!(unused[0].line, 2, "anchored on the comment line");
        assert_eq!(unused[0].severity, Severity::Warning);
        assert_eq!(unused[0].category, Category::Slop);
        assert!(unused[0].message.contains("no-unwrap-in-prod"));
    }

    #[test]
    fn used_targeted_directive_is_not_reported() {
        // A raw finding for the targeted rule lands on the next line: used.
        let source = "fn main() {\n    // slopguard-disable-next-line no-unwrap-in-prod\n    foo().unwrap();\n}\n";
        let raw = vec![make_finding("no-unwrap-in-prod", 3)];
        let unused = unused_disable_findings(Path::new("test.rs"), source, &raw);
        assert!(unused.is_empty());
    }

    #[test]
    fn unused_global_directive_is_reported() {
        // Blanket directive with no raw finding on the next line.
        let source = "fn main() {\n    // slopguard-disable-next-line\n    let x = 1;\n}\n";
        let unused = unused_disable_findings(Path::new("test.rs"), source, &[]);
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].line, 2);
        assert!(
            !unused[0].message.contains("for '"),
            "blanket directive message names no rule"
        );
    }

    #[test]
    fn used_global_directive_is_not_reported() {
        let source = "fn main() {\n    // slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let raw = vec![make_finding("no-unwrap-in-prod", 3)];
        let unused = unused_disable_findings(Path::new("test.rs"), source, &raw);
        assert!(unused.is_empty());
    }

    #[test]
    fn targeted_directive_for_other_rule_is_unused() {
        // The directive targets no-expect-in-prod, but the finding on the next
        // line is no-unwrap-in-prod: the directive suppressed nothing.
        let source = "fn main() {\n    // slopguard-disable-next-line no-expect-in-prod\n    foo().unwrap();\n}\n";
        let raw = vec![make_finding("no-unwrap-in-prod", 3)];
        let unused = unused_disable_findings(Path::new("test.rs"), source, &raw);
        assert_eq!(unused.len(), 1);
        assert!(unused[0].message.contains("no-expect-in-prod"));
    }

    #[test]
    fn no_directives_reports_nothing() {
        let source = "fn main() {\n    foo().unwrap();\n}\n";
        let raw = vec![make_finding("no-unwrap-in-prod", 2)];
        assert!(unused_disable_findings(Path::new("test.rs"), source, &raw).is_empty());
    }
}
