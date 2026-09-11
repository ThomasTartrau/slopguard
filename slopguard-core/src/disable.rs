use crate::finding::Finding;

const DISABLE_MARKER: &str = "slopguard-disable-next-line";

struct DisableDirective {
    target_line: usize,
    rule_id: Option<String>,
}

fn parse_directives(source: &str) -> Vec<DisableDirective> {
    source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let rest = line.trim().strip_prefix("//")?.trim().strip_prefix(DISABLE_MARKER)?;
            let rest = rest.trim();
            Some(DisableDirective {
                target_line: idx + 2,
                rule_id: (!rest.is_empty()).then(|| rest.to_string()),
            })
        })
        .collect()
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
                    && d.rule_id
                        .as_ref()
                        .is_none_or(|id| id == &finding.rule_id)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::finding::Finding;
    use crate::rule::{Category, Severity};

    use super::filter_disabled;

    fn make_finding(rule_id: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
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
        assert!(result.is_empty(), "all findings on the disabled line should be suppressed");
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
        assert_eq!(result[0].rule_id, "other-rule");
    }

    #[test]
    fn disable_with_unknown_rule_id_suppresses_nothing() {
        let source = "fn main() {\n    // slopguard-disable-next-line nonexistent-rule\n    foo().unwrap();\n}\n";
        let findings = vec![make_finding("no-unwrap-in-prod", 3)];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "no-unwrap-in-prod");
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
        let source_no_space = "fn main() {\n    //slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings1 = vec![make_finding("no-unwrap-in-prod", 3)];
        assert!(filter_disabled(findings1, source_no_space).is_empty());

        let source_extra_spaces = "fn main() {\n    //  slopguard-disable-next-line\n    foo().unwrap();\n}\n";
        let findings2 = vec![make_finding("no-unwrap-in-prod", 3)];
        assert!(filter_disabled(findings2, source_extra_spaces).is_empty());

        let source_leading_space = "fn main() {\n      // slopguard-disable-next-line\n    foo().unwrap();\n}\n";
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
        let source = "fn main() {\n    // slopguard-disable-next-line rule-b\n    foo().unwrap();\n}\n";
        let findings = vec![
            make_finding("rule-a", 3),
            make_finding("rule-b", 3),
            make_finding("rule-c", 3),
        ];
        let result = filter_disabled(findings, source);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].rule_id, "rule-a");
        assert_eq!(result[1].rule_id, "rule-c");
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
}
