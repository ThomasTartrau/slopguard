use std::io::{self, Write};
use std::ops::Not;

use serde::Serialize;

use slopguard_core::finding::ScanResult;
use slopguard_core::rule::{Rule, Severity};

use crate::output::write_json_pretty;
use crate::scan_exec::find_rule;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [SarifRun<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule<'a> {
    id: &'a str,
    short_description: SarifMessage<'a>,
    full_description: SarifMessage<'a>,
    default_configuration: SarifDefaultConfiguration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDefaultConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    rule_index: usize,
    level: &'static str,
    message: SarifMessage<'a>,
    locations: [SarifLocation; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    fixes: Option<[SarifFix<'a>; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifResultProperties>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    /// LLM confidence for AI-confirmed findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<f64>,
    /// True when repetition escalation raised this finding's level. Absent
    /// from the JSON when `false`, so plain AST findings keep their shape.
    #[serde(skip_serializing_if = "Not::not")]
    escalated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage<'a> {
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifFix<'a> {
    description: SarifMessage<'a>,
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

/// Format the result as SARIF. The rule metadata (descriptions, default
/// level) comes from the static `rules`, never from a finding: a finding's
/// note can carry third-party text such as a model's reason. A rule absent
/// from `rules` (baseline or unused-disable pseudo rules) falls back to the
/// finding's message.
pub fn format_sarif(result: &ScanResult, rules: &[Rule], w: &mut impl Write) -> io::Result<()> {
    let mut rule_ids: Vec<&str> = Vec::new();
    let mut sarif_rules: Vec<SarifRule<'_>> = Vec::new();

    for finding in &result.findings {
        let id = finding.rule_id.as_str();
        if !rule_ids.contains(&id) {
            rule_ids.push(id);
            let sarif_rule = match find_rule(rules, finding) {
                Some(rule) => SarifRule {
                    id,
                    short_description: SarifMessage {
                        text: &rule.message,
                    },
                    full_description: SarifMessage {
                        text: rule.note.as_deref().unwrap_or(&rule.message),
                    },
                    default_configuration: SarifDefaultConfiguration {
                        level: severity_to_sarif_level(&rule.severity),
                    },
                },
                None => SarifRule {
                    id,
                    short_description: SarifMessage {
                        text: &finding.message,
                    },
                    full_description: SarifMessage {
                        text: &finding.message,
                    },
                    default_configuration: SarifDefaultConfiguration {
                        level: severity_to_sarif_level(&finding.severity),
                    },
                },
            };
            sarif_rules.push(sarif_rule);
        }
    }

    let results: Vec<SarifResult<'_>> = result
        .findings
        .iter()
        .map(|f| {
            let rule_index = rule_ids
                .iter()
                .position(|rid| *rid == f.rule_id.as_str())
                .unwrap_or(0);

            // Emitted only when there is something to say, so a plain AST
            // finding keeps the same shape it had before escalation existed.
            let properties =
                (f.confidence.is_some() || f.escalated).then_some(SarifResultProperties {
                    confidence: f.confidence,
                    escalated: f.escalated,
                });

            SarifResult {
                rule_id: f.rule_id.as_str(),
                rule_index,
                level: severity_to_sarif_level(&f.severity),
                message: SarifMessage { text: &f.message },
                locations: [SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.file.display().to_string(),
                            uri_base_id: "%SRCROOT%",
                        },
                        region: SarifRegion {
                            start_line: f.line,
                            start_column: f.column,
                            end_line: f.end_line,
                            end_column: f.end_column,
                        },
                    },
                }],
                fixes: f.fix.as_deref().map(|fix| {
                    [SarifFix {
                        description: SarifMessage { text: fix },
                    }]
                }),
                properties,
            }
        })
        .collect();

    let sarif = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "slopguard",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/ThomasTartrau/slopguard",
                    rules: sarif_rules,
                },
            },
            results,
        }],
    };

    write_json_pretty(w, &sarif)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{from_slice, from_value, json, to_value, Value};
    use slopguard_core::finding::{Finding, ScanResult, ScanStats};
    use slopguard_core::rule::{Category, Rule, Severity};

    use super::{format_sarif, SarifResultProperties};

    fn rule(note: Option<&str>) -> Rule {
        from_value(json!({
            "id": "demo-rule",
            "language": "rust",
            "severity": "error",
            "message": "static message",
            "note": note,
        }))
        .unwrap()
    }

    fn finding(rule_id: &str, note: Option<&str>) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: Severity::Warning,
            category: Category::Slop,
            message: "finding message".to_string(),
            note: note.map(String::from),
            fix: None,
            file: PathBuf::from("src/lib.rs"),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            matched_text: "x".to_string(),
            confidence: None,
            escalated: false,
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            stats: ScanStats {
                errors: 0,
                warnings: findings.len(),
                total: findings.len(),
                files_scanned: 1,
                baseline_filtered: 0,
                diff_base: None,
                files_changed: None,
            },
            findings,
            cache_stats: None,
        }
    }

    fn sarif_rules(result: &ScanResult, rules: &[Rule]) -> Value {
        let mut out = Vec::new();
        format_sarif(result, rules, &mut out).unwrap();
        let log: Value = from_slice(&out).unwrap();
        log["runs"][0]["tool"]["driver"]["rules"].clone()
    }

    #[test]
    fn sarif_rule_metadata_ignores_finding_note() {
        let scan = result(vec![
            finding("demo-rule", Some("attacker note")),
            finding("demo-rule", None),
        ]);
        let rules = sarif_rules(&scan, &[rule(Some("static note"))]);

        assert_eq!(rules[0]["fullDescription"]["text"], "static note");
        assert_eq!(rules[0]["shortDescription"]["text"], "static message");
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
        assert!(!rules.to_string().contains("attacker note"));
    }

    #[test]
    fn sarif_rule_without_note_uses_message() {
        let scan = result(vec![finding("demo-rule", Some("attacker note"))]);
        let rules = sarif_rules(&scan, &[rule(None)]);

        assert_eq!(rules[0]["fullDescription"]["text"], "static message");
        assert!(!rules.to_string().contains("attacker note"));
    }

    #[test]
    fn sarif_unknown_rule_falls_back_to_message_not_note() {
        let scan = result(vec![finding("pseudo-rule", Some("attacker note"))]);
        let rules = sarif_rules(&scan, &[rule(Some("static note"))]);

        assert_eq!(rules[0]["shortDescription"]["text"], "finding message");
        assert_eq!(rules[0]["fullDescription"]["text"], "finding message");
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "warning");
        assert!(!rules.to_string().contains("attacker note"));
    }

    #[test]
    fn properties_omit_absent_confidence_and_false_escalation() {
        for (confidence, escalated, expected) in [
            (None, false, json!({})),
            (None, true, json!({ "escalated": true })),
            (Some(0.9), false, json!({ "confidence": 0.9 })),
            (
                Some(0.9),
                true,
                json!({ "confidence": 0.9, "escalated": true }),
            ),
        ] {
            let properties = SarifResultProperties {
                confidence,
                escalated,
            };
            assert_eq!(to_value(properties).unwrap(), expected);
        }
    }
}
