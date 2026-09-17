use std::io::{self, Write};

use serde::Serialize;

use slopguard_core::finding::ScanResult;
use slopguard_core::rule::Severity;

use crate::output::write_json_pretty;

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
    /// True when repetition escalation raised this finding's level.
    #[serde(skip_serializing_if = "is_false")]
    escalated: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
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

pub fn format_sarif(result: &ScanResult, w: &mut impl Write) -> io::Result<()> {
    let mut rules_map: Vec<(&str, &str, &str)> = Vec::new();
    let mut rules: Vec<SarifRule<'_>> = Vec::new();

    for finding in &result.findings {
        let id = finding.rule_id.as_str();
        if !rules_map.iter().any(|(rid, _, _)| *rid == id) {
            let desc = finding.note.as_deref().unwrap_or(&finding.message);
            rules_map.push((id, &finding.message, desc));
            rules.push(SarifRule {
                id,
                short_description: SarifMessage {
                    text: &finding.message,
                },
                full_description: SarifMessage { text: desc },
                default_configuration: SarifDefaultConfiguration {
                    level: severity_to_sarif_level(&finding.severity),
                },
            });
        }
    }

    let results: Vec<SarifResult<'_>> = result
        .findings
        .iter()
        .map(|f| {
            let rule_index = rules_map
                .iter()
                .position(|(rid, _, _)| *rid == f.rule_id.as_str())
                .unwrap_or(0);

            // Emitted only when there is something to say, so a plain AST
            // finding keeps the same shape it had before escalation existed.
            let properties = if f.confidence.is_some() || f.escalated {
                Some(SarifResultProperties {
                    confidence: f.confidence,
                    escalated: f.escalated,
                })
            } else {
                None
            };

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
                    rules,
                },
            },
            results,
        }],
    };

    write_json_pretty(w, &sarif)
}
