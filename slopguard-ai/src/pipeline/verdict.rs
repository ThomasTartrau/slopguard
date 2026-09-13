//! The structured answer the LLM returns for one candidate.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The LLM's structured verdict for one candidate.
///
/// Deriving [`JsonSchema`] lets ironflow generate the output schema from this
/// type (`Agent::output::<AiVerdict>()`), so the schema and the Rust type never
/// drift apart. Deserialization stays defensive (`#[serde(default)]`) because
/// the CLI does not guarantee strict schema conformance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AiVerdict {
    /// Whether the candidate is a real issue.
    pub is_issue: bool,
    /// Human-readable justification. Becomes the finding's `note`.
    #[serde(default)]
    pub reason: String,
    /// Model confidence in `[0.0, 1.0]`. Surfaced as finding metadata only.
    #[serde(default)]
    pub confidence: f64,
}
