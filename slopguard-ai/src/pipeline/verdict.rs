//! The structured answer the LLM returns for one candidate.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest `reason` kept, in characters. Longer model output is truncated.
pub(crate) const MAX_REASON_CHARS: usize = 500;

/// Why a model verdict was rejected.
#[derive(Debug, Error, PartialEq)]
pub(crate) enum VerdictError {
    /// The confidence is NaN, infinite or outside `[0.0, 1.0]`.
    #[error("confidence {0} is outside [0.0, 1.0]")]
    ConfidenceOutOfRange(f64),
}

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

impl AiVerdict {
    /// Check and sanitize a verdict coming from the model or the cache.
    ///
    /// The confidence must lie in `[0.0, 1.0]` (NaN and infinities fail). The
    /// reason loses its control characters first, then is cut to
    /// [`MAX_REASON_CHARS`] characters.
    pub(crate) fn validated(self) -> Result<Self, VerdictError> {
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(VerdictError::ConfidenceOutOfRange(self.confidence));
        }
        let reason = self
            .reason
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_REASON_CHARS)
            .collect();
        Ok(Self { reason, ..self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(reason: &str, confidence: f64) -> AiVerdict {
        AiVerdict {
            is_issue: true,
            reason: reason.to_string(),
            confidence,
        }
    }

    #[test]
    fn out_of_range_and_non_finite_confidence_is_rejected() {
        for confidence in [1.5, -0.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                verdict("r", confidence).validated().is_err(),
                "confidence {confidence} must be rejected"
            );
        }
    }

    #[test]
    fn boundary_confidence_is_accepted() {
        for confidence in [0.0, 1.0] {
            assert!(verdict("r", confidence).validated().is_ok());
        }
    }

    #[test]
    fn control_characters_are_stripped_from_reason() {
        let validated = verdict("a\nb\x1bc\0d", 0.5).validated().unwrap();
        assert_eq!(validated.reason, "abcd");
    }

    #[test]
    fn all_control_reason_becomes_empty() {
        let validated = verdict("\n\x1b\0", 0.5).validated().unwrap();
        assert_eq!(validated.reason, "");
    }

    #[test]
    fn long_reason_is_truncated_by_chars() {
        let validated = verdict(&"\u{e9}".repeat(600), 0.5).validated().unwrap();
        assert_eq!(validated.reason.chars().count(), MAX_REASON_CHARS);
    }
}
