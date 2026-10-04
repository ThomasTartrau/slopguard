//! AI analysis pipeline for slopguard.
//!
//! This crate turns `ai_check` rules into findings: the AST layer pre-filters
//! candidates, then an LLM confirms each one. It owns provider construction,
//! prompt rendering, the confirmation pipeline, and the verdict cache.
//!
//! `slopguard-core` (the AST layer) does not depend on this crate; the CLI
//! orchestrates the AST phase then the AI phase.

pub mod cache;
pub mod pipeline;
pub mod provider;

pub use cache::{cache_key, AiCache};
pub use pipeline::{cap_candidates, run_ai_pass, AiCandidate, AiVerdict, DEFAULT_MODEL};
pub use provider::{build_provider, provider_kind, ProviderError, ProviderKind};

#[cfg(feature = "provider-typesafe")]
pub use pipeline::classifier::{
    build_classifier, resolve_jev_model, run_classifier_pass, BatchConfig, ClassifierError,
};
