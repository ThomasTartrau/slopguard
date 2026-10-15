//! Builtin fixers: rewrites a single ast-grep template cannot express, because
//! they edit several nodes at once (an enum's derive list and the impl it
//! replaces, two adjacent match arms) or read another file (the module a glob
//! re-export points at).
//!
//! A fixer receives one detection match and returns every edit of its rewrite,
//! applied together or not at all. It returns `None` whenever it cannot prove
//! the rewrite compiles and preserves behavior: the finding then stays reported
//! and the code untouched.

use std::path::Path;

use ast_grep_core::{Doc, NodeMatch};
use serde::{Deserialize, Serialize};
use strum::Display;

use super::RawEdit;

mod derive_clone;
mod match_arms;
mod reexport;
mod strum_str;
mod syntax;

/// Builtin fixers a rule can name in its `fixer` field. Builtin only: a custom
/// YAML may reuse one, never define a new one, so an unknown name is a parse
/// error.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FixerKind {
    /// Replace a hand-written enum-to-string `match` (a `Display` impl or an
    /// `as_str`-style method) with a strum derive.
    StrumEnumStr,
    /// Merge two adjacent match arms with the same body into one `A | B` arm.
    MergeMatchArms,
    /// Expand `pub use module::*;` into the explicit list of what it exports.
    ExplicitReexport,
    /// Replace a field-by-field `impl Clone` with `#[derive(Clone)]`.
    DeriveClone,
}

/// What a fixer may consult beyond the matched node.
pub(super) struct FixEnv<'a> {
    /// The file being fixed, `None` for an in-memory snippet (`slopguard
    /// test`): a fixer that needs another file then gives up.
    pub path: Option<&'a Path>,
    /// The crate the strum derive macros are reachable through for this file
    /// (`strum` with its `derive` feature, or `strum_macros`), `None` when the
    /// governing `Cargo.toml` declares neither.
    pub strum_crate: Option<&'a str>,
}

/// Compute the edits of `kind` for one detection match, or `None` when the
/// rewrite cannot be proven correct.
pub(super) fn fix<D: Doc>(
    kind: FixerKind,
    node_match: &NodeMatch<'_, D>,
    env: &FixEnv<'_>,
) -> Option<Vec<RawEdit>> {
    let node = node_match.get_node();
    match kind {
        FixerKind::StrumEnumStr => strum_str::fix(node, env),
        FixerKind::MergeMatchArms => match_arms::fix(node),
        FixerKind::ExplicitReexport => reexport::fix(node, env),
        FixerKind::DeriveClone => derive_clone::fix(node),
    }
}

#[cfg(test)]
mod tests;
