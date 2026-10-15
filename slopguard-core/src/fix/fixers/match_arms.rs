//! Merge two adjacent match arms with the same body: `A => x, B => x` becomes
//! `A | B => x`. Adjacency keeps the first-match order, so the merged arm is
//! taken exactly when one of the two was.

use ast_grep_core::{Doc, Node};

use super::syntax::{replace, source_of};
use super::RawEdit;

/// Whether a match pattern binds a variable: an or-pattern requires every
/// alternative to bind the same names with the same types, which cannot be
/// checked without type information.
fn binds_variables<D: Doc>(pattern: &Node<'_, D>) -> bool {
    pattern.dfs().any(|node| match &*node.kind() {
        "captured_pattern"
        | "mut_pattern"
        | "ref_pattern"
        | "shorthand_field_identifier"
        | "macro_invocation" => true,
        "identifier" => {
            let is_path = node.parent().is_some_and(|p| {
                matches!(&*p.kind(), "scoped_identifier" | "scoped_type_identifier")
                    || p.field("type").is_some_and(|t| t.range() == node.range())
            });
            !is_path
                && node
                    .text()
                    .starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        }
        _ => false,
    })
}

/// The pattern of an arm that can join an or-pattern: no guard, no binding, no
/// attribute, not the `_` catch-all (`A | _` is just `_`, and clippy flags it).
fn mergeable_pattern<'r, D: Doc>(arm: &Node<'r, D>) -> Option<Node<'r, D>> {
    if arm.kind() != "match_arm" || arm.text().starts_with('#') {
        return None;
    }
    let pattern = arm.field("pattern")?;
    let is_wildcard = pattern.text().split('|').any(|alt| alt.trim() == "_");
    if is_wildcard || pattern.field("condition").is_some() || binds_variables(&pattern) {
        return None;
    }
    Some(pattern)
}

/// Collapse whitespace so two bodies compare by tokens, not layout.
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Merge `first` with the arm right after it. The merged arm keeps the second
/// arm's body and separator, so the edit only replaces the first arm with its
/// pattern followed by ` | `.
pub(super) fn fix<D: Doc>(first: &Node<'_, D>) -> Option<Vec<RawEdit>> {
    let second = first.next()?;
    let first_pattern = mergeable_pattern(first)?;
    mergeable_pattern(&second)?;
    let body = |arm: &Node<'_, D>| arm.field("value").map(|v| normalized(&v.text()));
    if body(first)? != body(&second)? {
        return None;
    }
    let src = source_of(first);
    let (start, end) = (first.range().start, second.range().start);
    if !src[first.range().end..end].trim().is_empty() {
        return None;
    }
    Some(vec![replace(
        start,
        end,
        format!("{} | ", first_pattern.text()),
    )])
}
