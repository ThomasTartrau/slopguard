//! Bare-name helpers: the cross-file index matches traits and types by their
//! last path segment, not through a real Rust path resolver.

use ast_grep_core::{Doc, Node};

/// The bare name a trait reference resolves to: the last path segment with any
/// generic arguments stripped. `fmt::Display` -> `Display`, `From<u32>` ->
/// `From`, `crate::db::Repo` -> `Repo`. Matching is by bare name, not by a
/// real Rust path resolver.
pub(super) fn bare_trait_name(text: &str) -> String {
    let base = text.split('<').next().unwrap_or(text);
    base.rsplit("::").next().unwrap_or(base).trim().to_string()
}

/// The bare name of an implementing type: references, lifetimes, `mut` and
/// `dyn` stripped, then the same last-segment rule as [`bare_trait_name`].
/// `&'a mut http::Request<B>` -> `Request`.
pub(super) fn bare_type_name(text: &str) -> String {
    let mut rest = text.trim();
    loop {
        let stripped = rest.trim_start_matches('&').trim_start();
        let stripped = match stripped.strip_prefix('\'') {
            Some(after) => after
                .trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
                .trim_start(),
            None => stripped,
        };
        let stripped = ["mut ", "dyn "]
            .iter()
            .find_map(|kw| stripped.strip_prefix(kw))
            .unwrap_or(stripped)
            .trim_start();
        if stripped == rest {
            return bare_trait_name(rest);
        }
        rest = stripped;
    }
}

/// The names of an impl's own generic parameters, used to recognise a blanket
/// impl. Lifetimes and const parameters are skipped: only a plain type
/// parameter can be the implementing type of a blanket impl.
pub(super) fn generic_param_names<D: Doc>(impl_node: &Node<D>) -> Vec<String> {
    let Some(params) = impl_node.field("type_parameters") else {
        return Vec::new();
    };
    params
        .children()
        .filter(|child| child.is_named())
        .filter_map(|child| {
            let text = child.text().to_string();
            // `T: Clone` and `T = u32` keep their head; `'a` and
            // `const N: usize` do not survive the shape check below.
            let head = text
                .split([':', '=', '<'])
                .next()
                .unwrap_or(&text)
                .trim()
                .to_string();
            let starts_ok = head.starts_with(|c: char| c.is_alphabetic() || c == '_');
            let rest_ok = head.chars().all(|c| c.is_alphanumeric() || c == '_');
            (starts_ok && rest_ok).then_some(head)
        })
        .collect()
}

/// The last `::`-separated segment of a macro or path name.
pub(super) fn last_segment(text: &str) -> &str {
    text.rsplit("::").next().unwrap_or(text).trim()
}
