//! Import bookkeeping around a removed `Display` impl: which strum macros the
//! file already imports, and which `std::fmt` imports only the impl used.

use std::ops::Range;

use ast_grep_core::{Doc, Node};

use super::super::syntax::{remove_item, replace};
use super::super::RawEdit;

/// Whether the file already imports the derive macro `name` from strum, so the
/// derive can name it bare.
pub(super) fn imports_strum_macro<D: Doc>(node: &Node<'_, D>, name: &str) -> bool {
    node.root().root().dfs().any(|n| {
        if n.kind() != "use_declaration" {
            return false;
        }
        let text = n.text();
        let from_strum = text.contains("strum::") || text.contains("strum_macros::");
        from_strum
            && text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|token| token == name)
    })
}

/// The edit for one `use std::fmt::{...}` list once the unused entries are
/// dropped, `None` when every entry is still used.
fn shrink_list<D: Doc>(
    import: &Node<'_, D>,
    argument: &Node<'_, D>,
    src: &str,
    is_used: &dyn Fn(&str) -> bool,
) -> Option<RawEdit> {
    let path = argument.field("path")?;
    let items: Vec<_> = argument.field("list")?.named_children().collect();
    if !items
        .iter()
        .all(|i| matches!(&*i.kind(), "identifier" | "self"))
    {
        return None;
    }
    let path = path.text();
    let module = path.rsplit("::").next().unwrap_or_default();
    let kept: Vec<String> = items
        .iter()
        .filter(|i| {
            let text = i.text();
            is_used(if i.kind() == "self" { module } else { &text })
        })
        .map(|i| i.text().to_string())
        .collect();
    let range = argument.range();
    match kept.as_slice() {
        [] => Some(remove_item(import, src)),
        k if k.len() == items.len() => None,
        [only] if only == "self" => Some(replace(range.start, range.end, path.to_string())),
        [only] => Some(replace(range.start, range.end, format!("{path}::{only}"))),
        many => Some(replace(
            range.start,
            range.end,
            format!("{path}::{{{}}}", many.join(", ")),
        )),
    }
}

/// Edits removing the `std::fmt` / `core::fmt` imports that only the code in
/// `removed` used, so the rewrite leaves no unused-import warning behind.
/// Imports with aliases or nested lists are left as they are.
pub(super) fn prune_fmt_imports<D: Doc>(
    anchor: &Node<'_, D>,
    src: &str,
    removed: &Range<usize>,
) -> Vec<RawEdit> {
    let root = anchor.root().root();
    let inside_removed =
        |n: &Node<'_, D>| removed.start <= n.range().start && n.range().end <= removed.end;
    // The last segment of a qualified path (`fmt::Formatter`) does not go
    // through an import of that name.
    let is_qualified_name = |n: &Node<'_, D>| {
        n.parent().is_some_and(|p| {
            matches!(&*p.kind(), "scoped_identifier" | "scoped_type_identifier")
                && p.field("name")
                    .is_some_and(|name| name.range() == n.range())
        })
    };
    let is_used = |name: &str| {
        root.dfs().any(|n| {
            matches!(&*n.kind(), "identifier" | "type_identifier")
                && n.text() == name
                && !inside_removed(&n)
                && !is_qualified_name(&n)
                && !n.ancestors().any(|a| a.kind() == "use_declaration")
        })
    };
    let mut edits = Vec::new();
    for import in root
        .dfs()
        .filter(|n| n.kind() == "use_declaration" && !inside_removed(n))
    {
        let Some(argument) = import.field("argument") else {
            continue;
        };
        let text = argument.text();
        if !(text.starts_with("std::fmt") || text.starts_with("core::fmt")) {
            continue;
        }
        match &*argument.kind() {
            "scoped_identifier" => {
                let unused = argument.field("name").is_some_and(|n| !is_used(&n.text()));
                if unused {
                    edits.push(remove_item(&import, src));
                }
            }
            "scoped_use_list" => edits.extend(shrink_list(&import, &argument, src, &is_used)),
            _ => {}
        }
    }
    edits
}
