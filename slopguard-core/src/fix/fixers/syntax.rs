//! Source helpers shared by the fixers: item boundaries, indentation, derive
//! lists. Offsets are byte offsets into the file's source.

use std::borrow::Cow;

use ast_grep_core::{Doc, Node};

use super::RawEdit;

/// The full source text of the file `node` belongs to.
pub(super) fn source_of<'r, D: Doc>(node: &Node<'r, D>) -> Cow<'r, str> {
    node.root().root().text()
}

/// An edit replacing `start..end` with `text`.
pub(super) fn replace(start: usize, end: usize, text: impl Into<String>) -> RawEdit {
    RawEdit {
        position: start,
        deleted_length: end - start,
        inserted: text.into().into_bytes(),
    }
}

/// An edit inserting `text` at `position`.
pub(super) fn insert(position: usize, text: impl Into<String>) -> RawEdit {
    replace(position, position, text)
}

/// Byte offset of the start of the line holding `pos`.
pub(super) fn line_start(src: &str, pos: usize) -> usize {
    src[..pos].rfind('\n').map_or(0, |i| i + 1)
}

/// The whitespace indentation of the line holding `pos`.
pub(super) fn indent_at(src: &str, pos: usize) -> &str {
    let line = &src[line_start(src, pos)..];
    let width = line.len() - line.trim_start_matches([' ', '\t']).len();
    &line[..width]
}

/// Byte offset of the start of the line after the one holding `pos` (the end
/// of the source on the last line).
fn next_line_start(src: &str, pos: usize) -> usize {
    if pos > 0 && src.as_bytes()[pos - 1] == b'\n' {
        return pos;
    }
    src[pos..].find('\n').map_or(src.len(), |i| pos + i + 1)
}

/// The attributes and comments written directly above `item`, nearest first:
/// each sits alone on its lines with no blank line before the next one.
pub(super) fn attached_prefix<'r, D: Doc>(item: &Node<'r, D>, src: &str) -> Vec<Node<'r, D>> {
    let mut attached = Vec::new();
    let mut below = item.range().start;
    let mut current = item.prev();
    while let Some(prev) = current {
        if !matches!(
            &*prev.kind(),
            "attribute_item" | "line_comment" | "block_comment"
        ) {
            break;
        }
        let range = prev.range();
        let alone = src[line_start(src, range.start)..range.start]
            .trim()
            .is_empty();
        let adjacent = next_line_start(src, range.end) == line_start(src, below);
        if !alone || !adjacent {
            break;
        }
        below = range.start;
        current = prev.prev();
        attached.push(prev);
    }
    attached
}

/// The byte range removing the item spanning `start..end` together with the
/// lines it occupies. When a blank line precedes it, the blank line that would
/// be left over (the next one, or the preceding one at the end of a file or
/// block) goes too.
pub(super) fn removal_range(src: &str, start: usize, end: usize) -> (usize, usize) {
    let first_line = line_start(src, start);
    let mut start = if src[first_line..start].trim().is_empty() {
        first_line
    } else {
        start
    };
    let rest_of_line = &src[end..next_line_start(src, end)];
    let mut end = if rest_of_line.trim().is_empty() {
        end + rest_of_line.len()
    } else {
        end
    };
    let blank_before = start == 0 || src[..start].ends_with("\n\n");
    let following_end = src[end..].find('\n').map_or(src.len(), |i| end + i + 1);
    let following = &src[end..following_end];
    if blank_before && !following.is_empty() && following.trim().is_empty() {
        end += following.len();
    } else if blank_before
        && start > 0
        && (following.is_empty() || following.trim_start().starts_with('}'))
    {
        start -= 1;
    }
    (start, end)
}

/// The edit removing `item`, its attached attributes and comments, and its
/// lines.
pub(super) fn remove_item<D: Doc>(item: &Node<'_, D>, src: &str) -> RawEdit {
    let start = attached_prefix(item, src)
        .last()
        .map_or(item.range().start, |first| first.range().start);
    let (start, end) = removal_range(src, start, item.range().end);
    replace(start, end, "")
}

/// The `derive(...)` argument list of an attribute item, `None` for any other
/// attribute.
fn derive_arguments<'r, D: Doc>(attribute_item: &Node<'r, D>) -> Option<Node<'r, D>> {
    let attribute = attribute_item
        .children()
        .find(|c| c.kind() == "attribute")?;
    let name = attribute.children().find(|c| c.kind() == "identifier")?;
    if name.text() != "derive" {
        return None;
    }
    attribute.field("arguments")
}

/// Whether the derive list text `list` (with its parentheses) names `name`,
/// bare or through any path.
fn derive_list_names(list: &str, name: &str) -> bool {
    list.trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
        .map(str::trim)
        .any(|entry| entry == name || entry.rsplit("::").next() == Some(name))
}

/// How to make `item` derive a trait.
pub(super) enum Derive {
    /// The item already derives it: nothing to add.
    Present,
    /// The edit adding it.
    Add(RawEdit),
}

/// Make `item` derive `path` (whose last segment is `name`): append it to the
/// item's first `#[derive(...)]`, or add a `#[derive(path)]` line just above
/// the item, below its other attributes.
pub(super) fn add_derive<D: Doc>(item: &Node<'_, D>, src: &str, path: &str, name: &str) -> Derive {
    let lists: Vec<_> = attached_prefix(item, src)
        .iter()
        .rev()
        .filter_map(derive_arguments)
        .collect();
    if lists
        .iter()
        .any(|list| derive_list_names(&list.text(), name))
    {
        return Derive::Present;
    }
    let Some(list) = lists.first() else {
        let start = item.range().start;
        let indent = indent_at(src, start);
        return Derive::Add(insert(start, format!("#[derive({path})]\n{indent}")));
    };
    let range = list.range();
    // Inside the parentheses, after the last entry (and its trailing comma).
    let inner = &src[range.start + 1..range.end - 1];
    let content = inner.trim_end();
    let separator = if content.trim().is_empty() {
        ""
    } else if content.ends_with(',') {
        " "
    } else {
        ", "
    };
    Derive::Add(insert(
        range.start + 1 + content.len(),
        format!("{separator}{path}"),
    ))
}

/// The item named `name` of kind `kind` declared next to `anchor` (in the same
/// file and module), when exactly one exists.
pub(super) fn sibling_item<'r, D: Doc>(
    anchor: &Node<'r, D>,
    kind: &str,
    name: &str,
) -> Option<Node<'r, D>> {
    let scope = anchor.parent()?;
    let mut found = scope
        .children()
        .filter(|item| item.kind() == kind && item.field("name").is_some_and(|n| n.text() == name));
    let item = found.next()?;
    found.next().is_none().then_some(item)
}

/// Whether `node` is a line or block comment.
pub(super) fn is_comment<D: Doc>(node: &Node<'_, D>) -> bool {
    matches!(&*node.kind(), "line_comment" | "block_comment")
}

/// Whether `node` carries a `type_parameters` or `where_clause` child.
pub(super) fn is_generic<D: Doc>(node: &Node<'_, D>) -> bool {
    node.children()
        .any(|c| matches!(&*c.kind(), "type_parameters" | "where_clause"))
}
