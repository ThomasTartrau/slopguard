//! Replace a hand-written enum-to-string `match` with a strum derive.
//!
//! Two shapes are rewritten, both a `match self` whose every arm maps a unit
//! variant to a string literal:
//! - an `impl fmt::Display for Enum`: the impl is removed and the enum derives
//!   strum's `Display` (callers keep `to_string()` and `{}`);
//! - a method returning `&'static str` (`as_str`, `label`, ...): its body
//!   becomes `self.into()` and the enum derives strum's `IntoStaticStr`, so its
//!   callers are untouched.
//!
//! The literals must follow one strum `serialize_all` style (see [`case`]).

use ast_grep_core::{Doc, Node};

use super::syntax::{
    add_derive, attached_prefix, indent_at, insert, is_comment, is_generic, remove_item, replace,
    sibling_item, source_of, Derive,
};
use super::{FixEnv, RawEdit};

mod case;
mod imports;
mod shapes;

use case::infer_style;
use imports::{imports_strum_macro, prune_fmt_imports};
use shapes::{display_pairs, method_pairs};

/// The `serialize_all` style an enum already declares in a `#[strum(...)]`
/// attribute, and whether a strum attribute sits on one of its variants (it
/// would override the derived name).
fn enum_strum_style<D: Doc>(enumeration: &Node<'_, D>, src: &str) -> (Option<String>, bool) {
    let style = attached_prefix(enumeration, src).iter().find_map(|attr| {
        let text = attr.text();
        let rest = text.split_once("serialize_all")?.1;
        let value = rest.split('"').nth(1)?;
        text.contains("strum").then(|| value.to_string())
    });
    let on_variant = enumeration.field("body").is_some_and(|body| {
        body.dfs()
            .any(|n| n.kind() == "attribute_item" && n.text().contains("strum"))
    });
    (style, on_variant)
}

/// strum derives whose strings follow `serialize_all`: adding that attribute
/// to an enum deriving one of them would change what it produces or parses.
const STRING_DERIVES: &[&str] = &[
    "Display",
    "EnumString",
    "AsRefStr",
    "IntoStaticStr",
    "VariantNames",
    "EnumVariantNames",
];

/// Whether `enumeration` already derives one of [`STRING_DERIVES`].
fn derives_strum_strings<D: Doc>(enumeration: &Node<'_, D>, src: &str) -> bool {
    attached_prefix(enumeration, src).iter().any(|attr| {
        let text = attr.text();
        text.contains("derive")
            && text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|token| STRING_DERIVES.contains(&token))
    })
}

/// Whether the enum's variants are all unit variants and exactly the variants
/// of `pairs`, each once.
fn covers_every_variant<D: Doc>(enumeration: &Node<'_, D>, pairs: &[(String, String)]) -> bool {
    let Some(body) = enumeration.field("body") else {
        return false;
    };
    let variants: Vec<_> = body
        .named_children()
        .filter(|c| c.kind() == "enum_variant")
        .collect();
    let all_unit = variants.iter().all(|v| v.field("body").is_none());
    let mut declared: Vec<String> = variants
        .iter()
        .filter_map(|v| v.field("name").map(|n| n.text().to_string()))
        .collect();
    let mut matched: Vec<String> = pairs.iter().map(|(v, _)| v.clone()).collect();
    declared.sort();
    matched.sort();
    all_unit && declared.len() == variants.len() && declared == matched
}

/// The edits making `enumeration` derive `name` with the inferred `style`.
fn derive_edits<D: Doc>(
    enumeration: &Node<'_, D>,
    src: &str,
    env: &FixEnv<'_>,
    name: &str,
    style: Option<&str>,
) -> Option<Vec<RawEdit>> {
    let path = if imports_strum_macro(enumeration, name) {
        name.to_string()
    } else {
        format!("{}::{name}", env.strum_crate?)
    };
    let start = enumeration.range().start;
    let indent = indent_at(src, start);
    let style_attr = style.map(|s| format!("#[strum(serialize_all = \"{s}\")]\n{indent}"));
    let mut edits = Vec::new();
    match add_derive(enumeration, src, &path, name) {
        Derive::Present => edits.extend(style_attr.map(|attr| insert(start, attr))),
        // A new derive line goes where the style attribute does: one insert
        // keeps the derive above the attribute its helper belongs to.
        Derive::Add(edit) if edit.position == start && edit.deleted_length == 0 => {
            let mut text = String::from_utf8(edit.inserted).ok()?;
            text.push_str(&style_attr.unwrap_or_default());
            edits.push(insert(start, text));
        }
        Derive::Add(edit) => {
            edits.push(edit);
            edits.extend(style_attr.map(|attr| insert(start, attr)));
        }
    }
    Some(edits)
}

/// The `(variant, literal)` pairs of `node`, an `impl Display` or an
/// `as_str`-style method, with the impl block holding it.
fn read_pairs<'r, D: Doc>(
    node: &Node<'r, D>,
) -> Option<(Node<'r, D>, String, Vec<(String, String)>)> {
    let is_display = node.kind() == "impl_item";
    let implementation = if is_display {
        node.clone()
    } else {
        node.parent()?.parent()?
    };
    if implementation.kind() != "impl_item" || is_generic(&implementation) {
        return None;
    }
    let ty = implementation.field("type")?;
    if ty.kind() != "type_identifier" {
        return None;
    }
    let enum_name = ty.text().to_string();
    if !is_display {
        let pairs = method_pairs(node, &enum_name)?;
        return Some((implementation, enum_name, pairs));
    }
    let trait_name = implementation.field("trait")?.text().to_string();
    if trait_name.rsplit("::").next() != Some("Display") {
        return None;
    }
    let body = implementation.field("body")?;
    let mut items = body.named_children().filter(|c| !is_comment(c));
    let fmt = items.next()?;
    if items.next().is_some() || fmt.kind() != "function_item" {
        return None;
    }
    let pairs = display_pairs(&fmt, &enum_name)?;
    Some((implementation, enum_name, pairs))
}

pub(super) fn fix<D: Doc>(node: &Node<'_, D>, env: &FixEnv<'_>) -> Option<Vec<RawEdit>> {
    let src = source_of(node);
    let is_display = node.kind() == "impl_item";
    let (implementation, enum_name, pairs) = read_pairs(node)?;

    let enumeration = sibling_item(&implementation, "enum_item", &enum_name)?;
    if is_generic(&enumeration) || !covers_every_variant(&enumeration, &pairs) {
        return None;
    }
    let (existing, on_variant) = enum_strum_style(&enumeration, &src);
    if on_variant {
        return None;
    }
    let style = infer_style(&pairs, existing.as_deref())?;
    if style.is_some() && derives_strum_strings(&enumeration, &src) {
        return None;
    }
    let derive = if is_display {
        "Display"
    } else {
        "IntoStaticStr"
    };
    let mut edits = derive_edits(&enumeration, &src, env, derive, style.as_deref())?;

    if is_display {
        let removal = remove_item(&implementation, &src);
        let removed = removal.position..removal.position + removal.deleted_length;
        edits.extend(prune_fmt_imports(node, &src, &removed));
        edits.push(removal);
    } else {
        let body = node.field("body")?.range();
        let indent = indent_at(&src, node.range().start);
        edits.push(replace(
            body.start,
            body.end,
            format!("{{\n{indent}    self.into()\n{indent}}}"),
        ));
    }
    edits.sort_by_key(|e| e.position);
    let disjoint = edits
        .windows(2)
        .all(|w| w[0].position + w[0].deleted_length <= w[1].position);
    disjoint.then_some(edits)
}
