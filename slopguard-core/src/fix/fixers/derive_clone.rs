//! Replace a field-by-field `impl Clone` with `#[derive(Clone)]`.
//!
//! The derive clones every field in declaration order, which is what an impl
//! made only of `field: self.field.clone()` (or `self.field` for a `Copy`
//! field) does. A generic struct is left alone: the derive would add a
//! `T: Clone` bound the manual impl may not have.

use ast_grep_core::{Doc, Node};

use super::syntax::{
    add_derive, attached_prefix, is_comment, is_generic, remove_item, sibling_item, source_of,
    Derive,
};
use super::RawEdit;

/// Whether `value` is `self.<field>` or `self.<field>.clone()`.
fn copies_field<D: Doc>(value: &Node<'_, D>, field: &str) -> bool {
    let text = value.text();
    let access = text.strip_suffix(".clone()").unwrap_or(&text);
    access.strip_prefix("self.") == Some(field)
}

/// Whether the body of `clone` rebuilds every field of `fields_list` from the
/// same field of `self`, and nothing else.
fn rebuilds_every_field<D: Doc>(expression: &Node<'_, D>, fields_list: &Node<'_, D>) -> bool {
    match (&*expression.kind(), &*fields_list.kind()) {
        ("struct_expression", "field_declaration_list") => {
            let Some(body) = expression.field("body") else {
                return false;
            };
            let initializers: Vec<_> = body.named_children().filter(|c| !is_comment(c)).collect();
            let declared = fields_list
                .named_children()
                .filter(|c| c.kind() == "field_declaration")
                .count();
            initializers.len() == declared
                && initializers.iter().all(|init| {
                    init.kind() == "field_initializer"
                        && init.field("field").is_some_and(|name| {
                            init.field("value")
                                .is_some_and(|v| copies_field(&v, &name.text()))
                        })
                })
        }
        ("call_expression", "ordered_field_declaration_list") => {
            let Some(arguments) = expression.field("arguments") else {
                return false;
            };
            let arguments: Vec<_> = arguments.named_children().collect();
            let declared = fields_list
                .named_children()
                .filter(|c| {
                    !is_comment(c)
                        && !matches!(&*c.kind(), "attribute_item" | "visibility_modifier")
                })
                .count();
            arguments.len() == declared
                && arguments
                    .iter()
                    .enumerate()
                    .all(|(i, arg)| copies_field(arg, &i.to_string()))
        }
        _ => false,
    }
}

/// The single expression a function body evaluates to, `None` when the body
/// holds anything else.
fn sole_expression<'r, D: Doc>(function: &Node<'r, D>) -> Option<Node<'r, D>> {
    let body = function.field("body")?;
    let mut children = body.named_children();
    let expression = children.next()?;
    children.next().is_none().then_some(expression)
}

/// Whether `node` is a doc comment (`///`, `/**`) or a `#[doc]` attribute.
fn is_doc<D: Doc>(node: &Node<'_, D>) -> bool {
    let text = node.text();
    text.starts_with("///") || text.starts_with("/**") || text.replace(' ', "").starts_with("#[doc")
}

pub(super) fn fix<D: Doc>(implementation: &Node<'_, D>) -> Option<Vec<RawEdit>> {
    let src = source_of(implementation);
    // A documented impl explains its clone semantics in rustdoc, which the
    // derive would drop.
    let documented = attached_prefix(implementation, &src).iter().any(is_doc)
        || implementation.dfs().any(|n| is_comment(&n) && is_doc(&n));
    if documented || is_generic(implementation) {
        return None;
    }
    let ty = implementation.field("type")?;
    if ty.kind() != "type_identifier" {
        return None;
    }
    let items = implementation.field("body")?;
    let mut functions = items.named_children().filter(|c| !is_comment(c));
    let clone_fn = functions.next()?;
    if functions.next().is_some()
        || clone_fn.kind() != "function_item"
        || clone_fn.field("name")?.text() != "clone"
    {
        return None;
    }
    let structure = sibling_item(implementation, "struct_item", &ty.text())?;
    if is_generic(&structure) {
        return None;
    }
    let fields = structure.field("body")?;
    if !rebuilds_every_field(&sole_expression(&clone_fn)?, &fields) {
        return None;
    }
    let Derive::Add(derive) = add_derive(&structure, &src, "Clone", "Clone") else {
        return None;
    };
    Some(vec![derive, remove_item(implementation, &src)])
}
