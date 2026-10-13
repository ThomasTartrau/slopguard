//! Post-match filters for AST rules whose exemption cannot be written in
//! ast-grep YAML. A filter sees the matched node and drops a match that is a
//! known false positive; the rule YAML stays the single source of what matches.

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::Node;
use ast_grep_language::SupportLang;

type RustNode<'a> = Node<'a, StrDoc<SupportLang>>;

/// Whether the match of rule `rule_id` on `node` is a false positive to drop.
/// Rules without a filter are never dropped.
pub(crate) fn is_false_positive(rule_id: &str, node: &RustNode<'_>) -> bool {
    match rule_id {
        "no-trivial-function" => trivial_function_is_benign(node),
        _ => false,
    }
}

/// Whether `node` is a comment.
fn is_comment(node: &RustNode<'_>) -> bool {
    matches!(&*node.kind(), "line_comment" | "block_comment")
}

/// The text of `node` with surrounding whitespace removed.
fn trimmed_text(node: &RustNode<'_>) -> String {
    node.text().trim().to_string()
}

/// Whether a function the `no-trivial-function` rule matched does real work:
/// a getter named like the field it reads, or a call that adds or derives an
/// argument (its arguments differ from its parameters). Anything unforeseen is
/// not benign, so the finding is kept.
fn trivial_function_is_benign(fn_item: &RustNode<'_>) -> bool {
    let Some(body) = fn_item.field("body") else {
        return false;
    };
    let mut exprs = body
        .children()
        .filter(|child| child.is_named() && !is_comment(child));
    let (Some(expr), None) = (exprs.next(), exprs.next()) else {
        return false;
    };
    if &*expr.kind() == "call_expression" {
        return call_changes_arguments(fn_item, &expr);
    }
    is_named_getter(fn_item, &expr)
}

/// Whether `expr` reads `self.<field>` (optionally borrowed) where `<field>` is
/// the name of the function.
fn is_named_getter(fn_item: &RustNode<'_>, expr: &RustNode<'_>) -> bool {
    let inner = if &*expr.kind() == "reference_expression" {
        let Some(value) = expr.field("value") else {
            return false;
        };
        value
    } else {
        expr.clone()
    };
    if &*inner.kind() != "field_expression" {
        return false;
    }
    let (Some(value), Some(field), Some(name)) = (
        inner.field("value"),
        inner.field("field"),
        fn_item.field("name"),
    ) else {
        return false;
    };
    trimmed_text(&value) == "self" && trimmed_text(&field) == trimmed_text(&name)
}

/// The names a function binds, in order: `self` for a self parameter, the
/// pattern text (without `mut`) for a plain parameter. `None` on any other
/// parameter shape.
fn parameter_names(fn_item: &RustNode<'_>) -> Option<Vec<String>> {
    let parameters = fn_item.field("parameters")?;
    parameters
        .children()
        .filter(|child| child.is_named() && !is_comment(child))
        .map(|param| match &*param.kind() {
            "self_parameter" => Some("self".to_string()),
            "parameter" => {
                let pattern = trimmed_text(&param.field("pattern")?);
                let name = pattern.strip_prefix("mut ").unwrap_or(&pattern);
                Some(name.trim_start().to_string())
            }
            _ => None,
        })
        .collect()
}

/// The call's arguments with borrows and dereferences stripped, so `&mut x` and
/// `*x` compare equal to the parameter `x`.
fn argument_names(call: &RustNode<'_>) -> Option<Vec<String>> {
    let arguments = call.field("arguments")?;
    Some(
        arguments
            .children()
            .filter(|child| child.is_named() && !is_comment(child))
            .map(|arg| {
                let text = trimmed_text(&arg);
                let text = text.strip_prefix("&mut ").unwrap_or(&text);
                text.trim_start_matches(['&', '*']).trim_start().to_string()
            })
            .collect(),
    )
}

/// Whether the call's arguments differ from the function's parameters, i.e. the
/// function is not a pure forward. A call through a non-identifier is kept.
fn call_changes_arguments(fn_item: &RustNode<'_>, call: &RustNode<'_>) -> bool {
    let is_plain_call = call
        .field("function")
        .is_some_and(|function| &*function.kind() == "identifier");
    if !is_plain_call {
        return false;
    }
    match (parameter_names(fn_item), argument_names(call)) {
        (Some(params), Some(args)) => params != args,
        _ => false,
    }
}
