//! Read the `(variant, literal)` pairs out of the hand-written code shapes the
//! strum fixer rewrites.

use ast_grep_core::{Doc, Node};

use super::super::syntax::is_comment;

/// The content of a plain string literal, `None` for one with escapes or a raw
/// string, whose source text differs from its value.
fn literal_value<D: Doc>(node: &Node<'_, D>) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let mut content = String::new();
    for child in node.named_children() {
        if child.kind() != "string_content" {
            return None;
        }
        content.push_str(&child.text());
    }
    Some(content)
}

/// The single argument of `f.write_str(arg)`.
fn written_str_arg<'r, D: Doc>(call: &Node<'r, D>, f: &str) -> Option<Node<'r, D>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.field("function")?;
    if function.kind() != "field_expression"
        || function.field("value")?.text() != f
        || function.field("field")?.text() != "write_str"
    {
        return None;
    }
    let arguments = call.field("arguments")?;
    let mut args = arguments.named_children();
    let arg = args.next()?;
    args.next().is_none().then_some(arg)
}

/// The literal an arm of a `Display` impl writes to the formatter `f`:
/// `write!(f, "lit")` or `f.write_str("lit")`.
fn written_literal<D: Doc>(value: &Node<'_, D>, f: &str) -> Option<String> {
    if value.kind() == "macro_invocation" {
        if value.field("macro")?.text() != "write" {
            return None;
        }
        let tokens = value.children().find(|c| c.kind() == "token_tree")?;
        let args: Vec<_> = tokens.named_children().collect();
        let [target, literal] = args.as_slice() else {
            return None;
        };
        let text = literal_value(literal)?;
        return (target.text() == f && !text.contains(['{', '}'])).then_some(text);
    }
    literal_value(&written_str_arg(value, f)?)
}

/// The expression a statement holds, unwrapping the statement wrapper
/// tree-sitter puts around a trailing block-like expression.
fn unwrap_statement<'r, D: Doc>(node: Node<'r, D>) -> Node<'r, D> {
    if node.kind() != "expression_statement" {
        return node;
    }
    let inner = node.named_children().next();
    inner.unwrap_or(node)
}

/// The non-comment statements of a function body.
fn body_statements<'r, D: Doc>(function: &Node<'r, D>) -> Option<Vec<Node<'r, D>>> {
    Some(
        function
            .field("body")?
            .named_children()
            .filter(|c| !is_comment(c))
            .collect(),
    )
}

/// Map each arm of `match self` to `(variant, literal)`, reading the literal
/// with `literal_of`. Every arm must name one unit variant through `Self::` or
/// `enum_name::`, without a guard.
fn arm_pairs<D: Doc>(
    matched: &Node<'_, D>,
    enum_name: &str,
    literal_of: impl Fn(&Node<'_, D>) -> Option<String>,
) -> Option<Vec<(String, String)>> {
    if matched.kind() != "match_expression"
        || !matches!(&*matched.field("value")?.text(), "self" | "*self")
    {
        return None;
    }
    let mut pairs = Vec::new();
    for arm in matched.field("body")?.named_children() {
        if is_comment(&arm) {
            continue;
        }
        let pattern = arm.field("pattern")?;
        if pattern.field("condition").is_some() {
            return None;
        }
        let path = pattern.named_children().next()?;
        if path.kind() != "scoped_identifier" {
            return None;
        }
        let qualifier = path.field("path")?.text().to_string();
        if qualifier != "Self" && qualifier != enum_name {
            return None;
        }
        let variant = path.field("name")?.text().to_string();
        pairs.push((variant, literal_of(&arm.field("value")?)?));
    }
    Some(pairs)
}

/// Whether `write` writes the binding `name` to `f` and nothing else:
/// `write!(f, "{name}")`, `write!(f, "{}", name)` or `f.write_str(name)`.
fn writes_binding<D: Doc>(write: &Node<'_, D>, f: &str, name: &str) -> bool {
    if write.kind() == "macro_invocation" {
        let Some(tokens) = write.children().find(|c| c.kind() == "token_tree") else {
            return false;
        };
        let compact: String = tokens.text().split_whitespace().collect();
        let is_write = write.field("macro").is_some_and(|m| m.text() == "write");
        return is_write
            && (compact == format!("({f},\"{{{name}}}\")")
                || compact == format!("({f},\"{{}}\",{name})"));
    }
    written_str_arg(write, f).is_some_and(|arg| arg.text() == name)
}

/// The literals a `Display::fmt` body writes per variant, for three shapes: a
/// `match` writing in each arm, `f.write_str(match ...)`, and `let s = match
/// ...;` followed by a write of `s`.
pub(super) fn display_pairs<D: Doc>(
    fmt: &Node<'_, D>,
    enum_name: &str,
) -> Option<Vec<(String, String)>> {
    let formatter = fmt
        .field("parameters")?
        .named_children()
        .find(|p| p.kind() == "parameter")?
        .field("pattern")?
        .text()
        .to_string();
    let f = formatter.as_str();
    match body_statements(fmt)?.as_slice() {
        [single] => {
            let single = unwrap_statement(single.clone());
            if single.kind() == "match_expression" {
                return arm_pairs(&single, enum_name, |v| written_literal(v, f));
            }
            arm_pairs(&written_str_arg(&single, f)?, enum_name, literal_value)
        }
        [binding, write] => {
            if binding.kind() != "let_declaration" {
                return None;
            }
            let name = binding.field("pattern")?.text().to_string();
            if !writes_binding(&unwrap_statement(write.clone()), f, &name) {
                return None;
            }
            arm_pairs(&binding.field("value")?, enum_name, literal_value)
        }
        _ => None,
    }
}

/// The literals an `as_str`-style method returns per variant: a method taking
/// only `self` or `&self`, returning `&'static str` or `&str`, whose body is a
/// `match self` of string literals. A `const fn` is left alone: `self.into()`
/// is not const.
pub(super) fn method_pairs<D: Doc>(
    method: &Node<'_, D>,
    enum_name: &str,
) -> Option<Vec<(String, String)>> {
    let params: String = method
        .field("parameters")?
        .text()
        .split_whitespace()
        .collect();
    let returns: String = method
        .field("return_type")?
        .text()
        .split_whitespace()
        .collect();
    let is_const = method
        .children()
        .any(|c| c.kind() == "function_modifiers" && c.text().contains("const"));
    if !matches!(params.as_str(), "(&self)" | "(self)")
        || !matches!(returns.as_str(), "&'staticstr" | "&str")
        || is_const
    {
        return None;
    }
    let [single] = <[_; 1]>::try_from(body_statements(method)?).ok()?;
    arm_pairs(&unwrap_statement(single), enum_name, literal_value)
}
