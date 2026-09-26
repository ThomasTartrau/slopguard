//! The assertion-free-test analysis. A `#[test]` that checks nothing itself is
//! reported unless it calls, directly or through other helpers, test code that
//! asserts. Helpers are matched by bare name across the whole project, so a
//! shared test helper (`tests/common/mod.rs`, a `*-test-support` crate) is seen.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ast_grep_core::{Doc, Node};
use serde::{Deserialize, Serialize};

use super::names::last_segment;
use super::test_support::SupportCrates;
use super::DeclFilter;
use crate::finding::Finding;
use crate::rule::Rule;
use crate::test_filter::CfgTestRanges;

/// Macros whose `name![..]` form is an inline snapshot: the expected value
/// handed to a checking helper (snapbox `str![]`, expect-test `expect![]`).
const SNAPSHOT_MACROS: &[&str] = &["str", "expect", "expect_file", "file"];

/// Body statements the compiler checks just by building the test. A test made
/// only of these (plus typed `let _: T = ..` bindings) is a compile-time check.
const COMPILE_ONLY_KINDS: &[&str] = &[
    "struct_item",
    "enum_item",
    "union_item",
    "impl_item",
    "trait_item",
    "function_item",
    "type_item",
    "const_item",
    "static_item",
    "use_declaration",
    "mod_item",
    "macro_definition",
];

/// Body children that neither check nor declare anything.
const NEUTRAL_KINDS: &[&str] = &[
    "attribute_item",
    "inner_attribute_item",
    "line_comment",
    "block_comment",
    "empty_statement",
];

/// A function or `macro_rules!` macro a test may delegate its checks to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestHelper {
    pub name: String,
    /// Checks something on its own: `assert`/`panic`, `?`, `.unwrap()` /
    /// `.expect()`, or an inline snapshot.
    pub asserts: bool,
    /// Bare names of the functions, methods and macros it calls, sorted and
    /// deduplicated.
    pub calls: Vec<String>,
    /// The helper sits inside a `#[cfg(test)]` item.
    pub in_cfg_test: bool,
}

/// A test function that checks nothing on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassertedTest {
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    /// The whole function, reported as `matched_text` like the former AST rule
    /// did, so existing baseline entries still match.
    pub text: String,
    /// Bare names of everything the test calls, sorted and deduplicated.
    pub calls: Vec<String>,
}

/// Record a `function_item` or `macro_definition` node: a test that does not
/// assert becomes an [`UnassertedTest`], any other function or macro that
/// asserts or calls something becomes a [`TestHelper`]. Other nodes are ignored.
pub(super) fn collect<D: Doc>(
    node: &Node<D>,
    cfg_test: &CfgTestRanges,
    helpers: &mut Vec<TestHelper>,
    tests: &mut Vec<UnassertedTest>,
) {
    let kind = node.kind();
    if !matches!(&*kind, "function_item" | "macro_definition") {
        return;
    }
    let Some(name) = node.field("name") else {
        return;
    };
    let text = node.text();
    let asserts = asserts_directly(node, &text);
    let calls = called_names(node);
    let start = node.start_pos();
    let line = start.line() + 1;
    let attributes = stacked_attributes(node);
    let is_test = &*kind == "function_item" && attributes.iter().any(|a| is_test_attribute(a));
    if !is_test {
        if asserts || !calls.is_empty() {
            helpers.push(TestHelper {
                name: name.text().to_string(),
                asserts,
                calls,
                in_cfg_test: cfg_test.contains_line(line),
            });
        }
        return;
    }
    let should_panic = attributes.iter().any(|a| a.contains("should_panic"));
    if should_panic || asserts || is_compile_only(node) {
        return;
    }
    let end = node.end_pos();
    tests.push(UnassertedTest {
        line,
        column: start.byte_point().1 + 1,
        end_line: end.line() + 1,
        end_column: end.byte_point().1 + 1,
        text: text.to_string(),
        calls,
    });
}

/// The attributes stacked directly on an item. The walk goes back over
/// attributes and comments only and stops at the first other sibling, so an
/// attribute on an earlier item never counts.
fn stacked_attributes<D: Doc>(node: &Node<D>) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut current = node.prev();
    while let Some(sibling) = current {
        match &*sibling.kind() {
            "attribute_item" => attributes.push(sibling.text().to_string()),
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        current = sibling.prev();
    }
    attributes
}

/// `#[test]`, `#[tokio::test(..)]`, `#[cargo_test]`: an attribute whose path's
/// last segment contains `test`, followed by `]` or `(`. `#[cfg(test)]` does
/// not qualify: its path is `cfg`.
fn is_test_attribute(attribute: &str) -> bool {
    let Some(inner) = attribute.strip_prefix("#[") else {
        return false;
    };
    let inner = inner.trim_start();
    let path_len = inner
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
        .unwrap_or(inner.len());
    let (path, rest) = inner.split_at(path_len);
    let closes = rest.trim_start().starts_with([']', '(']);
    closes && last_segment(path).contains("test")
}

/// Whether a function or macro checks something itself: `assert` or `panic`
/// anywhere in its text (`assert_eq!`, `panic!`, `prop_assert!`, a helper named
/// `assert_valid`), a `?`, a panicking accessor, or an inline snapshot.
fn asserts_directly<D: Doc>(node: &Node<D>, text: &str) -> bool {
    text.contains("assert")
        || text.contains("panic")
        || has_panicking_accessor(text)
        || has_inline_snapshot(text)
        || node.dfs().any(|n| &*n.kind() == "try_expression")
}

/// `.unwrap()`, `.expect(..)`, `.unwrap_err()`, `.expect_err(..)`: each fails
/// the test on the wrong variant, like `?` does. `.unwrap_or(..)` does not.
fn has_panicking_accessor(text: &str) -> bool {
    [".unwrap", ".expect"].iter().any(|method| {
        text.match_indices(method).any(|(at, found)| {
            let rest = &text[at + found.len()..];
            let rest = rest.strip_prefix("_err").unwrap_or(rest);
            rest.trim_start().starts_with('(')
        })
    })
}

/// `str![..]`, `expect![..]`, `expect_file![..]`, `file![..]`.
fn has_inline_snapshot(text: &str) -> bool {
    text.match_indices('!').any(|(at, _)| {
        let before = &text[..at];
        let prefix = before.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_');
        let name = &before[prefix.len()..];
        SNAPSHOT_MACROS.contains(&name) && text[at + 1..].trim_start().starts_with('[')
    })
}

/// Bare names of everything under `node` that is called: plain, scoped and
/// generic function calls, method calls, macro invocations, and the `name(..)`
/// and `name!` sequences inside macro token trees, whose content is not parsed.
fn called_names<D: Doc>(node: &Node<D>) -> Vec<String> {
    let mut names = Vec::new();
    for descendant in node.dfs() {
        match &*descendant.kind() {
            "call_expression" => {
                names.extend(descendant.field("function").and_then(|f| callee_name(&f)));
            }
            "macro_invocation" => {
                names.extend(
                    descendant
                        .field("macro")
                        .map(|m| last_segment(&m.text()).to_string()),
                );
            }
            "token_tree" => names.extend(token_tree_calls(&descendant)),
            _ => {}
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The bare name of a call's callee: `f`, `a::b::f`, `x.f`, `f::<T>`.
fn callee_name<D: Doc>(callee: &Node<D>) -> Option<String> {
    match &*callee.kind() {
        "identifier" => Some(callee.text().to_string()),
        "scoped_identifier" => callee.field("name").map(|n| n.text().to_string()),
        "field_expression" => callee.field("field").map(|n| n.text().to_string()),
        "generic_function" => callee.field("function").and_then(|f| callee_name(&f)),
        _ => None,
    }
}

/// Inside a token tree, an identifier directly followed by a parenthesized
/// token tree (`name(..)`) or by `!` (`name!`) is a call.
fn token_tree_calls<D: Doc>(tree: &Node<D>) -> Vec<String> {
    let children: Vec<Node<D>> = tree.children().collect();
    children
        .windows(2)
        .filter_map(|pair| {
            let [ident, next] = pair else {
                return None;
            };
            if &*ident.kind() != "identifier" {
                return None;
            }
            let next_text = next.text();
            let is_call =
                (&*next.kind() == "token_tree" && next_text.starts_with('(')) || next_text == "!";
            is_call.then(|| ident.text().to_string())
        })
        .collect()
}

/// Whether a test body only declares items and typed `let _: T = ..`
/// bindings: it checks that the code compiles (a derive, a trait bound, a type
/// annotation), which is its whole intent. An empty body is not one.
fn is_compile_only<D: Doc>(function: &Node<D>) -> bool {
    let Some(body) = function.field("body") else {
        return false;
    };
    let mut declares = false;
    for child in body.children().filter(|c| c.is_named()) {
        let kind = child.kind();
        if NEUTRAL_KINDS.contains(&&*kind) {
            continue;
        }
        let typed_discard = &*kind == "let_declaration"
            && child.field("type").is_some()
            && child.field("pattern").is_some_and(|p| p.text() == "_");
        if !(typed_discard || COMPILE_ONLY_KINDS.contains(&&*kind)) {
            return false;
        }
        declares = true;
    }
    declares
}

/// Every file's tests and helpers, folded into one index.
#[derive(Debug, Default)]
pub(super) struct AssertionIndex {
    helpers: Vec<(PathBuf, TestHelper)>,
    tests: Vec<(PathBuf, UnassertedTest)>,
    /// Every indexed file, even one contributing nothing: its crate's manifest
    /// may make a support crate a normal dependency.
    files: Vec<PathBuf>,
}

impl AssertionIndex {
    /// Add one file's contribution.
    pub(super) fn add(&mut self, path: &Path, helpers: &[TestHelper], tests: &[UnassertedTest]) {
        self.files.push(path.to_path_buf());
        self.helpers
            .extend(helpers.iter().map(|h| (path.to_path_buf(), h.clone())));
        self.tests
            .extend(tests.iter().map(|t| (path.to_path_buf(), t.clone())));
    }
}

/// Report the tests whose calls reach no asserting helper and no function
/// listed in the rule's `assert_functions` option.
///
/// Only test code can vouch for a test: a helper inside `#[cfg(test)]`, in a
/// test path (built-in layout or `scan.test_paths`), or in a test-support crate.
/// A production function with a precondition `assert!` does not, or every test
/// calling a `new` somewhere would be silenced.
pub(super) fn evaluate(rule: &Rule, index: &AssertionIndex, filter: &DeclFilter) -> Vec<Finding> {
    let candidates: Vec<&(PathBuf, UnassertedTest)> = index
        .tests
        .iter()
        .filter(|(path, _)| filter.allows_path(path))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let configured = |name: &str| {
        filter
            .assert_functions
            .as_ref()
            .is_some_and(|globs| globs.is_match(name))
    };
    let helpers = test_code_helpers(index, filter);
    let asserting = asserting_names(&helpers, &configured);
    candidates
        .into_iter()
        .filter(|(_, test)| {
            !test
                .calls
                .iter()
                .any(|call| asserting.contains(call.as_str()) || configured(call))
        })
        .map(|(path, test)| Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity.clone(),
            category: rule.category.clone().unwrap_or_default(),
            message: rule.message.clone(),
            note: rule.note.clone(),
            fix: rule.fix.clone(),
            file: path.clone(),
            line: test.line,
            column: test.column,
            end_line: test.end_line,
            end_column: test.end_column,
            matched_text: test.text.clone(),
            confidence: None,
            escalated: false,
        })
        .collect()
}

/// The helpers that live in test code. The per-file verdict is computed once
/// per distinct path: test-support detection reads manifests.
fn test_code_helpers<'a>(index: &'a AssertionIndex, filter: &DeclFilter) -> Vec<&'a TestHelper> {
    let support = SupportCrates::detect(index.files.iter().map(PathBuf::as_path));
    let mut test_file: HashMap<&Path, bool> = HashMap::new();
    index
        .helpers
        .iter()
        .filter(|(path, helper)| {
            helper.in_cfg_test
                || *test_file
                    .entry(path.as_path())
                    .or_insert_with(|| filter.test_paths.is_test(path) || support.contains(path))
        })
        .map(|(_, helper)| helper)
        .collect()
}

/// Names of the helpers that assert: directly, through a configured assert
/// function, or by calling another asserting helper. A worklist over the
/// reversed call graph reaches the fixpoint in one pass over the edges.
fn asserting_names<'a>(
    helpers: &[&'a TestHelper],
    configured: &impl Fn(&str) -> bool,
) -> HashSet<&'a str> {
    let mut callers: HashMap<&str, Vec<&str>> = HashMap::new();
    for helper in helpers {
        for call in &helper.calls {
            callers
                .entry(call.as_str())
                .or_default()
                .push(helper.name.as_str());
        }
    }
    let mut asserting: HashSet<&str> = HashSet::new();
    let mut queue: Vec<&str> = Vec::new();
    for helper in helpers {
        let seeds = helper.asserts || helper.calls.iter().any(|call| configured(call));
        if seeds && asserting.insert(helper.name.as_str()) {
            queue.push(helper.name.as_str());
        }
    }
    while let Some(name) = queue.pop() {
        for caller in callers.get(name).into_iter().flatten() {
            if asserting.insert(caller) {
                queue.push(caller);
            }
        }
    }
    asserting
}
