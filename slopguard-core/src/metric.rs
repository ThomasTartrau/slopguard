//! File-level structural metrics.
//!
//! An AST rule matches nodes; a metric rule measures a property of the whole
//! file and fires once when the measured value exceeds a threshold. Metrics are
//! computed directly on the parsed tree rather than through ast-grep, which has
//! no notion of a whole-file match.

use std::collections::HashSet;

use ast_grep_core::{AstGrep, Doc};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::rule::Language;

/// A structural property measured over a whole file.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Metric {
    FileLines,
    ImportCount,
    FunctionCount,
    CommentRatio,
}

/// Tree-sitter node kinds that represent an import in each language.
fn import_kinds(lang: &Language) -> &'static [&'static str] {
    match lang {
        Language::Rust => &["use_declaration", "extern_crate_declaration"],
        Language::TypeScript => &["import_statement"],
    }
}

/// Tree-sitter node kinds that represent a function definition in each
/// language. Nested functions, closures with a body, and methods all count.
fn function_kinds(lang: &Language) -> &'static [&'static str] {
    match lang {
        Language::Rust => &["function_item"],
        Language::TypeScript => &[
            "function_declaration",
            "generator_function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        ],
    }
}

/// Tree-sitter node kinds that represent a comment in each language.
fn comment_kinds(lang: &Language) -> &'static [&'static str] {
    match lang {
        Language::Rust => &["line_comment", "block_comment", "doc_comment"],
        Language::TypeScript => &["comment"],
    }
}

/// Measure `metric` over an already parsed file.
///
/// Lines are counted with [`str::lines`], which treats a trailing newline as a
/// terminator: `"a\n"` is one line and `""` is zero lines.
pub fn compute<D: Doc>(metric: Metric, lang: &Language, root: &AstGrep<D>, source: &str) -> f64 {
    match metric {
        Metric::FileLines => source.lines().count() as f64,
        Metric::ImportCount => count_kinds(root, import_kinds(lang)) as f64,
        Metric::FunctionCount => count_kinds(root, function_kinds(lang)) as f64,
        Metric::CommentRatio => {
            let total_lines = source.lines().count();
            if total_lines == 0 {
                return 0.0;
            }
            comment_lines(root, comment_kinds(lang)) as f64 / total_lines as f64
        }
    }
}

fn count_kinds<D: Doc>(root: &AstGrep<D>, kinds: &[&str]) -> usize {
    let mut count = 0;
    for node in root.root().dfs() {
        if kinds.contains(&node.kind().as_ref()) {
            count += 1;
        }
    }
    count
}

/// Distinct 0-indexed source lines touched by a comment node. A block comment
/// spanning five lines counts as five.
///
/// A line set also makes the overlapping Rust `doc_comment` / `line_comment`
/// kinds harmless: a line reached twice still counts once.
fn comment_lines<D: Doc>(root: &AstGrep<D>, kinds: &[&str]) -> usize {
    let mut lines = HashSet::new();
    for node in root.root().dfs() {
        if kinds.contains(&node.kind().as_ref()) {
            lines.extend(node.start_pos().line()..=node.end_pos().line());
        }
    }
    lines.len()
}

impl Metric {
    /// Rendering of a measured value for `$value` substitution: an integer for
    /// counts, two decimals for ratios.
    pub fn format_value(&self, value: f64) -> String {
        match self {
            Metric::CommentRatio => format!("{value:.2}"),
            _ => (value as u64).to_string(),
        }
    }

    /// The `matched_text` of a metric finding: the value plus its unit, e.g.
    /// "547 lines", "42 imports", "0.62 comment ratio".
    pub fn describe(&self, value: f64) -> String {
        let rendered = self.format_value(value);
        match self {
            Metric::FileLines => format!("{rendered} lines"),
            Metric::ImportCount => format!("{rendered} imports"),
            Metric::FunctionCount => format!("{rendered} functions"),
            Metric::CommentRatio => format!("{rendered} comment ratio"),
        }
    }
}

/// A metric rule fires when the measured value is strictly above the threshold,
/// so `threshold: 500` does not flag a file of exactly 500 lines.
pub fn exceeds(value: f64, threshold: f64) -> bool {
    value > threshold
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    use super::*;

    fn rust(metric: Metric, source: &str) -> f64 {
        let root = SupportLang::Rust.ast_grep(source);
        compute(metric, &Language::Rust, &root, source)
    }

    fn typescript(metric: Metric, source: &str) -> f64 {
        let root = SupportLang::TypeScript.ast_grep(source);
        compute(metric, &Language::TypeScript, &root, source)
    }

    #[test]
    fn file_lines_counts_lines() {
        let source = "fn a() {}\nfn b() {}\nfn c() {}\n";
        assert_eq!(rust(Metric::FileLines, source), 3.0);
        assert_eq!(
            rust(Metric::FileLines, "fn a() {}\n"),
            1.0,
            "a trailing newline terminates the last line"
        );
    }

    #[test]
    fn file_lines_empty_file_is_zero() {
        assert_eq!(rust(Metric::FileLines, ""), 0.0);
    }

    #[test]
    fn import_count_rust() {
        let source = "\
use std::fmt;
use std::io::Write;
extern crate serde;

fn f() {
    use std::collections::HashMap;
    let _: HashMap<u8, u8> = HashMap::new();
}
";
        assert_eq!(
            rust(Metric::ImportCount, source),
            4.0,
            "a nested `use` inside a function still counts"
        );
    }

    #[test]
    fn import_count_typescript() {
        let source = "\
import { a } from \"./a\";
import b from \"./b\";
const c = require(\"./c\");
";
        assert_eq!(
            typescript(Metric::ImportCount, source),
            2.0,
            "a require() call is not an import statement"
        );
    }

    #[test]
    fn function_count_rust() {
        let source = "\
trait T {
    fn signature_only(&self);
}

struct S;

impl S {
    fn method(&self) {}
    fn other(&self) {}
}

fn free() {}
";
        assert_eq!(
            rust(Metric::FunctionCount, source),
            3.0,
            "a trait signature has no body and does not count"
        );
    }

    #[test]
    fn function_count_typescript() {
        let source = "\
function declared() {}
const arrow = () => 1;
class C {
    method() {}
}
";
        assert_eq!(typescript(Metric::FunctionCount, source), 3.0);
    }

    #[test]
    fn comment_ratio_line_comments() {
        let source = "\
// one
// two
fn a() {}
// three
fn b() {}
// four
fn c() {}
fn d() {}
";
        assert_eq!(rust(Metric::CommentRatio, source), 0.5);
    }

    #[test]
    fn comment_ratio_block_comment_spans_lines() {
        let source = "\
/* one
   two
   three
   four
   five */
fn a() {}
fn b() {}
fn c() {}
fn d() {}
fn e() {}
";
        assert_eq!(
            rust(Metric::CommentRatio, source),
            0.5,
            "a 5-line block comment contributes 5 comment lines out of 10"
        );
    }

    #[test]
    fn comment_ratio_empty_file_is_zero() {
        assert_eq!(rust(Metric::CommentRatio, ""), 0.0);
    }

    #[test]
    fn comment_ratio_no_comments_is_zero() {
        let source = "fn a() {}\nfn b() {}\n";
        assert_eq!(rust(Metric::CommentRatio, source), 0.0);
    }

    #[test]
    fn format_value_and_describe() {
        assert_eq!(Metric::FileLines.format_value(547.0), "547");
        assert_eq!(Metric::FileLines.describe(547.0), "547 lines");
        assert_eq!(Metric::ImportCount.describe(42.0), "42 imports");
        assert_eq!(Metric::FunctionCount.describe(31.0), "31 functions");
        assert_eq!(Metric::CommentRatio.format_value(0.617), "0.62");
        let ratio = Metric::CommentRatio.describe(0.617);
        assert_eq!(ratio, "0.62 comment ratio");
    }

    #[test]
    fn exceeds_is_strict() {
        assert!(!exceeds(500.0, 500.0));
        assert!(exceeds(501.0, 500.0));
        assert!(!exceeds(499.0, 500.0));
    }

    #[test]
    fn metric_display_is_snake_case() {
        assert_eq!(Metric::FileLines.to_string(), "file_lines");
        assert_eq!(Metric::CommentRatio.to_string(), "comment_ratio");
    }
}
