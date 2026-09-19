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
use crate::test_filter::CfgTestRanges;

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
/// When `exclude_tests` is `Some`, lines and nodes inside `#[cfg(test)]` ranges
/// do not count, so a production file's inline test module does not inflate the
/// measurement. When it is `None`, everything counts.
pub fn compute<D: Doc>(
    metric: Metric,
    lang: &Language,
    root: &AstGrep<D>,
    source: &str,
    exclude_tests: Option<&CfgTestRanges>,
) -> f64 {
    match metric {
        Metric::FileLines => count_lines(source, exclude_tests) as f64,
        Metric::ImportCount => count_kinds(root, import_kinds(lang), exclude_tests) as f64,
        Metric::FunctionCount => count_kinds(root, function_kinds(lang), exclude_tests) as f64,
        Metric::CommentRatio => {
            let total_lines = count_lines(source, exclude_tests);
            if total_lines == 0 {
                return 0.0;
            }
            comment_lines(root, comment_kinds(lang), exclude_tests) as f64 / total_lines as f64
        }
    }
}

/// Whether a 0-indexed tree-sitter line falls inside a `#[cfg(test)]` range.
/// `CfgTestRanges` is 1-indexed, so the line is shifted before the lookup.
fn in_test(exclude_tests: Option<&CfgTestRanges>, zero_indexed_line: usize) -> bool {
    exclude_tests.is_some_and(|r| r.contains_line(zero_indexed_line + 1))
}

/// Count source lines, optionally dropping those inside `#[cfg(test)]` ranges.
///
/// Lines are counted with [`str::lines`], which treats a trailing newline as a
/// terminator: `"a\n"` is one line and `""` is zero lines.
fn count_lines(source: &str, exclude_tests: Option<&CfgTestRanges>) -> usize {
    source
        .lines()
        .enumerate()
        .filter(|(i, _)| !in_test(exclude_tests, *i))
        .count()
}

fn count_kinds<D: Doc>(
    root: &AstGrep<D>,
    kinds: &[&str],
    exclude_tests: Option<&CfgTestRanges>,
) -> usize {
    let mut count = 0;
    for node in root.root().dfs() {
        if kinds.contains(&node.kind().as_ref()) && !in_test(exclude_tests, node.start_pos().line())
        {
            count += 1;
        }
    }
    count
}

/// Distinct 0-indexed source lines touched by a *narration* comment. A block
/// comment spanning five lines counts as five; a line reached twice counts once.
///
/// Doc comments (`///`, `//!`, `/** */`) do not count. They are API
/// documentation, not line-by-line narration, and this project (like most)
/// requires them on public items, so counting them would flag well-documented
/// files. Rust marks them with a nested `doc_comment` node; TypeScript has no
/// such node, so a `/** */` JSDoc block is recognised by its opening marker.
fn comment_lines<D: Doc>(
    root: &AstGrep<D>,
    kinds: &[&str],
    exclude_tests: Option<&CfgTestRanges>,
) -> usize {
    let mut lines = HashSet::new();
    let mut doc_lines = HashSet::new();
    for node in root.root().dfs() {
        let kind = node.kind();
        if kind.as_ref() == "doc_comment" {
            doc_lines.extend(node.start_pos().line()..=node.end_pos().line());
            continue;
        }
        if !kinds.contains(&kind.as_ref()) {
            continue;
        }
        let range = node.start_pos().line()..=node.end_pos().line();
        if node.text().trim_start().starts_with("/**") {
            doc_lines.extend(range);
        } else {
            lines.extend(range);
        }
    }
    lines
        .into_iter()
        .filter(|line| !doc_lines.contains(line) && !in_test(exclude_tests, *line))
        .count()
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
        compute(metric, &Language::Rust, &root, source, None)
    }

    fn typescript(metric: Metric, source: &str) -> f64 {
        let root = SupportLang::TypeScript.ast_grep(source);
        compute(metric, &Language::TypeScript, &root, source, None)
    }

    fn cfg_ranges(source: &str) -> CfgTestRanges {
        CfgTestRanges::from_root(&SupportLang::Rust.ast_grep(source))
    }

    fn rust_no_tests(metric: Metric, source: &str) -> f64 {
        let root = SupportLang::Rust.ast_grep(source);
        compute(
            metric,
            &Language::Rust,
            &root,
            source,
            Some(&cfg_ranges(source)),
        )
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
    fn excludes_cfg_test_lines_and_functions() {
        let source = "\
use std::fmt;

fn prod_one() {}
fn prod_two() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() {}
    fn t_one() {}
    fn t_two() {}
}
";
        // Counting everything: 5 functions, 2 imports, 13 lines.
        assert_eq!(rust(Metric::FunctionCount, source), 5.0);
        assert_eq!(rust(Metric::ImportCount, source), 2.0);
        assert_eq!(rust(Metric::FileLines, source), 13.0);
        // Excluding the `#[cfg(test)]` module (lines 6-13): only the 2 production
        // functions, the 1 production import, and the 5 non-test lines remain.
        assert_eq!(rust_no_tests(Metric::FunctionCount, source), 2.0);
        assert_eq!(rust_no_tests(Metric::ImportCount, source), 1.0);
        assert_eq!(rust_no_tests(Metric::FileLines, source), 5.0);
    }

    #[test]
    fn excludes_cfg_test_comment_lines() {
        let source = "\
// prod comment
fn prod() {}
#[cfg(test)]
mod tests {
    // test comment
    // another test comment
    fn t() {}
}
";
        // Everything: 3 comment lines / 8 lines.
        assert_eq!(rust(Metric::CommentRatio, source), 3.0 / 8.0);
        // Test comments and test lines both drop out: 1 comment / 2 prod lines.
        assert_eq!(rust_no_tests(Metric::CommentRatio, source), 1.0 / 2.0);
    }

    #[test]
    fn no_cfg_test_leaves_metrics_unchanged() {
        let source = "use std::fmt;\nfn a() {}\nfn b() {}\n";
        assert_eq!(
            rust_no_tests(Metric::FunctionCount, source),
            rust(Metric::FunctionCount, source)
        );
        assert_eq!(
            rust_no_tests(Metric::FileLines, source),
            rust(Metric::FileLines, source)
        );
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
    fn comment_ratio_ignores_doc_comments() {
        // `///`, `//!` and `/** */` are API docs, not narration: none count.
        let source = "\
//! module doc
/// outer doc for a
/// still doc
fn a() {}
/** block doc */
fn b() {}
";
        assert_eq!(
            rust(Metric::CommentRatio, source),
            0.0,
            "a file with only doc comments has a zero narration ratio"
        );
    }

    #[test]
    fn comment_ratio_counts_narration_but_not_docs() {
        // Two `//` narration lines and two `///` doc lines over six lines: only
        // the narration counts, so 2/6, not 4/6.
        let source = "\
// narrate one
// narrate two
/// doc one
/// doc two
fn a() {}
fn b() {}
";
        assert_eq!(rust(Metric::CommentRatio, source), 2.0 / 6.0);
    }

    #[test]
    fn comment_ratio_typescript_ignores_jsdoc() {
        let source = "\
/** jsdoc line one
 * jsdoc line two
 */
// real narration
function f() {}
";
        // Only the `//` line counts: 1 of 5 lines.
        assert_eq!(typescript(Metric::CommentRatio, source), 1.0 / 5.0);
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
