use std::ops::Range;
use std::path::Path;

use ast_grep_core::{AstGrep, Doc, Node};
use globset::{Error as GlobError, Glob, GlobSet, GlobSetBuilder};

/// Whether `path` lives in a conventional test, bench, or example tree, using
/// the built-in layout heuristic.
///
/// Rust integration tests, benchmarks, and examples are not `#[cfg(test)]`
/// modules, so `CfgTestRanges` cannot see them. Rules with `skip_test_code`
/// should treat these whole files as test code.
///
/// Matches exact directory names (`tests`, `benches`, `examples`, `fixtures`,
/// `__tests__`) and also crate-level test directories whose name ends with
/// `_test` or `_tests` (e.g. `integrations_tests`, `e2e_tests`). For single-file
/// test modules it matches a file stem of `tests` or `test` (the idiomatic
/// out-of-line `#[cfg(test)] mod tests;` target), one ending in `_test` /
/// `_tests`, and the TypeScript/JavaScript `*.spec.*` / `*.test.*` conventions
/// (whose stem ends in `.spec` / `.test`).
pub(crate) fn is_default_test_path(path: &Path) -> bool {
    let in_test_dir = path.components().any(|c| {
        let Some(name) = c.as_os_str().to_str() else {
            return false;
        };
        matches!(
            name,
            "tests" | "benches" | "examples" | "fixtures" | "__tests__"
        ) || name.ends_with("_tests")
            || name.ends_with("_test")
            || name.starts_with("test_")
    });
    let test_file_name = path.file_stem().and_then(|s| s.to_str()).is_some_and(|s| {
        matches!(s, "tests" | "test")
            || s.ends_with("_test")
            || s.ends_with("_tests")
            || s.ends_with(".spec")
            || s.ends_with(".test")
    });
    in_test_dir || test_file_name
}

/// Which paths count as test code for `skip_test_code` rules: the built-in
/// [`is_default_test_path`] heuristic plus any extra glob patterns supplied via
/// `scan.test_paths` in config or `--test-path` on the CLI.
#[derive(Clone, Default)]
pub(crate) struct TestPaths {
    extra: Option<GlobSet>,
}

impl TestPaths {
    /// Compile the user-supplied glob patterns. An empty list keeps only the
    /// built-in heuristic.
    pub(crate) fn new(patterns: &[String]) -> Result<Self, GlobError> {
        if patterns.is_empty() {
            return Ok(Self::default());
        }
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            builder.add(Glob::new(pattern)?);
        }
        Ok(Self {
            extra: Some(builder.build()?),
        })
    }

    /// Whether `path` should be treated as test code: it matches the built-in
    /// layout heuristic, or one of the configured patterns.
    pub(crate) fn is_test(&self, path: &Path) -> bool {
        is_default_test_path(path) || self.extra.as_ref().is_some_and(|g| g.is_match(path))
    }
}

/// Line ranges covered by `#[cfg(test)]` items in a parsed Rust file.
///
/// Detects patterns like:
/// ```text
/// #[cfg(test)]
/// mod tests {
///     ...
/// }
/// ```
/// and records the line range (1-indexed, attribute through closing brace) so
/// that findings inside can be filtered out post-scan.
pub struct CfgTestRanges {
    ranges: Vec<Range<usize>>,
}

impl CfgTestRanges {
    /// Collect the ranges from an already parsed Rust tree.
    ///
    /// Works on the AST rather than the raw text so braces inside string
    /// literals or comments cannot throw the range off.
    pub fn from_root<D: Doc>(root: &AstGrep<D>) -> Self {
        let ranges = root
            .root()
            .dfs()
            .filter(is_cfg_test_attr)
            .filter_map(|attr| {
                let item = annotated_item(&attr)?;
                Some((attr.start_pos().line() + 1)..(item.end_pos().line() + 2))
            })
            .collect();
        Self { ranges }
    }

    /// Returns `true` if the given 1-indexed line falls inside a `#[cfg(test)]` item.
    pub fn contains_line(&self, line: usize) -> bool {
        self.ranges.iter().any(|r| r.contains(&line))
    }
}

fn is_cfg_test_attr<D: Doc>(node: &Node<D>) -> bool {
    node.kind() == "attribute_item" && {
        let normalized: String = node.text().chars().filter(|c| !c.is_whitespace()).collect();
        normalized == "#[cfg(test)]"
    }
}

/// The item an attribute applies to: the next named sibling that is not
/// another attribute or a comment.
fn annotated_item<'r, D: Doc>(attr: &Node<'r, D>) -> Option<Node<'r, D>> {
    attr.next_all().find(|n| {
        n.is_named()
            && !matches!(
                &*n.kind(),
                "attribute_item" | "line_comment" | "block_comment"
            )
    })
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    use super::*;

    fn ranges(source: &str) -> CfgTestRanges {
        CfgTestRanges::from_root(&SupportLang::Rust.ast_grep(source))
    }

    #[test]
    fn detects_simple_cfg_test_block() {
        let source = "\
fn prod() {
    foo().unwrap();
}

#[cfg(test)]
mod tests {
    fn test_it() {
        bar().unwrap();
    }
}
";
        let ranges = ranges(source);
        // Line 1-3: prod code
        assert!(!ranges.contains_line(1));
        assert!(!ranges.contains_line(2));
        assert!(!ranges.contains_line(3));
        // Line 5: #[cfg(test)]
        assert!(ranges.contains_line(5));
        // Line 6: mod tests {
        assert!(ranges.contains_line(6));
        // Line 8: bar().unwrap()
        assert!(ranges.contains_line(8));
        // Line 10: }
        assert!(ranges.contains_line(10));
    }

    #[test]
    fn no_cfg_test_returns_empty() {
        let source = "fn main() { foo().unwrap(); }\n";
        let ranges = ranges(source);
        assert!(!ranges.contains_line(1));
    }

    #[test]
    fn cfg_test_with_extra_attributes() {
        let source = "\
fn prod() {}

#[cfg(test)]
#[allow(unused)]
mod tests {
    fn t() {}
}
";
        let ranges = ranges(source);
        assert!(!ranges.contains_line(1));
        assert!(ranges.contains_line(3)); // #[cfg(test)]
        assert!(ranges.contains_line(4)); // #[allow(unused)]
        assert!(ranges.contains_line(5)); // mod tests {
        assert!(ranges.contains_line(6)); // fn t()
        assert!(ranges.contains_line(7)); // }
    }

    #[test]
    fn multiple_cfg_test_blocks() {
        let source = "\
fn prod() {}

#[cfg(test)]
mod tests_a {
    fn a() {}
}

fn more_prod() {}

#[cfg(test)]
mod tests_b {
    fn b() {}
}
";
        let ranges = ranges(source);
        assert!(!ranges.contains_line(1));
        assert!(ranges.contains_line(4)); // mod tests_a
        assert!(!ranges.contains_line(8)); // more_prod
        assert!(ranges.contains_line(11)); // mod tests_b
    }

    #[test]
    fn adjacent_cfg_test_blocks() {
        let source = "\
#[cfg(test)]
mod a {}
#[cfg(test)]
mod b {}
";
        let ranges = ranges(source);
        assert!(ranges.contains_line(1));
        assert!(ranges.contains_line(2));
        assert!(ranges.contains_line(3));
        assert!(ranges.contains_line(4));
    }

    #[test]
    fn braces_inside_strings_do_not_break_the_range() {
        let source = "\
#[cfg(test)]
mod tests {
    fn t() {
        let bad = \"not valid {{{\";
        let other = \"}}}\";
        foo().unwrap();
    }
}
fn prod() {
    bar().unwrap();
}
";
        let ranges = ranges(source);
        assert!(ranges.contains_line(6)); // foo().unwrap() inside the module
        assert!(ranges.contains_line(8)); // closing brace of the module
        assert!(!ranges.contains_line(10)); // bar().unwrap() in prod
    }

    #[test]
    fn cfg_test_on_single_fn_inside_impl() {
        let source = "\
struct S;
impl S {
    fn prod(&self) {}

    #[cfg(test)]
    fn helper(&self) {
        x().unwrap();
    }
}
";
        let ranges = ranges(source);
        assert!(!ranges.contains_line(3));
        assert!(ranges.contains_line(5));
        assert!(ranges.contains_line(7));
        assert!(ranges.contains_line(8));
        assert!(!ranges.contains_line(9));
    }

    #[test]
    fn out_of_line_test_module_file_is_test_code() {
        // `#[cfg(test)] mod tests;` points at a bare `tests.rs` next to its
        // parent module; CfgTestRanges cannot see it, so the path heuristic must.
        assert!(is_default_test_path(Path::new("src/baseline/tests.rs")));
        assert!(is_default_test_path(Path::new("src/test.rs")));
        assert!(is_default_test_path(Path::new("src/foo_tests.rs")));
        assert!(is_default_test_path(Path::new(
            "crate/tests/integration.rs"
        )));
    }

    #[test]
    fn fixtures_and_ts_test_conventions_are_test_code() {
        assert!(is_default_test_path(Path::new(
            "tests/fixtures/rust_violations.rs"
        )));
        assert!(is_default_test_path(Path::new("crate/fixtures/data.rs")));
        assert!(is_default_test_path(Path::new("src/__tests__/foo.ts")));
        assert!(is_default_test_path(Path::new("src/button.spec.ts")));
        assert!(is_default_test_path(Path::new("src/button.test.tsx")));
        assert!(is_default_test_path(Path::new("src/api.spec.js")));
    }

    #[test]
    fn production_files_are_not_test_code() {
        assert!(!is_default_test_path(Path::new("src/scanner.rs")));
        assert!(!is_default_test_path(Path::new("src/testing.rs")));
        assert!(!is_default_test_path(Path::new("src/latest.rs")));
        assert!(!is_default_test_path(Path::new("src/mod.rs")));
        assert!(!is_default_test_path(Path::new("src/spec.ts")));
        assert!(!is_default_test_path(Path::new("src/inspector.ts")));
    }

    #[test]
    fn custom_patterns_extend_the_default_heuristic() {
        let tp =
            TestPaths::new(&["**/fixtures/**".to_string(), "**/*.spec.ts".to_string()]).unwrap();
        // custom patterns match
        assert!(tp.is_test(Path::new("src/fixtures/sample.rs")));
        assert!(tp.is_test(Path::new("src/foo.spec.ts")));
        // the built-in heuristic still applies
        assert!(tp.is_test(Path::new("src/baseline/tests.rs")));
        // unrelated production code stays production
        assert!(!tp.is_test(Path::new("src/scanner.rs")));
    }

    #[test]
    fn empty_patterns_keep_only_the_default_heuristic() {
        let tp = TestPaths::new(&[]).unwrap();
        assert!(tp.is_test(Path::new("tests/integration.rs")));
        assert!(!tp.is_test(Path::new("src/scanner.rs")));
    }

    #[test]
    fn invalid_pattern_is_an_error() {
        assert!(TestPaths::new(&["[unterminated".to_string()]).is_err());
    }
}
