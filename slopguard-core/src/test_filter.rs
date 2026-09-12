use std::ops::Range;

use ast_grep_core::{AstGrep, Doc, Node};

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
}
