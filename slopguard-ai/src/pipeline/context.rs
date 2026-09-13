//! Source-context extraction around a matched line.

/// Lines of context extracted on each side of a matched line.
pub(crate) const CONTEXT_RADIUS: usize = 50;

/// Extract the source lines around a 1-based `line` (inclusive), `radius` on
/// each side, clamped to the file bounds.
pub(crate) fn extract_context(source: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = line.saturating_sub(1).min(lines.len() - 1);
    let start = idx.saturating_sub(radius);
    let end = (idx + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_context_clamps_to_bounds() {
        let src = "a\nb\nc\nd\ne";
        // radius covering the whole file
        assert_eq!(extract_context(src, 3, 50), "a\nb\nc\nd\ne");
        // tight radius around line 3 (1-based) -> lines 2..4
        assert_eq!(extract_context(src, 3, 1), "b\nc\nd");
        // out-of-range line clamps to the last line, then applies the radius
        assert_eq!(extract_context(src, 999, 1), "d\ne");
        // empty source
        assert_eq!(extract_context("", 1, 5), "");
    }
}
