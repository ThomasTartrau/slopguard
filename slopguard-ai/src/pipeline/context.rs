//! Source-context extraction around a matched line.

/// Lines of context extracted on each side of a matched line. Reduced from 50
/// to 25 to shrink the per-candidate input sent to the classifier: with
/// batching, overlapping windows are merged into one request, so a smaller
/// radius directly lowers the state size without losing local context.
pub(crate) const CONTEXT_RADIUS: usize = 25;

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

/// Extract the inclusive 1-based line range `[start, end]`, prefixing each line
/// with its absolute line number, clamped to the file bounds. Used to build the
/// merged `state` of a classifier batch: absolute numbers let each noul point at
/// its own candidate line inside a region shared by several candidates.
#[cfg(feature = "provider-typesafe")]
pub(crate) fn extract_numbered(source: &str, start: usize, end: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let first = start.max(1).min(lines.len());
    let last = end.max(first).min(lines.len());
    lines[(first - 1)..last]
        .iter()
        .enumerate()
        .map(|(offset, text)| format!("{}: {text}", first + offset))
        .collect::<Vec<_>>()
        .join("\n")
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

    #[test]
    fn context_radius_is_twenty_five() {
        assert_eq!(CONTEXT_RADIUS, 25);
    }

    #[cfg(feature = "provider-typesafe")]
    #[test]
    fn extract_numbered_prefixes_absolute_line_numbers() {
        let src = "a\nb\nc\nd\ne";
        // lines 2..4 carry their absolute numbers
        assert_eq!(extract_numbered(src, 2, 4), "2: b\n3: c\n4: d");
        // end past the file clamps to the last line
        assert_eq!(extract_numbered(src, 4, 999), "4: d\n5: e");
        // start below 1 clamps to the first line
        assert_eq!(extract_numbered(src, 0, 2), "1: a\n2: b");
        // empty source
        assert_eq!(extract_numbered("", 1, 5), "");
    }
}
