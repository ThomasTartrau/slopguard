//! Neutralizing terminal control characters in strings that third parties
//! control (rule text, file paths, git output, model reasons).

use std::borrow::Cow;

/// Escape control characters so a string is safe to print to a terminal.
///
/// Every control char (C0, DEL and C1, ESC included) except `\n` and `\t` is
/// replaced by a `\xNN` escape with two lowercase hex digits. Returns the
/// input borrowed when nothing needs escaping.
pub fn sanitize_control(s: &str) -> Cow<'_, str> {
    let needs_escape = |c: char| c.is_control() && c != '\n' && c != '\t';
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if needs_escape(c) {
            out.push_str(&format!("\\x{:02x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_esc() {
        assert_eq!(sanitize_control("a\x1b[2Jb"), "a\\x1b[2Jb");
    }

    #[test]
    fn keeps_newline_and_tab() {
        let out = sanitize_control("a\n\tb");
        assert_eq!(out, "a\n\tb");
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn escapes_carriage_return() {
        assert_eq!(sanitize_control("a\rb"), "a\\x0db");
    }

    #[test]
    fn escapes_c1() {
        assert_eq!(sanitize_control("a\u{9b}b"), "a\\x9bb");
    }

    #[test]
    fn leaves_plain_and_non_ascii_borrowed() {
        for s in ["plain", "caf\u{e9}"] {
            let out = sanitize_control(s);
            assert_eq!(out, s);
            assert!(matches!(out, Cow::Borrowed(_)));
        }
    }
}
