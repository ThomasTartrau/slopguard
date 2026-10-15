//! Infer the strum `serialize_all` style that turns each variant name into
//! the literal a hand-written match returns for it.

/// Turns a variant name, split into words, into its serialized string.
type Convert = fn(&[&str]) -> String;

/// strum `serialize_all` styles tried in this order, each with the conversion
/// it applies to a variant's words.
const CASE_STYLES: &[(&str, Convert)] = &[
    ("snake_case", |w| join_lower(w, "_")),
    ("kebab-case", |w| join_lower(w, "-")),
    ("lowercase", |w| join_lower(w, "")),
    ("camelCase", |w| {
        let mut out = w.first().map(|f| f.to_lowercase()).unwrap_or_default();
        out.extend(w.iter().skip(1).copied());
        out
    }),
    ("SCREAMING_SNAKE_CASE", |w| {
        join_lower(w, "_").to_uppercase()
    }),
    ("SCREAMING-KEBAB-CASE", |w| {
        join_lower(w, "-").to_uppercase()
    }),
    ("UPPERCASE", |w| join_lower(w, "").to_uppercase()),
    ("title_case", |w| w.join(" ")),
    ("Train-Case", |w| w.join("-")),
];

fn join_lower(words: &[&str], separator: &str) -> String {
    words
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(separator)
}

/// Split a variant name into its words when every word is one ASCII capital
/// followed by ASCII lowercase letters (`ForbiddenHost`), `None` otherwise
/// (acronyms, digits, underscores), where strum's word splitting (heck) could
/// disagree with this one.
fn simple_words(name: &str) -> Option<Vec<&str>> {
    let mut words = Vec::new();
    let mut start = 0;
    for (i, c) in name.char_indices().skip(1) {
        if c.is_ascii_uppercase() {
            words.push(&name[start..i]);
            start = i;
        }
    }
    words.push(&name[start..]);
    words
        .iter()
        .all(|w| {
            let mut chars = w.chars();
            chars.next().is_some_and(|c| c.is_ascii_uppercase())
                && w.len() > 1
                && chars.all(|c| c.is_ascii_lowercase())
        })
        .then_some(words)
}

/// Whether `style` maps every `(variant, literal)` pair.
fn converts(style: &str, pairs: &[(String, String)]) -> bool {
    let Some((_, convert)) = CASE_STYLES.iter().find(|(name, _)| *name == style) else {
        return false;
    };
    pairs.iter().all(|(variant, literal)| {
        simple_words(variant).is_some_and(|words| convert(&words) == *literal)
    })
}

/// The style mapping every variant to its literal: `Some(None)` when no
/// `serialize_all` attribute is needed (the literals repeat the variant names,
/// or the enum's `existing` style already produces them), `Some(Some(style))`
/// for the style to add, `None` when no single style fits.
pub(super) fn infer_style(
    pairs: &[(String, String)],
    existing: Option<&str>,
) -> Option<Option<String>> {
    if let Some(style) = existing {
        return converts(style, pairs).then_some(None);
    }
    if pairs.iter().all(|(variant, literal)| variant == literal) {
        return Some(None);
    }
    CASE_STYLES
        .iter()
        .map(|(style, _)| *style)
        .find(|style| converts(style, pairs))
        .map(|style| Some(style.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(v, l)| (v.to_string(), l.to_string()))
            .collect()
    }

    #[test]
    fn infers_the_first_style_that_maps_every_variant() {
        let p = pairs(&[("ForbiddenHost", "forbidden_host"), ("Relayed", "relayed")]);
        assert_eq!(infer_style(&p, None), Some(Some("snake_case".into())));
        let p = pairs(&[("ForbiddenHost", "forbidden-host")]);
        assert_eq!(infer_style(&p, None), Some(Some("kebab-case".into())));
        let p = pairs(&[("ForbiddenHost", "FORBIDDEN_HOST")]);
        assert_eq!(
            infer_style(&p, None),
            Some(Some("SCREAMING_SNAKE_CASE".into()))
        );
        let p = pairs(&[("ForbiddenHost", "Forbidden Host")]);
        assert_eq!(infer_style(&p, None), Some(Some("title_case".into())));
        let p = pairs(&[("ForbiddenHost", "forbiddenHost")]);
        assert_eq!(infer_style(&p, None), Some(Some("camelCase".into())));
    }

    #[test]
    fn verbatim_literals_need_no_style() {
        let p = pairs(&[("HTTPError", "HTTPError"), ("V2", "V2")]);
        assert_eq!(infer_style(&p, None), Some(None));
    }

    #[test]
    fn mixed_or_irregular_literals_have_no_style() {
        let p = pairs(&[
            ("Stdout", "stdout"),
            ("ForbiddenHost", "forbidden-host"),
            ("Ab", "a_b"),
        ]);
        assert_eq!(infer_style(&p, None), None);
        let p = pairs(&[("Http2Server", "http2_server")]);
        assert_eq!(
            infer_style(&p, None),
            None,
            "digits: heck may split differently"
        );
        let p = pairs(&[("Stdout", "out")]);
        assert_eq!(infer_style(&p, None), None);
    }

    #[test]
    fn an_existing_style_must_already_produce_the_literals() {
        let p = pairs(&[("ForbiddenHost", "forbidden_host")]);
        assert_eq!(infer_style(&p, Some("snake_case")), Some(None));
        assert_eq!(infer_style(&p, Some("kebab-case")), None);
    }
}
