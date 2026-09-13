//! Prompt-template rendering.

/// Render a prompt template, substituting every occurrence of the supported
/// variables: `{{code}}`, `{{filename}}`, and `{{rule_context}}`.
pub(crate) fn render_prompt(
    template: &str,
    code: &str,
    filename: &str,
    rule_context: &str,
) -> String {
    template
        .replace("{{code}}", code)
        .replace("{{filename}}", filename)
        .replace("{{rule_context}}", rule_context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_prompt_substitutes_all_variables() {
        let rendered = render_prompt(
            "file={{filename}} code={{code}} ctx={{rule_context}} again={{code}}",
            "CODE",
            "main.rs",
            "CTX",
        );
        assert_eq!(rendered, "file=main.rs code=CODE ctx=CTX again=CODE");
    }
}
