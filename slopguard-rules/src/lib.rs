use rust_embed::Embed;

#[derive(Embed)]
#[folder = "rules/"]
pub struct BuiltinRules;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_embeds_subdirectories() {
        let files: Vec<_> = BuiltinRules::iter().collect();
        assert!(
            files.iter().any(|f| f.starts_with("slop/")),
            "should contain slop/ files, got: {files:?}"
        );
        assert!(
            files.iter().any(|f| f.starts_with("security/")),
            "should contain security/ files, got: {files:?}"
        );
        assert!(
            files.iter().any(|f| f.starts_with("correctness/")),
            "should contain correctness/ files, got: {files:?}"
        );
    }
}
