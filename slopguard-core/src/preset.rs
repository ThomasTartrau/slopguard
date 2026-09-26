//! Configuration presets used by `slopguard init`.
//!
//! A preset renders a complete `slopguard.toml`. The rule id lists are derived
//! from the builtin ruleset at render time, so a preset can never name a rule
//! that no longer ships.

use std::collections::HashSet;

use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

use crate::rule::{load_builtin_rules, Category, RuleError, Severity};

/// A named starting configuration for a project.
#[derive(Debug, Display, EnumString, EnumIter, Default, Clone, Copy, PartialEq, Eq)]
#[strum(serialize_all = "lowercase")]
pub enum Preset {
    /// Every ruleset on, opt-in rules off.
    #[default]
    Default,
    /// Every ruleset on plus every opt-in rule.
    Strict,
    /// Security plus correctness errors only.
    Relaxed,
    /// Default rules with the AI confirmation pass switched on.
    Ai,
}

/// `[rulesets]` with every ruleset on. Shared by the `default`, `ai` and
/// `strict` presets.
const RULESETS_ALL_ON: &str = "[rulesets]\nslop = true\nsecurity = true\ncorrectness = true\n";

/// The `[output]` block. Identical in every preset.
const OUTPUT_BLOCK: &str = "[output]\nformat = \"text\"\ncolors = true\n";

/// The `[rules]` and `[scan]` sections of the `default` and `ai` presets:
/// opt-in rules off and listed in a comment, nothing disabled, the standard
/// scan comments. The list comes from the builtin ruleset, so it cannot drift.
fn default_rules_and_scan() -> Result<String, RuleError> {
    let mut out = String::from("[rules]\ndisable = []\n# Opt-in rules (disabled by default):\n");
    for id in opt_in_rule_ids()? {
        out.push_str(&format!("#   {id}\n"));
    }
    out.push_str(
        "enable = []\n# custom_dirs = [\"./my-rules\"]\n\n\
         # Test helpers from outside the project that assert, so a test\n\
         # calling them is not reported by no-assertion-free-test:\n\
         # [rules.options.no-assertion-free-test]\n\
         # assert_functions = [\"run\", \"check_*\"]\n\n\
         [scan]\nignores = []\n# cache_dir = \".slopguard-cache\"\n",
    );
    Ok(out)
}

/// The `[rulesets]`, `[rules]`, `[scan]` and `[output]` sections shared by the
/// `default` and `ai` presets.
fn common_body() -> Result<String, RuleError> {
    Ok(format!(
        "{RULESETS_ALL_ON}\n{}\n{OUTPUT_BLOCK}",
        default_rules_and_scan()?
    ))
}

/// The commented-out `[ai]` block shipped by every preset that leaves AI off.
const COMMENTED_AI_BODY: &str = r#"
# [ai]
# enabled = false
# provider = "api"        # "api" (HTTP) | "cli" (local claude)
# vendor = "anthropic"    # "anthropic" | "openai" (for provider = "api")
# model = "claude-haiku-4-5"
# concurrency = 4
# api_key via ANTHROPIC_API_KEY / OPENAI_API_KEY env, or ai.api_key
#
# [ai.classifier]         # System One (Jev) pass, on a separate axis from the LLM
# enabled = false
# transport = "direct"    # "direct" (TYPESAFE_API_KEY) | "openrouter" (OPENROUTER_API_KEY)
# threshold = 0.7
# batch = true            # group overlapping candidates into one request
# batch_max_questions = 8
# batch_max_state_lines = 200
"#;

/// The live `[ai]` block of the `ai` preset. The model is the same default the
/// AI pipeline uses; `slopguard-core` must not depend on `slopguard-ai`.
const LIVE_AI_BODY: &str = r#"
[ai]
enabled = true
provider = "api"        # "api" (HTTP) | "cli" (local claude)
vendor = "anthropic"    # "anthropic" | "openai"
model = "claude-haiku-4-5"
concurrency = 4
# api_key via ANTHROPIC_API_KEY / OPENAI_API_KEY env, or ai.api_key
#
# [ai.classifier]         # System One (Jev) pass, on a separate axis from the LLM
# enabled = false
# transport = "direct"    # "direct" (TYPESAFE_API_KEY) | "openrouter" (OPENROUTER_API_KEY)
# threshold = 0.7
# batch = true            # group overlapping candidates into one request
# batch_max_questions = 8
# batch_max_state_lines = 200
"#;

/// The commented-out `[escalation]` block shipped by every preset. Escalation
/// is opt-in, so no preset turns it on.
const COMMENTED_ESCALATION_BODY: &str = r#"
# [escalation]
# enabled = false
# threshold = 5          # same rule firing N times in one file becomes an error
#
# [escalation.rules]
# no-magic-number = 3    # per-rule override
"#;

impl Preset {
    /// One-line summary shown by `slopguard init --preset` and written into
    /// the header of the generated file.
    pub fn description(&self) -> &'static str {
        match self {
            Preset::Default => {
                "All rulesets on, opt-in rules off. Same as running init with no preset."
            }
            Preset::Strict => "Everything on, including every opt-in rule. Warnings fail the scan.",
            Preset::Relaxed => {
                "Security plus correctness errors only. Slop and correctness warnings off."
            }
            Preset::Ai => {
                "Default rules plus the AI confirmation pass (api provider, haiku model)."
            }
        }
    }

    /// Render the preset as the full text of a `slopguard.toml`.
    pub fn render(&self) -> Result<String, RuleError> {
        let mut out = match self {
            Preset::Default => render_default()?,
            Preset::Strict => render_strict()?,
            Preset::Relaxed => render_relaxed()?,
            Preset::Ai => render_ai()?,
        };
        out.push_str(COMMENTED_ESCALATION_BODY);
        Ok(out)
    }
}

/// The two comment lines that open every generated file.
fn header(preset: Preset) -> String {
    format!(
        "# Generated by: slopguard init --preset {preset}\n# {}\n\n",
        preset.description()
    )
}

/// Render a TOML array of rule ids, one per line, or `name = []` when empty.
fn toml_array(name: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return format!("{name} = []\n");
    }
    let mut out = format!("{name} = [\n");
    for id in ids {
        out.push_str(&format!("  \"{id}\",\n"));
    }
    out.push_str("]\n");
    out
}

/// Ids of builtin rules that are opt-in (`enabled: false` in their YAML).
/// Sorted and deduped: the same id can exist for both Rust and TypeScript.
fn opt_in_rule_ids() -> Result<Vec<String>, RuleError> {
    let mut ids: Vec<String> = load_builtin_rules()?
        .iter()
        .filter(|r| !r.enabled)
        .map(|r| r.id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Ids of correctness rules that are on by default and only ever warnings.
/// An id that is an error in any language variant is kept active, so the
/// relaxed preset never silences a correctness error.
fn correctness_warning_rule_ids() -> Result<Vec<String>, RuleError> {
    let rules = load_builtin_rules()?;
    let error_ids: HashSet<&str> = rules
        .iter()
        .filter(|r| r.severity == Severity::Error)
        .map(|r| r.id.as_str())
        .collect();
    let mut ids: Vec<String> = rules
        .iter()
        .filter(|r| {
            r.enabled
                && r.effective_category() == Category::Correctness
                && r.severity == Severity::Warning
                && !error_ids.contains(r.id.as_str())
        })
        .map(|r| r.id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn render_default() -> Result<String, RuleError> {
    Ok(format!(
        "{}{}{COMMENTED_AI_BODY}",
        header(Preset::Default),
        common_body()?
    ))
}

fn render_ai() -> Result<String, RuleError> {
    Ok(format!(
        "{}{}{LIVE_AI_BODY}",
        header(Preset::Ai),
        common_body()?
    ))
}

fn render_strict() -> Result<String, RuleError> {
    let mut out = header(Preset::Strict);
    out.push_str(RULESETS_ALL_ON);
    out.push_str(
        "\n[rules]\ndisable = []\n# Opt-in rules, all switched on by the strict preset.\n",
    );
    out.push_str(&toml_array("enable", &opt_in_rule_ids()?));
    out.push_str("# custom_dirs = [\"./my-rules\"]\n\n[scan]\nignores = []\n\n");
    out.push_str(OUTPUT_BLOCK);
    out.push_str(
        "\n# Severity threshold is a scan flag, not a config key. Strict keeps the\n\
         # default (warning), so any finding fails the run:\n\
         #   slopguard scan --severity-threshold warning\n",
    );
    out.push_str(COMMENTED_AI_BODY);
    Ok(out)
}

fn render_relaxed() -> Result<String, RuleError> {
    let mut out = header(Preset::Relaxed);
    out.push_str(
        "[rulesets]\nslop = false\nsecurity = true\ncorrectness = true\n\n\
         [rules]\n# Correctness warnings are off: only correctness errors and \
         security rules fire.\n",
    );
    out.push_str(&toml_array("disable", &correctness_warning_rule_ids()?));
    out.push_str("enable = []\n# custom_dirs = [\"./my-rules\"]\n\n[scan]\nignores = []\n\n");
    out.push_str(OUTPUT_BLOCK);
    Ok(out)
}

/// Parse a preset name (the `--preset <name>` value), returning an error
/// message that lists the valid names. Keeps the name list on the core enum
/// so the CLI never maintains its own copy.
pub fn parse_preset(value: &str) -> Result<Preset, String> {
    // strum's VariantNotFound carries no context; the message lists valid presets.
    // slopguard-disable-next-line no-swallowed-error
    value.parse().map_err(|_| {
        let names: Vec<String> = Preset::iter().map(|p| p.to_string()).collect();
        format!(
            "unknown preset '{value}' (expected one of: {})",
            names.join(", ")
        )
    })
}

/// The preset listing printed by `slopguard init --preset` with no value.
pub fn presets_help() -> String {
    let name_w = Preset::iter()
        .map(|p| p.to_string().len())
        .max()
        .unwrap_or(7);
    let mut out = String::from("Available presets:\n\n");
    for preset in Preset::iter() {
        let name = preset.to_string();
        out.push_str(&format!("  {name:<name_w$}  {}\n", preset.description()));
    }
    out.push_str("\nUsage: slopguard init --preset <name>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{AiTransport, AiVendor, Config};
    use crate::rule::{is_rule_active, Rule};

    fn parse(preset: Preset) -> Config {
        let rendered = preset.render().unwrap();
        toml::from_str(&rendered)
            .unwrap_or_else(|e| panic!("preset {preset} should render valid TOML: {e}\n{rendered}"))
    }

    fn rule_with_id(id: &str) -> Rule {
        load_builtin_rules()
            .unwrap()
            .into_iter()
            .find(|r| r.id.as_str() == id)
            .unwrap_or_else(|| panic!("builtin rule '{id}' should exist"))
    }

    #[test]
    fn every_preset_renders_valid_config() {
        for preset in Preset::iter() {
            let _config = parse(preset);
        }
    }

    #[test]
    fn every_preset_leaves_escalation_off() {
        for preset in Preset::iter() {
            let config = parse(preset);
            assert!(
                !config.escalation.enabled,
                "preset {preset} should leave escalation off"
            );
            assert_eq!(config.escalation.threshold, 5);
        }
    }

    #[test]
    fn every_preset_ends_with_one_escalation_block() {
        for preset in Preset::iter() {
            let rendered = preset.render().unwrap();
            assert!(rendered.ends_with(COMMENTED_ESCALATION_BODY));
            assert_eq!(rendered.matches("# [escalation]\n").count(), 1);
        }
    }

    #[test]
    fn every_preset_has_generated_by_header() {
        for preset in Preset::iter() {
            let rendered = preset.render().unwrap();
            let expected = format!("# Generated by: slopguard init --preset {preset}\n");
            assert!(
                rendered.starts_with(&expected),
                "preset {preset} should start with its header, got:\n{rendered}"
            );
        }
    }

    #[test]
    fn strict_enables_opt_in_rules() {
        let config = parse(Preset::Strict);
        assert!(config.rulesets.slop);
        assert!(config.rulesets.security);
        assert!(config.rulesets.correctness);
        assert!(config.rules.disable.is_empty());
        let enable = &config.rules.enable;
        assert!(enable.iter().any(|id| id == "pub-fn-needs-tracing"));
        assert!(enable.iter().any(|id| id == "test-needs-timeout"));
    }

    #[test]
    fn strict_activates_opt_in_rules() {
        let config = parse(Preset::Strict);
        let rule = rule_with_id("pub-fn-needs-tracing");
        assert!(
            is_rule_active(&rule, &config),
            "strict should activate opt-in rules"
        );
    }

    #[test]
    fn relaxed_disables_slop_and_correctness_warnings() {
        let config = parse(Preset::Relaxed);
        assert!(!config.rulesets.slop);
        assert!(config.rulesets.security);
        assert!(config.rulesets.correctness);
        let disable = &config.rules.disable;
        assert!(disable.iter().any(|id| id == "no-swallowed-error"));
        // Correctness errors and every security rule stay active.
        assert!(!disable.iter().any(|id| id == "no-unwrap-in-prod"));
        assert!(!disable.iter().any(|id| id == "no-hardcoded-secret"));
    }

    #[test]
    fn relaxed_keeps_correctness_errors_active() {
        let config = parse(Preset::Relaxed);
        assert!(!is_rule_active(
            &rule_with_id("no-swallowed-error"),
            &config
        ));
        assert!(is_rule_active(&rule_with_id("no-unwrap-in-prod"), &config));
    }

    #[test]
    fn ai_preset_enables_ai() {
        let config = parse(Preset::Ai);
        assert!(config.ai.enabled);
        assert_eq!(config.ai.provider, AiTransport::Api);
        assert_eq!(config.ai.vendor, AiVendor::Anthropic);
        assert_eq!(config.ai.model.as_deref(), Some("claude-haiku-4-5"));
    }

    #[test]
    fn default_preset_matches_defaults() {
        let config = parse(Preset::Default);
        let defaults = Config::default();
        assert_eq!(config.rulesets, defaults.rulesets);
        assert!(config.rules.enable.is_empty());
        assert!(config.rules.disable.is_empty());
        assert_eq!(config.output, defaults.output);
        assert!(!config.ai.enabled);
    }

    // The comment used to hardcode two ids while the ruleset shipped more.
    #[test]
    fn default_preset_comment_lists_every_opt_in_rule() {
        let text = Preset::Default.render().unwrap();
        let ids = opt_in_rule_ids().unwrap();
        assert!(ids.len() > 2, "expected several opt-in rules, got {ids:?}");
        for id in ids {
            assert!(
                text.contains(&format!("#   {id}\n")),
                "missing opt-in rule {id} in:\n{text}"
            );
        }
    }

    #[test]
    fn no_duplicate_ids_in_rendered_lists() {
        let strict = parse(Preset::Strict).rules.enable;
        let mut deduped = strict.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(strict.len(), deduped.len(), "strict enable has duplicates");

        let relaxed = parse(Preset::Relaxed).rules.disable;
        let mut deduped = relaxed.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            relaxed.len(),
            deduped.len(),
            "relaxed disable has duplicates"
        );
    }

    #[test]
    fn preset_from_str_roundtrip() {
        assert_eq!("strict".parse::<Preset>().unwrap(), Preset::Strict);
        assert_eq!(Preset::Strict.to_string(), "strict");
        assert_eq!(Preset::Default.to_string(), "default");
        assert_eq!(Preset::Relaxed.to_string(), "relaxed");
        assert_eq!(Preset::Ai.to_string(), "ai");
        assert_eq!(Preset::default(), Preset::Default);
    }

    #[test]
    fn presets_help_lists_every_preset() {
        let help = presets_help();
        for preset in Preset::iter() {
            assert!(
                help.contains(&preset.to_string()),
                "help should name {preset}"
            );
            assert!(
                help.contains(preset.description()),
                "help should describe {preset}"
            );
        }
    }
}
