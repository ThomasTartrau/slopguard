use std::fs::{create_dir_all, write};

use tempfile::tempdir;

use super::*;

#[test]
fn parse_complete_config() {
    let dir = tempdir().unwrap();
    let toml = r#"
[rulesets]
slop = false
security = true
correctness = false

[rules]
disable = ["pub-fn-needs-tracing", "no-glob-reexport"]
enable = ["test-needs-timeout"]
custom_dirs = ["./my-rules"]

[scan]
ignores = ["target/", "generated/"]
test_paths = ["**/fixtures/**", "**/*.spec.ts"]

[output]
format = "json"
colors = false

[ai]
enabled = true
provider = "cli"
vendor = "openai"
model = "claude-sonnet-5"
concurrency = 8
api_key = "sk-test"

[escalation]
enabled = true
threshold = 3

[escalation.rules]
no-magic-number = 2
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(!cfg.rulesets.slop);
    assert!(cfg.rulesets.security);
    assert!(!cfg.rulesets.correctness);
    assert_eq!(
        cfg.rules.disable,
        vec!["pub-fn-needs-tracing", "no-glob-reexport"]
    );
    assert_eq!(cfg.rules.enable, vec!["test-needs-timeout"]);
    assert_eq!(cfg.rules.custom_dirs, vec![PathBuf::from("./my-rules")]);
    assert_eq!(cfg.scan.ignores, vec!["target/", "generated/"]);
    assert_eq!(cfg.scan.test_paths, vec!["**/fixtures/**", "**/*.spec.ts"]);
    assert_eq!(cfg.output.format, OutputFormat::Json);
    assert!(!cfg.output.colors);
    assert!(cfg.ai.enabled);
    assert_eq!(cfg.ai.provider, AiTransport::Cli);
    assert_eq!(cfg.ai.vendor, AiVendor::OpenAI);
    assert_eq!(cfg.ai.model.as_deref(), Some("claude-sonnet-5"));
    assert_eq!(cfg.ai.concurrency, 8);
    assert_eq!(cfg.ai.api_key.as_deref(), Some("sk-test"));
    assert!(cfg.escalation.enabled);
    assert_eq!(cfg.escalation.threshold, 3);
    assert_eq!(cfg.escalation.rules.get("no-magic-number"), Some(&2));
}

#[test]
fn parse_partial_config() {
    let dir = tempdir().unwrap();
    let toml = r#"
[rulesets]
slop = false
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(!cfg.rulesets.slop);
    assert!(cfg.rulesets.security);
    assert!(cfg.rulesets.correctness);
    assert!(cfg.rules.disable.is_empty());
    assert_eq!(cfg.output.format, OutputFormat::Text);
    assert!(cfg.output.colors);
    assert!(!cfg.ai.enabled);
    // defaults hold when [ai] is absent
    assert_eq!(cfg.ai.provider, AiTransport::Api);
    assert_eq!(cfg.ai.vendor, AiVendor::Anthropic);
    assert_eq!(cfg.ai.concurrency, 4);
    // defaults hold when [escalation] is absent
    assert!(!cfg.escalation.enabled);
    assert_eq!(cfg.escalation.threshold, 5);
    assert!(cfg.escalation.rules.is_empty());
}

#[test]
fn merge_project_overrides_global() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();

    let slopguard_config_dir = global_dir.path().join("slopguard");
    create_dir_all(&slopguard_config_dir).unwrap();

    let global_toml = r#"
[rulesets]
slop = false
security = true

[rules]
disable = ["no-glob-reexport"]

[output]
format = "json"
colors = false
"#;
    write(slopguard_config_dir.join("config.toml"), global_toml).unwrap();

    let project_toml = r#"
[rulesets]
slop = true

[output]
format = "sarif"
"#;
    write(project_dir.path().join("slopguard.toml"), project_toml).unwrap();

    let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();

    // project overrides global for slop
    assert!(cfg.rulesets.slop);
    // global value kept for security (not in project)
    assert!(cfg.rulesets.security);
    // default kept for correctness (in neither)
    assert!(cfg.rulesets.correctness);
    // global value kept for rules.disable (not in project)
    assert_eq!(cfg.rules.disable, vec!["no-glob-reexport"]);
    // project overrides global for format
    assert_eq!(cfg.output.format, OutputFormat::Sarif);
    // global value kept for colors (not in project)
    assert!(!cfg.output.colors);
}

#[test]
fn invalid_toml_error() {
    let dir = tempdir().unwrap();
    let bad_toml = "this is not [valid toml {{{";
    write(dir.path().join("slopguard.toml"), bad_toml).unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("slopguard.toml"),
        "error should mention the file path, got: {msg}"
    );
    assert!(
        matches!(err, ConfigError::Parse { .. }),
        "expected Parse error, got: {err:?}"
    );
}

#[test]
fn unknown_format_error() {
    let dir = tempdir().unwrap();
    let toml = r#"
[output]
format = "xml"
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::Parse { .. }),
        "expected Parse error for unknown format, got: {msg}"
    );
    assert!(
        msg.contains("slopguard.toml") && msg.contains("output.format"),
        "error should name the file and the key, got: {msg}"
    );
}

#[test]
fn load_config_with_temp_dirs() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();

    let slopguard_config_dir = global_dir.path().join("slopguard");
    create_dir_all(&slopguard_config_dir).unwrap();

    write(
        slopguard_config_dir.join("config.toml"),
        "[rulesets]\nslop = false\n",
    )
    .unwrap();
    write(
        project_dir.path().join("slopguard.toml"),
        "[output]\nformat = \"json\"\n",
    )
    .unwrap();

    let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();
    assert!(!cfg.rulesets.slop);
    assert_eq!(cfg.output.format, OutputFormat::Json);
    assert!(cfg.output.colors);
}

#[test]
fn load_config_global_only() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();

    let slopguard_config_dir = global_dir.path().join("slopguard");
    create_dir_all(&slopguard_config_dir).unwrap();

    write(
        slopguard_config_dir.join("config.toml"),
        "[rulesets]\ncorrectness = false\n\n[output]\nformat = \"sarif\"\n",
    )
    .unwrap();

    // No slopguard.toml in project dir
    let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();
    assert!(cfg.rulesets.slop);
    assert!(cfg.rulesets.security);
    assert!(!cfg.rulesets.correctness);
    assert_eq!(cfg.output.format, OutputFormat::Sarif);
    assert!(cfg.output.colors);
}

#[test]
fn default_config() {
    let cfg = Config::default();
    assert!(cfg.rulesets.slop);
    assert!(cfg.rulesets.security);
    assert!(cfg.rulesets.correctness);
    assert!(cfg.rules.disable.is_empty());
    assert!(cfg.rules.custom_dirs.is_empty());
    assert!(cfg.scan.ignores.is_empty());
    assert_eq!(cfg.output.format, OutputFormat::Text);
    assert!(cfg.output.colors);
    assert!(!cfg.ai.enabled);
    assert_eq!(cfg.ai.provider, AiTransport::Api);
    assert_eq!(cfg.ai.vendor, AiVendor::Anthropic);
    assert_eq!(cfg.ai.concurrency, 4);
    assert!(cfg.ai.model.is_none());
    assert!(cfg.ai.api_key.is_none());
    assert!(!cfg.escalation.enabled);
    assert_eq!(cfg.escalation.threshold, 5);
    assert!(cfg.escalation.rules.is_empty());
}

#[test]
fn escalation_section_defaults_threshold() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[escalation]\nenabled = true\n",
    )
    .unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(cfg.escalation.enabled);
    assert_eq!(cfg.escalation.threshold, 5);
}

#[test]
fn escalation_rules_merge_global_and_project() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();

    let slopguard_config_dir = global_dir.path().join("slopguard");
    create_dir_all(&slopguard_config_dir).unwrap();

    write(
        slopguard_config_dir.join("config.toml"),
        "[escalation]\nenabled = true\n\n[escalation.rules]\na = 3\n",
    )
    .unwrap();
    write(
        project_dir.path().join("slopguard.toml"),
        "[escalation.rules]\nb = 7\n",
    )
    .unwrap();

    let cfg = load_config_from(Some(global_dir.path()), project_dir.path()).unwrap();
    assert!(cfg.escalation.enabled);
    assert_eq!(cfg.escalation.rules.get("a"), Some(&3));
    assert_eq!(cfg.escalation.rules.get("b"), Some(&7));
}

#[test]
fn invalid_escalation_threshold_is_an_error() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[escalation]\nthreshold = \"five\"\n",
    )
    .unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::Parse { .. }),
        "expected Parse error for a non-numeric threshold, got: {msg}"
    );
    assert!(
        msg.contains("slopguard.toml"),
        "error should mention the file path, got: {msg}"
    );
}

#[test]
fn parse_cache_dir() {
    let dir = tempdir().unwrap();
    let toml = r#"
[scan]
cache_dir = ".cache/slopguard"
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert_eq!(cfg.scan.cache_dir, Some(PathBuf::from(".cache/slopguard")));
}

#[test]
fn parse_cache_dir_absent() {
    let dir = tempdir().unwrap();
    let toml = r#"
[scan]
ignores = ["target/"]
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(cfg.scan.cache_dir.is_none());
}

#[test]
fn parses_html_output_format() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[output]\nformat = \"html\"\n",
    )
    .unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert_eq!(cfg.output.format, OutputFormat::Html);
}

#[test]
fn enum_string_roundtrip() {
    assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
    assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!(AiVendor::OpenAI.to_string(), "openai");
    assert_eq!("openai".parse::<AiVendor>().unwrap(), AiVendor::OpenAI);
    assert_eq!(AiTransport::Cli.to_string(), "cli");
    assert_eq!("api".parse::<AiTransport>().unwrap(), AiTransport::Api);
    assert_eq!(ClassifierTransport::Openrouter.to_string(), "openrouter");
    assert_eq!(
        "direct".parse::<ClassifierTransport>().unwrap(),
        ClassifierTransport::Direct
    );
}

#[test]
fn parse_classifier_config() {
    let dir = tempdir().unwrap();
    let toml = r#"
[ai.classifier]
enabled = true
transport = "openrouter"
model = "typesafe/jev-1.13"
threshold = 0.85
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(cfg.ai.classifier.enabled);
    assert_eq!(cfg.ai.classifier.transport, ClassifierTransport::Openrouter);
    assert_eq!(
        cfg.ai.classifier.model.as_deref(),
        Some("typesafe/jev-1.13")
    );
    assert!((cfg.ai.classifier.threshold - 0.85).abs() < f64::EPSILON);
}

#[test]
fn classifier_defaults_when_absent() {
    // The classifier must be off with a 0.7 threshold when [ai.classifier] is
    // not present: opt-in strict, so a bare config never reaches Jev.
    let cfg = Config::default();
    assert!(!cfg.ai.classifier.enabled);
    assert_eq!(cfg.ai.classifier.transport, ClassifierTransport::Direct);
    assert!(cfg.ai.classifier.model.is_none());
    assert!((cfg.ai.classifier.threshold - 0.7).abs() < f64::EPSILON);
}

#[test]
fn classifier_partial_keeps_defaults() {
    // Setting only `enabled` must leave transport/threshold at their defaults.
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai.classifier]\nenabled = true\n",
    )
    .unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert!(cfg.ai.classifier.enabled);
    assert_eq!(cfg.ai.classifier.transport, ClassifierTransport::Direct);
    assert!((cfg.ai.classifier.threshold - 0.7).abs() < f64::EPSILON);
}

#[test]
fn invalid_classifier_transport_is_an_error() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai.classifier]\ntransport = \"grpc\"\n",
    )
    .unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse { .. }),
        "expected Parse error for an unknown transport, got: {err:?}"
    );
}

#[test]
fn parse_rule_sources_git_and_local() {
    let dir = tempdir().unwrap();
    let toml = r#"
[[rules.sources]]
git = "https://gitlab.com/org/slopguard-rules.git"
ref = "v1.2.0"
path = "rules/"

[[rules.sources]]
path = "../shared-rules"
"#;
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let cfg = load_config_from(None, dir.path()).unwrap();
    assert_eq!(cfg.rules.sources.len(), 2);

    let git = &cfg.rules.sources[0];
    assert_eq!(
        git.git.as_deref(),
        Some("https://gitlab.com/org/slopguard-rules.git")
    );
    assert_eq!(git.git_ref.as_deref(), Some("v1.2.0"));
    assert_eq!(git.path, Some(PathBuf::from("rules/")));
    assert!(git.is_git());

    let local = &cfg.rules.sources[1];
    assert_eq!(local.git, None);
    assert_eq!(local.git_ref, None);
    assert_eq!(local.path, Some(PathBuf::from("../shared-rules")));
    assert!(!local.is_git());
}

#[test]
fn rule_source_without_git_or_path_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\nref = \"main\"\n",
    )
    .unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidSource(_)),
        "expected InvalidSource for a source without git or path, got: {err:?}"
    );
}

#[test]
fn rule_source_ref_without_git_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\npath = \"../shared-rules\"\nref = \"main\"\n",
    )
    .unwrap();

    let err = load_config_from(None, dir.path()).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidSource(_)),
        "expected InvalidSource for a ref without git, got: {err:?}"
    );
}
