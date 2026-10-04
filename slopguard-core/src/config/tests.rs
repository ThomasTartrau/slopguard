use std::fs::{create_dir_all, write};
#[cfg(unix)]
use std::os::unix::fs::symlink;

use tempfile::tempdir;

use super::*;

/// Load with a trusted repo file, so the parsing tests see every key.
fn load(global: Option<&Path>, root: &Path) -> Config {
    let loaded = load_config_from(global, root, ProjectTrust::Trusted);
    loaded.unwrap().config
}

/// The error of a trusted load.
fn load_err(global: Option<&Path>, root: &Path) -> ConfigError {
    let loaded = load_config_from(global, root, ProjectTrust::Trusted);
    loaded.unwrap_err()
}

/// Load with an untrusted repo file (the default trust of a scan).
fn load_untrusted(global: Option<&Path>, root: &Path) -> LoadedConfig {
    let loaded = load_config_from(global, root, ProjectTrust::Untrusted);
    loaded.unwrap()
}

/// The error of an untrusted load.
fn load_untrusted_err(global: Option<&Path>, root: &Path) -> ConfigError {
    let loaded = load_config_from(global, root, ProjectTrust::Untrusted);
    loaded.unwrap_err()
}

/// Write `content` as the global config under `global_dir`.
fn write_global(global_dir: &Path, content: &str) {
    let dir = global_dir.join("slopguard");
    create_dir_all(&dir).unwrap();
    write(dir.join("config.toml"), content).unwrap();
}

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

    let cfg = load(None, dir.path());
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

    let cfg = load(None, dir.path());
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

    let cfg = load(Some(global_dir.path()), project_dir.path());

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

    let err = load_err(None, dir.path());
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

    let err = load_err(None, dir.path());
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

    let cfg = load(Some(global_dir.path()), project_dir.path());
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
    let cfg = load(Some(global_dir.path()), project_dir.path());
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

    let cfg = load(None, dir.path());
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

    let cfg = load(Some(global_dir.path()), project_dir.path());
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

    let err = load_err(None, dir.path());
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

    let cfg = load(None, dir.path());
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

    let cfg = load(None, dir.path());
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

    let cfg = load(None, dir.path());
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

    let cfg = load(None, dir.path());
    assert!(cfg.ai.classifier.enabled);
    assert_eq!(cfg.ai.classifier.transport, ClassifierTransport::Openrouter);
    assert_eq!(
        cfg.ai.classifier.model.as_deref(),
        Some("typesafe/jev-1.13")
    );
    assert!((cfg.ai.classifier.threshold - 0.85).abs() < f64::EPSILON);
}

#[test]
fn classifier_batch_defaults() {
    // Batching is on by default with caps of 8 questions and 200 state lines.
    let cfg = Config::default();
    assert!(cfg.ai.classifier.batch, "batching defaults on");
    assert_eq!(cfg.ai.classifier.batch_max_questions, 8);
    assert_eq!(cfg.ai.classifier.batch_max_state_lines, 200);
}

#[test]
fn classifier_batch_overrides_parse() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai.classifier]\nbatch = false\nbatch_max_questions = 3\nbatch_max_state_lines = 120\n",
    )
    .unwrap();

    let cfg = load(None, dir.path());
    assert!(!cfg.ai.classifier.batch);
    assert_eq!(cfg.ai.classifier.batch_max_questions, 3);
    assert_eq!(cfg.ai.classifier.batch_max_state_lines, 120);
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

    let cfg = load(None, dir.path());
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

    let err = load_err(None, dir.path());
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

    let cfg = load(None, dir.path());
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

    let err = load_err(None, dir.path());
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

    let err = load_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::InvalidSource(_)),
        "expected InvalidSource for a ref without git, got: {err:?}"
    );
}

#[test]
fn assertion_free_test_options_are_parsed() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules.options.no-assertion-free-test]\nassert_functions = [\"run\", \"check_*\"]\n",
    )
    .unwrap();

    let cfg = load(None, dir.path());
    assert_eq!(
        cfg.rules.options.no_assertion_free_test.assert_functions,
        vec!["run", "check_*"]
    );
}

#[test]
fn options_default_to_empty() {
    let dir = tempdir().unwrap();
    let cfg = load(None, dir.path());
    assert!(cfg
        .rules
        .options
        .no_assertion_free_test
        .assert_functions
        .is_empty());
}

#[test]
fn options_for_an_unknown_rule_are_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules.options.no-such-rule]\nassert_functions = [\"run\"]\n",
    )
    .unwrap();

    let err = load_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::Parse { .. }) && err.to_string().contains("no-such-rule"),
        "expected a parse error naming the unknown rule, got: {err}"
    );
}

#[test]
fn unknown_option_key_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules.options.no-assertion-free-test]\nassert_function = [\"run\"]\n",
    )
    .unwrap();

    let err = load_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::Parse { .. }) && err.to_string().contains("assert_function"),
        "expected a parse error naming the misspelled key, got: {err}"
    );
}

#[test]
fn repo_config_cannot_enable_ai() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai]\nenabled = true\napi_key = \"k\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert!(!loaded.config.ai.enabled);
    assert_eq!(loaded.config.ai.api_key, None);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].starts_with("ignored 'ai.api_key', 'ai.enabled' in slopguard.toml"));
    assert!(
        loaded
            .warnings
            .iter()
            .all(|w| !w.contains("\"k\"") && !w.contains("= k")),
        "warnings must not echo the api key: {:?}",
        loaded.warnings
    );
}

#[test]
fn repo_config_cannot_enable_classifier() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai.classifier]\nenabled = true\ntransport = \"openrouter\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert!(!loaded.config.ai.classifier.enabled);
    assert_eq!(
        loaded.config.ai.classifier.transport,
        ClassifierTransport::Direct
    );
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].starts_with(
        "ignored 'ai.classifier.enabled', 'ai.classifier.transport' in slopguard.toml"
    ));
}

#[test]
fn repo_config_cannot_set_cache_dir() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[scan]\ncache_dir = \"/home/victim\"\nignores = [\"target/\"]\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert_eq!(loaded.config.scan.cache_dir, None);
    assert_eq!(loaded.config.scan.ignores, vec!["target/"]);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].starts_with("ignored 'scan.cache_dir' in slopguard.toml"));
    assert!(!loaded.warnings[0].contains("/home/victim"));
}

#[test]
fn global_ai_settings_survive_repo_override() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();
    write_global(
        global_dir.path(),
        "[ai]\nenabled = true\nconcurrency = 8\n\n[scan]\ncache_dir = \"/global/cache\"\n",
    );
    write(
        project_dir.path().join("slopguard.toml"),
        "[ai]\nenabled = false\nconcurrency = 99\n\n[scan]\ncache_dir = \"/repo/cache\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(Some(global_dir.path()), project_dir.path());
    assert!(loaded.config.ai.enabled);
    assert_eq!(loaded.config.ai.concurrency, 8);
    assert_eq!(
        loaded.config.scan.cache_dir,
        Some(PathBuf::from("/global/cache"))
    );
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0]
        .starts_with("ignored 'ai.concurrency', 'ai.enabled', 'scan.cache_dir' in slopguard.toml"));
}

#[test]
fn trust_repo_config_restores_repo_ai_settings() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai]\nenabled = true\n\n[scan]\ncache_dir = \".cache/slopguard\"\n",
    )
    .unwrap();

    let loaded = load_config_from(None, dir.path(), ProjectTrust::Trusted);
    let loaded = loaded.unwrap();
    assert!(loaded.config.ai.enabled);
    assert_eq!(
        loaded.config.scan.cache_dir,
        Some(PathBuf::from(".cache/slopguard"))
    );
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn repo_rules_keys_still_apply() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rulesets]\nslop = false\n\n[rules]\ndisable = [\"no-magic-number\"]\n\n\
         [scan]\nignores = [\"generated/\"]\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert!(!loaded.config.rulesets.slop);
    assert_eq!(loaded.config.rules.disable, vec!["no-magic-number"]);
    assert_eq!(loaded.config.scan.ignores, vec!["generated/"]);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn repo_config_without_reserved_keys_has_no_warning() {
    let dir = tempdir().unwrap();
    assert!(load_untrusted(None, dir.path()).warnings.is_empty());

    write(dir.path().join("slopguard.toml"), "").unwrap();
    assert!(load_untrusted(None, dir.path()).warnings.is_empty());
}

#[test]
fn custom_dir_outside_repo_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules]\ncustom_dirs = [\"../elsewhere\"]\n",
    )
    .unwrap();
    let err = load_untrusted_err(None, dir.path());
    assert!(
        matches!(&err, ConfigError::PathOutsideRepo { key, .. } if key == "rules.custom_dirs"),
        "expected PathOutsideRepo, got: {err:?}"
    );
    assert!(err.to_string().contains("outside the repository root"));

    let outside = tempdir().unwrap();
    let outside_path = outside.path().display().to_string();
    let toml = format!("[rules]\ncustom_dirs = [{outside_path:?}]\n");
    write(dir.path().join("slopguard.toml"), toml).unwrap();
    let err = load_untrusted_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::PathOutsideRepo { .. }),
        "expected PathOutsideRepo for an absolute path, got: {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn custom_dir_symlink_escaping_repo_is_rejected() {
    let dir = tempdir().unwrap();
    let outside = tempdir().unwrap();
    symlink(outside.path(), dir.path().join("rules")).unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules]\ncustom_dirs = [\"./rules\"]\n",
    )
    .unwrap();

    let err = load_untrusted_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::PathOutsideRepo { .. }),
        "expected PathOutsideRepo for an escaping symlink, got: {err:?}"
    );
}

#[test]
fn custom_dir_inside_repo_is_accepted() {
    let dir = tempdir().unwrap();
    create_dir_all(dir.path().join("rules")).unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules]\ncustom_dirs = [\"./rules\", \"./missing\"]\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert_eq!(
        loaded.config.rules.custom_dirs,
        vec![PathBuf::from("./rules"), PathBuf::from("./missing")]
    );
}

#[test]
fn custom_dir_inside_repo_is_accepted_from_relative_root() {
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    create_dir_all(repo.join("rules")).unwrap();
    write(
        repo.join("slopguard.toml"),
        "[rules]\ncustom_dirs = [\"rules\"]\n",
    )
    .unwrap();

    // A root with a `..` hop still canonicalizes to the repository.
    let root = repo.join("rules").join("..");
    let loaded = load_untrusted(None, &root);
    assert_eq!(
        loaded.config.rules.custom_dirs,
        vec![PathBuf::from("rules")]
    );
}

#[test]
fn local_rule_source_outside_repo_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\npath = \"/tmp/x\"\n",
    )
    .unwrap();

    let err = load_untrusted_err(None, dir.path());
    assert!(
        matches!(&err, ConfigError::PathOutsideRepo { key, .. } if key == "rules.sources.path"),
        "expected PathOutsideRepo, got: {err:?}"
    );
}

#[test]
fn git_rule_source_path_is_not_checked() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\ngit = \"https://gitlab.com/org/rules.git\"\npath = \"../rules\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert_eq!(loaded.config.rules.sources.len(), 1);
}

#[test]
fn trusted_repo_may_use_external_custom_dir() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[rules]\ncustom_dirs = [\"../elsewhere\"]\n\n[[rules.sources]]\npath = \"/tmp/x\"\n",
    )
    .unwrap();

    let cfg = load(None, dir.path());
    assert_eq!(cfg.rules.custom_dirs, vec![PathBuf::from("../elsewhere")]);
    assert_eq!(cfg.rules.sources[0].path, Some(PathBuf::from("/tmp/x")));
}

#[test]
fn global_custom_dirs_are_not_restricted() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();
    write_global(
        global_dir.path(),
        "[rules]\ncustom_dirs = [\"/opt/rules\"]\n",
    );

    let loaded = load_untrusted(Some(global_dir.path()), project_dir.path());
    assert_eq!(
        loaded.config.rules.custom_dirs,
        vec![PathBuf::from("/opt/rules")]
    );
}

#[test]
fn ai_concurrency_zero_is_rejected() {
    let dir = tempdir().unwrap();
    let toml = "[ai]\nconcurrency = 0\n";
    write(dir.path().join("slopguard.toml"), toml).unwrap();

    let err = load_err(None, dir.path());
    assert!(
        matches!(err, ConfigError::InvalidConcurrency(0)),
        "expected InvalidConcurrency, got: {err:?}"
    );
    assert!(err.to_string().contains("between 1 and 64"));
}

#[test]
fn ai_concurrency_above_64_is_rejected() {
    for value in ["65", "9223372036854775807"] {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("slopguard.toml"),
            format!("[ai]\nconcurrency = {value}\n"),
        )
        .unwrap();

        let err = load_err(None, dir.path());
        assert!(
            matches!(err, ConfigError::InvalidConcurrency(_)),
            "expected InvalidConcurrency for {value}, got: {err:?}"
        );
    }
}

#[test]
fn ai_concurrency_bounds_are_accepted() {
    for value in [1, MAX_AI_CONCURRENCY] {
        let dir = tempdir().unwrap();
        write(
            dir.path().join("slopguard.toml"),
            format!("[ai]\nconcurrency = {value}\n"),
        )
        .unwrap();

        assert_eq!(load(None, dir.path()).ai.concurrency, value);
    }
}

#[test]
fn ai_concurrency_in_global_config_is_rejected() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();
    write_global(global_dir.path(), "[ai]\nconcurrency = 0\n");

    let err = load_untrusted_err(Some(global_dir.path()), project_dir.path());
    assert!(
        matches!(err, ConfigError::InvalidConcurrency(0)),
        "expected InvalidConcurrency from the global config, got: {err:?}"
    );
}

#[test]
fn ai_concurrency_in_explicit_config_file_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("custom.toml");
    write(&path, "[ai]\nconcurrency = 65\n").unwrap();

    let err = load_config_file(&path).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidConcurrency(65)),
        "expected InvalidConcurrency from --config, got: {err:?}"
    );
}

#[test]
fn ai_external_rules_and_max_calls_defaults() {
    let cfg = Config::default();
    assert!(!cfg.ai.allow_external_rules);
    assert_eq!(cfg.ai.max_calls, 200);
    assert_eq!(cfg.git.token_host, None);
}

#[test]
fn ai_external_rules_and_max_calls_parse() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();
    write_global(
        global_dir.path(),
        "[ai]\nallow_external_rules = true\nmax_calls = 0\n",
    );

    let loaded = load_untrusted(Some(global_dir.path()), project_dir.path());
    assert!(loaded.config.ai.allow_external_rules);
    assert_eq!(loaded.config.ai.max_calls, 0);
}

#[test]
fn repo_config_cannot_allow_external_ai_rules() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[ai]\nallow_external_rules = true\nmax_calls = 100000\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert!(!loaded.config.ai.allow_external_rules);
    assert_eq!(loaded.config.ai.max_calls, 200);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0]
        .starts_with("ignored 'ai.allow_external_rules', 'ai.max_calls' in slopguard.toml"));
}

#[test]
fn repo_config_cannot_set_git_token_host() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[git]\ntoken_host = \"evil.example\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(None, dir.path());
    assert_eq!(loaded.config.git.token_host, None);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].starts_with("ignored 'git.token_host' in slopguard.toml"));
}

#[test]
fn global_git_token_host_is_honored() {
    let global_dir = tempdir().unwrap();
    let project_dir = tempdir().unwrap();
    write_global(global_dir.path(), "[git]\ntoken_host = \"gitlab.com\"\n");
    write(
        project_dir.path().join("slopguard.toml"),
        "[git]\ntoken_host = \"evil.example\"\n",
    )
    .unwrap();

    let loaded = load_untrusted(Some(global_dir.path()), project_dir.path());
    assert_eq!(loaded.config.git.token_host.as_deref(), Some("gitlab.com"));
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
}

#[test]
fn rule_source_git_starting_with_dash_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\ngit = \"--upload-pack=touch /tmp/pwned\"\n",
    )
    .unwrap();

    let err = load_err(None, dir.path());
    assert!(
        matches!(&err, ConfigError::InvalidSource(msg) if msg.contains("'git' must not start with '-'")),
        "expected InvalidSource for a dash-prefixed git url, got: {err:?}"
    );
}

#[test]
fn rule_source_ref_starting_with_dash_is_rejected() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("slopguard.toml"),
        "[[rules.sources]]\ngit = \"https://gitlab.com/org/rules.git\"\nref = \"--upload-pack=touch /tmp/pwned\"\n",
    )
    .unwrap();

    let err = load_err(None, dir.path());
    assert!(
        matches!(&err, ConfigError::InvalidSource(msg) if msg.contains("'ref' must not start with '-'")),
        "expected InvalidSource for a dash-prefixed ref, got: {err:?}"
    );
}
