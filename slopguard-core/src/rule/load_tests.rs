use std::fs::{create_dir, write};

use tempfile::tempdir;

use super::*;

#[test]
fn rule_activation_precedence() {
    let opt_in = parse_rule(
        r#"
id: opt-in
language: rust
severity: warning
category: slop
enabled: false
message: "Opt-in"
rule:
  pattern: $X.unwrap()
"#,
    )
    .unwrap();
    let mut config = crate::config::Config::default();

    assert!(!is_rule_active(&opt_in, &config), "enabled: false is off");

    config.rules.enable.push("opt-in".to_string());
    assert!(is_rule_active(&opt_in, &config), "enable list turns it on");

    config.rules.disable.push("opt-in".to_string());
    assert!(is_rule_active(&opt_in, &config), "enable wins over disable");

    config.rulesets.slop = false;
    assert!(is_rule_active(&opt_in, &config), "enable wins over ruleset");

    config.rules.enable.clear();
    config.rules.disable.clear();
    config.rulesets.slop = true;
    let mut default_on = opt_in.clone();
    default_on.enabled = true;
    assert!(is_rule_active(&default_on, &config));

    config.rules.disable.push("opt-in".to_string());
    assert!(!is_rule_active(&default_on, &config), "disable list");

    config.rules.disable.clear();
    config.rulesets.slop = false;
    assert!(!is_rule_active(&default_on, &config), "ruleset off");
}

#[test]
fn load_all_builtin_rules() {
    let rules = load_builtin_rules().unwrap();
    assert_eq!(
        rules.len(),
        117,
        "expected 117 builtin rules, got {}",
        rules.len()
    );

    let slop_count = rules
        .iter()
        .filter(|r| r.category == Some(Category::Slop))
        .count();
    let security_count = rules
        .iter()
        .filter(|r| r.category == Some(Category::Security))
        .count();
    let correctness_count = rules
        .iter()
        .filter(|r| r.category == Some(Category::Correctness))
        .count();
    assert_eq!(slop_count, 44, "expected 44 slop rules");
    assert_eq!(security_count, 22, "expected 22 security rules");
    assert_eq!(correctness_count, 51, "expected 51 correctness rules");

    assert!(rules
        .iter()
        .any(|r| r.id == RuleId::from("no-unwrap-in-prod")));
    assert!(rules
        .iter()
        .any(|r| r.id == RuleId::from("no-debug-on-secrets")));
    assert!(rules.iter().any(|r| r.id == RuleId::from("no-slop-words")));
    assert!(
        rules
            .iter()
            .any(|r| r.id == RuleId::from("max-file-lines") && r.is_metric()),
        "max-file-lines should be loaded as a metric rule"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.id == RuleId::from("no-single-impl-trait") && r.is_cross_file()),
        "no-single-impl-trait should be loaded as a cross-file rule"
    );
    assert_eq!(
        rules
            .iter()
            .filter(|r| r.id == RuleId::from("unresolved-import") && r.is_resolution())
            .count(),
        2,
        "unresolved-import should be loaded as a resolution rule for both languages"
    );

    validate_unique_ids(&rules).unwrap();
}

#[test]
fn load_custom_rules_from_dir() {
    let dir = tempdir().unwrap();
    let rule_yaml = r#"
id: custom-rule
language: rust
severity: warning
message: "Custom rule"
rule:
  pattern: $X.clone()
"#;
    write(dir.path().join("custom.yml"), rule_yaml).unwrap();

    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, RuleId::from("custom-rule"));
}

#[test]
fn reject_duplicate_ids_same_language() {
    let rule1 = parse_rule(
        r#"
id: same-id
language: rust
severity: error
message: "First"
rule:
  pattern: $X
"#,
    )
    .unwrap();
    let rule2 = parse_rule(
        r#"
id: same-id
language: rust
severity: warning
message: "Second"
rule:
  pattern: $Y
"#,
    )
    .unwrap();
    let err = validate_unique_ids(&[rule1, rule2]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate rule id"),
        "expected duplicate id error, got: {msg}"
    );
    assert!(
        msg.contains("same-id"),
        "expected same-id in error, got: {msg}"
    );
}

#[test]
fn allow_same_id_different_language() {
    let rust_rule = parse_rule(
        r#"
id: shared-rule
language: rust
severity: error
message: "Rust variant"
rule:
  pattern: $X
"#,
    )
    .unwrap();
    let ts_rule = parse_rule(
        r#"
id: shared-rule
language: typescript
severity: error
message: "TypeScript variant"
rule:
  pattern: $X
"#,
    )
    .unwrap();
    validate_unique_ids(&[rust_rule, ts_rule]).unwrap();
}

#[test]
fn all_builtin_rules_valid_messages() {
    for path in BuiltinRules::iter() {
        if !is_rule_file(Path::new(path.as_ref())) {
            continue;
        }
        let file = BuiltinRules::get(&path).unwrap();
        let yaml = from_utf8(&file.data).unwrap();
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        assert!(
            !rule.message.contains('\u{2014}'),
            "rule '{}' message contains em dash: {}",
            rule.id,
            rule.message
        );
        assert!(
            !rule.message.contains('\u{2013}'),
            "rule '{}' message contains en dash: {}",
            rule.id,
            rule.message
        );
        assert!(
            rule.message.is_ascii() || rule.message.chars().all(|c| c.is_ascii() || c == '\''),
            "rule '{}' message contains non-ASCII characters: {}",
            rule.id,
            rule.message
        );
    }
}

#[test]
fn all_builtin_rules_have_tests() {
    for path in BuiltinRules::iter() {
        if !is_rule_file(Path::new(path.as_ref())) {
            continue;
        }
        let file = BuiltinRules::get(&path).unwrap();
        let yaml = from_utf8(&file.data).unwrap();
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        // A cross-file or resolution rule needs a whole project (and its
        // manifests) to mean anything, so no snippet can exercise it; its logic
        // is covered by unit and integration tests instead.
        if rule.cross_file.is_some() || rule.resolution.is_some() {
            continue;
        }
        let tests = rule
            .tests
            .as_ref()
            .unwrap_or_else(|| panic!("rule '{}' (at {path}) is missing `tests` block", rule.id));
        if rule.is_metric() {
            // Two near-identical whole-file fixtures add no coverage, so a
            // metric rule only needs one case per direction.
            assert!(
                tests.should_match.len() + tests.should_match_files.len() >= 1,
                "metric rule '{}' (at {path}) needs >= 1 should_match case",
                rule.id
            );
            assert!(
                tests.should_not_match.len() + tests.should_not_match_files.len() >= 1,
                "metric rule '{}' (at {path}) needs >= 1 should_not_match case",
                rule.id
            );
            continue;
        }
        assert!(
            tests.should_match.len() >= 2,
            "rule '{}' (at {path}) needs >= 2 should_match, got {}",
            rule.id,
            tests.should_match.len()
        );
        assert!(
            tests.should_not_match.len() >= 2,
            "rule '{}' (at {path}) needs >= 2 should_not_match, got {}",
            rule.id,
            tests.should_not_match.len()
        );
    }
}

#[test]
fn all_builtin_rules_have_explicit_category() {
    for path in BuiltinRules::iter() {
        if !is_rule_file(Path::new(path.as_ref())) {
            continue;
        }
        let file = BuiltinRules::get(&path).unwrap();
        let yaml = from_utf8(&file.data).unwrap();
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        assert!(
            rule.category.is_some(),
            "rule '{}' (at {path}) is missing an explicit `category` field",
            rule.id
        );
    }
}

fn fixture_metric_rule() -> Rule {
    parse_rule(
        r#"
id: fixture-reader
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 500
message: "m"
"#,
    )
    .unwrap()
}

#[test]
fn read_fixture_rejects_parent_dir() {
    let rule = fixture_metric_rule();
    let err = read_fixture(&rule, "../secrets.rs").unwrap_err();
    assert!(
        matches!(err, RuleError::InvalidFixturePath { .. }),
        "{err:?}"
    );
}

#[test]
fn read_fixture_rejects_absolute_path() {
    let rule = fixture_metric_rule();
    let err = read_fixture(&rule, "/etc/passwd").unwrap_err();
    assert!(
        matches!(err, RuleError::InvalidFixturePath { .. }),
        "{err:?}"
    );
}

#[test]
fn read_fixture_from_custom_dir() {
    let dir = tempdir().unwrap();
    let fixtures = dir.path().join("fixtures");
    create_dir(&fixtures).unwrap();
    write(
        fixtures.join("big.rs"),
        "fn a() {}
fn b() {}
",
    )
    .unwrap();
    write(
        dir.path().join("metric.yml"),
        r#"
id: custom-metric
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 1
message: "m"
tests:
  should_match_files:
    - "fixtures/big.rs"
"#,
    )
    .unwrap();

    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].source_dir.as_deref(), Some(dir.path()));
    let content = read_fixture(&rules[0], "fixtures/big.rs").unwrap();
    assert_eq!(
        content,
        "fn a() {}
fn b() {}
"
    );
}

#[test]
fn read_fixture_missing_in_custom_dir() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("metric.yml"),
        r#"
id: custom-metric-missing
language: rust
severity: warning
category: slop
metric: file_lines
threshold: 1
message: "m"
"#,
    )
    .unwrap();
    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    let err = read_fixture(&rules[0], "fixtures/nope.rs").unwrap_err();
    assert!(matches!(err, RuleError::FixtureNotFound { .. }), "{err:?}");
}

#[test]
fn read_builtin_fixture() {
    let rules = load_builtin_rules().unwrap();
    let rule = rules
        .iter()
        .find(|r| r.id == RuleId::from("max-file-lines"))
        .expect("max-file-lines should be a builtin rule");
    let content = read_fixture(rule, "fixtures/metrics/rust_large.rs").unwrap();
    assert!(
        content.lines().count() > 500,
        "the large fixture should exceed 500 lines, got {}",
        content.lines().count()
    );
}

#[test]
fn custom_rules_category_from_subdir() {
    let dir = tempdir().unwrap();
    let security_dir = dir.path().join("security");
    create_dir(&security_dir).unwrap();
    let rule_yaml = r#"
id: custom-sec
language: rust
severity: error
message: "Custom security"
rule:
  pattern: $X
"#;
    write(security_dir.join("rule.yml"), rule_yaml).unwrap();

    let rules = load_custom_rules(&[dir.path().to_path_buf()]).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].category, Some(Category::Security));
}

#[test]
fn source_reusing_builtin_id_is_rejected() {
    // A builtin id, reused by an external git source: must be rejected, not
    // silently override the builtin.
    let builtin_id = "no-unwrap-in-prod";
    let dir = tempdir().unwrap();
    let rule_yaml = format!(
        r#"
id: {builtin_id}
language: rust
severity: error
message: "Shadowing attempt"
rule:
  pattern: $X.unwrap()
"#
    );
    write(dir.path().join("shadow.yml"), rule_yaml).unwrap();

    let sources = vec![crate::source::ResolvedSource {
        dir: dir.path().to_path_buf(),
        origin: crate::source::RuleOrigin::Git {
            url: "https://example.com/rules.git".to_string(),
        },
    }];
    let config = crate::config::Config::default();

    let err = load_effective_rules(&config, &sources).unwrap_err();
    match err {
        RuleError::SourceReusesBuiltinId { id, origin } => {
            assert_eq!(id.as_str(), builtin_id);
            assert_eq!(origin, "https://example.com/rules.git");
        }
        other => panic!("expected SourceReusesBuiltinId, got: {other:?}"),
    }
}

#[test]
fn source_rules_load_with_git_origin() {
    let dir = tempdir().unwrap();
    write(
        dir.path().join("source-only.yml"),
        r#"
id: source-only-rule
language: rust
severity: warning
message: "from a source"
rule:
  pattern: foo()
"#,
    )
    .unwrap();

    let sources = vec![crate::source::ResolvedSource {
        dir: dir.path().to_path_buf(),
        origin: crate::source::RuleOrigin::Git {
            url: "https://example.com/rules.git".to_string(),
        },
    }];
    let config = crate::config::Config::default();

    let rules = load_effective_rules(&config, &sources).unwrap();
    let imported = rules
        .iter()
        .find(|r| r.id.as_str() == "source-only-rule")
        .expect("imported rule should be present");
    assert_eq!(
        imported.origin,
        crate::source::RuleOrigin::Git {
            url: "https://example.com/rules.git".to_string()
        }
    );
}
