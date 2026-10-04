mod common;

use std::fs::{create_dir, write};
use std::path::PathBuf;

use predicates::prelude::*;
use tempfile::{tempdir, TempDir};

use common::slopguard;

/// Build a project dir with a source file, a custom-rules dir holding one
/// `ai_check` rule, and a config file. Returns (project_dir, config_path).
///
/// All rulesets are disabled and the custom AI rule is enabled by id, so it is
/// the only active rule: this isolates the AI phase from builtin AST findings.
/// `allow_external_rules` lets that custom (external) rule reach the AI phase.
fn ai_fixture(ai_enabled: bool, allow_external_rules: bool) -> (TempDir, PathBuf) {
    let proj = tempdir().unwrap();

    // A file the AI rule's AST pre-filter would match (a SAFETY comment).
    write(
        proj.path().join("main.rs"),
        "fn main() {\n    // SAFETY: trust me\n    let _x = 1;\n}\n",
    )
    .unwrap();

    let rules_dir = proj.path().join("custom-rules");
    create_dir(&rules_dir).unwrap();
    write(
        rules_dir.join("ai.yml"),
        r#"
id: ai-safety-demo
language: rust
severity: warning
category: slop
message: "AI: SAFETY comment may be meaningless"
rule:
  kind: line_comment
  regex: 'SAFETY'
ai_check:
  prompt: "Is this SAFETY comment meaningful?\n{{code}}"
"#,
    )
    .unwrap();

    let config_path = proj.path().join("slopguard.toml");
    // Forward slashes are valid in TOML strings and fine on the test platforms.
    let custom_dir = rules_dir.to_str().unwrap().replace('\\', "/");
    write(
        &config_path,
        format!(
            "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n\
             [rules]\nenable = [\"ai-safety-demo\"]\ncustom_dirs = [\"{custom_dir}\"]\n\n\
             [ai]\nenabled = {ai_enabled}\nallow_external_rules = {allow_external_rules}\n\
             provider = \"api\"\nvendor = \"anthropic\"\n"
        ),
    )
    .unwrap();

    (proj, config_path)
}

/// Like [`ai_fixture`] but enables the System One classifier instead of the
/// LLM. `[ai]` is left disabled so the classifier path is the one under test.
fn classifier_fixture() -> (TempDir, PathBuf) {
    let proj = tempdir().unwrap();
    write(
        proj.path().join("main.rs"),
        "fn main() {\n    // SAFETY: trust me\n    let _x = 1;\n}\n",
    )
    .unwrap();

    let rules_dir = proj.path().join("custom-rules");
    create_dir(&rules_dir).unwrap();
    write(
        rules_dir.join("ai.yml"),
        r#"
id: ai-safety-demo
language: rust
severity: warning
category: slop
message: "AI: SAFETY comment may be meaningless"
rule:
  kind: line_comment
  regex: 'SAFETY'
ai_check:
  prompt: "Is this SAFETY comment meaningful?\n{{code}}"
"#,
    )
    .unwrap();

    let config_path = proj.path().join("slopguard.toml");
    let custom_dir = rules_dir.to_str().unwrap().replace('\\', "/");
    write(
        &config_path,
        format!(
            "[rulesets]\nslop = false\nsecurity = false\ncorrectness = false\n\n\
             [rules]\nenable = [\"ai-safety-demo\"]\ncustom_dirs = [\"{custom_dir}\"]\n\n\
             [ai]\nenabled = false\nallow_external_rules = true\n\n\
             [ai.classifier]\nenabled = true\ntransport = \"direct\"\n"
        ),
    )
    .unwrap();

    (proj, config_path)
}

#[test]
fn scan_classifier_without_key_warns_and_skips() {
    // WHY: the classifier is opt-in strict. With [ai.classifier].enabled = true
    // but no TYPESAFE_API_KEY, the scan must fail fast (before any network call)
    // with a single warning naming the missing credential, and still succeed.
    let (proj, config) = classifier_fixture();

    slopguard()
        // Ensure a locally-set key does not turn this into a real network call.
        .env_remove("TYPESAFE_API_KEY")
        .args([
            "scan",
            "--no-colors",
            "--config",
            config.to_str().unwrap(),
            proj.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::contains("AI rules skipped"))
        // Names the exact missing credential, not a generic message.
        .stderr(predicate::str::contains("TYPESAFE_API_KEY"));
}

#[test]
fn scan_no_ai_skips_classifier_too() {
    // WHY (gate 5): --no-ai must skip Jev as well, not just the LLM. With the
    // classifier enabled but --no-ai passed, ai_check rules are dropped before
    // the classifier phase, so there is no call and no warning.
    let (proj, config) = classifier_fixture();

    slopguard()
        .env_remove("TYPESAFE_API_KEY")
        .args([
            "scan",
            "--no-ai",
            "--no-colors",
            "--config",
            config.to_str().unwrap(),
            proj.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn scan_no_ai_makes_no_llm_call_and_is_silent() {
    // WHY: --no-ai must skip AI rules entirely without any network call, error,
    // or warning. The issue spec requires "pas de warning": the AI subsystem
    // must emit nothing on stderr so `scan --no-ai 2>&1 | grep -c AI` is 0.
    let (proj, config) = ai_fixture(true, true);

    slopguard()
        .args([
            "scan",
            "--no-ai",
            "--no-colors",
            "--config",
            config.to_str().unwrap(),
            proj.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        // AI rules are excluded from AST results: no finding leaks through.
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        // No warning at all: the fixture's custom rule id and message both
        // contain "AI", so any leak would show up here.
        .stderr(predicate::str::is_empty());
}

#[test]
fn scan_without_provider_warns_and_skips_ai_rules() {
    // WHY: with an active AI rule but no usable provider ([ai].enabled = false),
    // the scan must emit a single "N AI rules skipped" warning and proceed,
    // never calling an LLM and never reporting the unconfirmed candidate.
    let (proj, config) = ai_fixture(false, true);

    slopguard()
        .args([
            "scan",
            "--no-colors",
            "--config",
            config.to_str().unwrap(),
            proj.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        // A single clear warning naming the reason (AI disabled), not an LLM call.
        .stderr(predicate::str::contains("AI rules skipped"))
        .stderr(predicate::str::contains("AI is disabled"));
}

#[test]
fn list_shows_ai_rules_with_type_column() {
    // WHY: `slopguard list` must surface AI rules and mark them with a type
    // (ast vs ai) so users can tell which rules need a provider.
    slopguard()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("type"))
        .stdout(predicate::str::contains("ai-safety-comment-validation"))
        // The builtin AI rule is tagged "ai", not "ast".
        .stdout(
            predicate::str::is_match(r"ai-safety-comment-validation\s+rust\s+\S+\s+security\s+ai")
                .unwrap(),
        );
}

#[test]
fn explain_ai_rule_shows_prompt_template() {
    // WHY: the issue requires `explain` to show the prompt template for AI
    // rules, so a rule author can inspect what is sent to the model.
    slopguard()
        .args(["explain", "ai-safety-comment-validation"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prompt:"))
        .stdout(predicate::str::contains("type:      ai"));
}

#[test]
fn scan_skips_external_ai_rule_unless_allowed() {
    // WHY: an `ai_check` rule from a custom dir or source carries a prompt the
    // user never reviewed, and running it sends code to the provider. Without
    // `ai.allow_external_rules` it is dropped (not downgraded to an AST rule,
    // which would report unconfirmed candidates) with a single warning.
    let (proj, config) = ai_fixture(false, false);

    slopguard()
        .args([
            "scan",
            "--no-colors",
            "--config",
            config.to_str().unwrap(),
            proj.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 errors, 0 warnings"))
        .stderr(predicate::str::contains(
            "warning: 1 external AI rules skipped (set ai.allow_external_rules = true in the user config to allow them)",
        ))
        // The rule never reaches the AI phase, so no provider is even built.
        .stderr(predicate::str::contains("AI is disabled").not());
}
