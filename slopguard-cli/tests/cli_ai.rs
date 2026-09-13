mod common;

use std::fs::{create_dir, write};
use std::path::PathBuf;

use predicates::prelude::*;
use tempfile::{tempdir, TempDir};

use common::slopguard;

/// Build a project dir with a source file, a custom-rules dir holding one
/// `ai_check` rule, and a config file. Returns (project_dir, config_path).
///
/// All rulesets are disabled so the only active rule is the custom AI rule:
/// this isolates the AI phase from builtin AST findings.
fn ai_fixture(ai_enabled: bool) -> (TempDir, PathBuf) {
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
             [rules]\ncustom_dirs = [\"{custom_dir}\"]\n\n\
             [ai]\nenabled = {ai_enabled}\nprovider = \"api\"\nvendor = \"anthropic\"\n"
        ),
    )
    .unwrap();

    (proj, config_path)
}

#[test]
fn scan_no_ai_makes_no_llm_call_and_is_silent() {
    // WHY: --no-ai must skip AI rules entirely without any network call, error,
    // or warning. The issue spec requires "pas de warning": the AI subsystem
    // must emit nothing on stderr so `scan --no-ai 2>&1 | grep -c AI` is 0.
    let (proj, config) = ai_fixture(true);

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
    let (proj, config) = ai_fixture(false);

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
