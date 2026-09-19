mod common;

use predicates::prelude::*;

use common::slopguard;

#[test]
fn explain_existing_rule() {
    slopguard()
        .args(["explain", "no-unwrap-in-prod"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no-unwrap-in-prod"))
        .stdout(predicate::str::contains("error"))
        .stdout(predicate::str::contains("correctness"))
        .stdout(predicate::str::contains(".unwrap()"))
        .stdout(predicate::str::contains("should_match"))
        .stdout(predicate::str::contains("should_not_match"));
}

#[test]
fn explain_shows_generated_reason_for_relational_rule() {
    // Gate: a relational rule escalates to the LLM for a per-instance reason.
    slopguard()
        .args(["explain", "ai-ssrf-unvalidated-url"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reason:"))
        .stdout(predicate::str::contains("generated"));
}

#[test]
fn explain_shows_static_reason_for_note_rule() {
    // Gate: a non-relational ai_check rule uses its static note.
    slopguard()
        .args(["explain", "ai-doc-comment-quality"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reason:"))
        .stdout(predicate::str::contains("static"));
}

#[test]
fn explain_unknown_rule_suggests() {
    slopguard()
        .args(["explain", "no-unwarp-in-prod"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no-unwrap-in-prod"));
}

#[test]
fn explain_unknown_no_suggestion() {
    slopguard()
        .args(["explain", "zzz-completely-fake-rule"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"))
        .stderr(predicate::str::contains("Did you mean").not());
}

#[test]
fn explain_json_output() {
    let output = slopguard()
        .args(["explain", "no-unwrap-in-prod", "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    assert_eq!(json["id"].as_str(), Some("no-unwrap-in-prod"));
    assert_eq!(json["severity"].as_str(), Some("error"));
    assert_eq!(json["category"].as_str(), Some("correctness"));
    assert!(json["message"].is_string());
    assert!(json["should_match"].is_array());
    assert!(json["should_not_match"].is_array());
}

#[test]
fn explain_metric_rule_text() {
    slopguard()
        .args(["explain", "max-file-lines"])
        .assert()
        .success()
        .stdout(predicate::str::contains("type:      metric"))
        .stdout(predicate::str::contains("metric:    file_lines"))
        .stdout(predicate::str::contains("threshold: 500"));
}

#[test]
fn explain_metric_rule_json() {
    let output = slopguard()
        .args(["explain", "max-file-lines", "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("output should be valid JSON");

    assert_eq!(json["id"].as_str(), Some("max-file-lines"));
    assert_eq!(json["type"].as_str(), Some("metric"));
    assert_eq!(json["metric"].as_str(), Some("file_lines"));
    assert_eq!(json["threshold"].as_f64(), Some(500.0));
}
