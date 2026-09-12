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
