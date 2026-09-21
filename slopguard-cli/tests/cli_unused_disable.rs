mod common;

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tempfile::{tempdir, TempDir};

use common::slopguard;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/fixtures/unused-disable/sample.rs"
);

/// Copy the fixture into a fresh tempdir. Copying matters: the source lives under
/// `tests/fixtures/`, and `no-unwrap-in-prod` ignores `**/fixtures/**` and
/// `**/tests/**` (plus `skip_test_code`), so a scan pointed at it in place would
/// see no unwrap findings and every directive would look unused.
fn fixture_project() -> (TempDir, PathBuf) {
    let tmp = tempdir().unwrap();
    let dest = tmp.path().join("sample.rs");
    fs::copy(Path::new(FIXTURE), &dest).unwrap();
    (tmp, dest)
}

/// Run `scan --format json` (always `--no-ai` for a deterministic, provider-free
/// run) and return the parsed findings array. `report_unused` adds the flag.
fn scan_findings(dir: &Path, report_unused: bool) -> Vec<Value> {
    let mut cmd = slopguard();
    cmd.args(["scan", "--format", "json", "--no-ai"]);
    if report_unused {
        cmd.arg("--report-unused-disable");
    }
    let output = cmd.arg(dir.to_str().unwrap()).output().unwrap();
    let json: Value =
        serde_json::from_slice(&output.stdout).expect("scan output should be valid JSON");
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .clone()
}

/// The comment lines carrying an `unused-disable` finding, sorted.
fn unused_disable_lines(findings: &[Value]) -> Vec<u64> {
    let mut lines: Vec<u64> = findings
        .iter()
        .filter(|f| f["rule_id"] == "unused-disable")
        .map(|f| f["line"].as_u64().expect("line is a number"))
        .collect();
    lines.sort_unstable();
    lines
}

// Rows 2, 3, 5: the three directives that suppress nothing are all reported,
// anchored on their comment lines (16 targeted, 21 global, 29 wrong-rule).
#[test]
fn reports_every_unused_directive() {
    let (_tmp, dir) = fixture_project();
    let findings = scan_findings(dir.parent().unwrap(), true);
    assert_eq!(unused_disable_lines(&findings), vec![16, 21, 29]);
}

// Row 1 + Row 4: directives that actually suppressed a finding (targeted line 6,
// global line 11) are NOT reported as unused.
#[test]
fn used_directives_are_not_reported() {
    let (_tmp, dir) = fixture_project();
    let findings = scan_findings(dir.parent().unwrap(), true);
    let lines = unused_disable_lines(&findings);
    assert!(
        !lines.contains(&6),
        "used targeted directive must not be flagged"
    );
    assert!(
        !lines.contains(&11),
        "used global directive must not be flagged"
    );
}

// Row 6: without the flag, no unused-disable finding is emitted at all.
#[test]
fn without_flag_reports_no_unused_disable() {
    let (_tmp, dir) = fixture_project();
    let findings = scan_findings(dir.parent().unwrap(), false);
    assert_eq!(unused_disable_lines(&findings), Vec::<u64>::new());
}

// Row 5 (second half): a directive naming the wrong rule does not suppress the
// real finding; the unwrap on line 30 is still reported.
#[test]
fn wrong_rule_directive_leaves_real_finding() {
    let (_tmp, dir) = fixture_project();
    let findings = scan_findings(dir.parent().unwrap(), true);
    let unwrap_on_30 = findings
        .iter()
        .any(|f| f["rule_id"] == "no-unwrap-in-prod" && f["line"].as_u64() == Some(30));
    assert!(
        unwrap_on_30,
        "the wrongly-disabled unwrap must still be reported"
    );
}

// Row 7: the unused-disable findings carry the expected shape in JSON output.
#[test]
fn unused_disable_finding_shape() {
    let (_tmp, dir) = fixture_project();
    let findings = scan_findings(dir.parent().unwrap(), true);
    let first = findings
        .iter()
        .find(|f| f["rule_id"] == "unused-disable")
        .expect("at least one unused-disable finding");
    assert_eq!(first["severity"], "warning");
    assert_eq!(first["category"], "slop");
    assert!(
        first["message"]
            .as_str()
            .unwrap()
            .contains("suppresses no finding"),
        "message explains why the directive is flagged"
    );
}
