mod common;

use common::slopguard;
use predicates::prelude::*;

/// install.sh runs `slopguard --version` under `set -eu` as its last step, so
/// a missing flag makes a successful install exit with an error.
#[test]
fn version_flag_prints_package_version() {
    slopguard()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::diff(format!(
            "slopguard {}\n",
            env!("CARGO_PKG_VERSION")
        )));
}
