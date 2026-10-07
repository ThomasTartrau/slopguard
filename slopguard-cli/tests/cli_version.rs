mod common;

use common::slopguard;
use predicates::prelude::*;

/// `cargo install` users and CI scripts check the installation with
/// `slopguard --version`, so a missing flag would break that check.
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
