use assert_cmd::Command;

pub fn slopguard() -> Command {
    Command::cargo_bin("slopguard").unwrap()
}
