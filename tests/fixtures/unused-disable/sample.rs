// Fixture for --report-unused-disable. Scanned via a tempdir copy so the path
// carries no `fixtures`/`tests` component (no-unwrap-in-prod ignores those and
// applies skip_test_code). Each function isolates one directive case.

pub fn used_targeted(db: Db) -> User {
    // slopguard-disable-next-line no-unwrap-in-prod
    db.get_user().unwrap()
}

pub fn used_global(db: Db) -> User {
    // slopguard-disable-next-line
    db.get_user().unwrap()
}

pub fn unused_targeted(x: i32) -> i32 {
    // slopguard-disable-next-line no-unwrap-in-prod
    x + 1
}

pub fn unused_global(x: i32) -> i32 {
    // slopguard-disable-next-line
    x + 1
}

pub fn unused_wrong_rule(db: Db) -> User {
    // the directive names no-expect-in-prod but the line triggers
    // no-unwrap-in-prod: the directive suppresses nothing, and the unwrap
    // finding stays reported.
    // slopguard-disable-next-line no-expect-in-prod
    db.get_user().unwrap()
}
