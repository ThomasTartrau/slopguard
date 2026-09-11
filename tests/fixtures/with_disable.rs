// Fixture: violations with inline disable comments.
// Tests that slopguard-disable-next-line suppresses findings correctly.

fn _suppressed_all() {
    // slopguard-disable-next-line
    let user = db.get_user(id).unwrap();
}

fn _suppressed_specific() {
    // slopguard-disable-next-line no-expect-in-prod
    let conn = pool.get().expect("pool exhausted");
}

fn _not_suppressed_wrong_id() {
    // slopguard-disable-next-line nonexistent-rule
    let val = map.get("key").unwrap();
}

fn _not_suppressed() {
    let x = foo().unwrap();
}
