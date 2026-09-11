// Fixture: violations for rules that only apply to **/migrations/**/*.rs

// --- correctness/no-index-without-if-not-exists ---
fn _migration_index() {
    let sql = "CREATE INDEX idx_users_email ON users (email)";
}

// --- correctness/no-float-money ---
fn _migration_float() {
    let sql = "ALTER TABLE orders ADD COLUMN amount FLOAT";
}
