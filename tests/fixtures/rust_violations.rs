// Fixture: one violation per Rust rule that fires in a real scan.
// Placed in src/ at runtime for rules with files: [**/src/**].
// Rules whose inline tests fail (no-empty-env-secret, no-format-path,
// no-format-url) are excluded: they have ast-grep matching issues.

// --- slop/no-slop-words (warning) ---
// This provides a comprehensive overview of the API

// --- slop/no-trivial-doc (warning) ---
/// This method provides the user data
fn _trivial_doc() {}

// --- slop/no-paraphrase-doc (warning) ---
/// Creates a new UserService instance.
fn _paraphrase_doc() {}

// --- slop/no-and-more-doc (warning) ---
/// Supports JSON, XML, and more.
fn _and_more_doc() {}

// --- slop/no-restated-comment (warning) ---
// increment the counter
fn _restated() {}

// --- slop/no-manual-display (warning) ---
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// --- slop/no-manual-rfc3339 (warning) ---
fn _rfc3339() {
    let s = now.to_rfc3339();
}

// --- slop/no-inline-qualified-path (warning) ---
fn _inline_path() {
    let v = serde_json::Value::Null;
}

// --- slop/no-glob-reexport (warning) ---
pub use crate::models::*;

// --- security/no-debug-on-secrets (error) ---
#[derive(Debug)]
struct SecretConfig {
    api_key: String,
}

// --- security/no-unsafe-without-safety (error) ---
fn _unsafe_no_safety() {
    unsafe { ptr::read(p) };
}

// --- security/no-safety-hallucination (error) ---
fn _safety_hallucination() {
    // SAFETY: this is safe because we checked the length
    let x = vec![1, 2, 3];
}

// --- security/no-allow-dead-code (error) ---
#[allow(dead_code)]
fn _dead() {}

// --- security/no-client-without-timeout (error) ---
fn _client() {
    let client = Client::new();
}

// --- correctness/no-unwrap-in-prod (error) ---
fn _unwrap() {
    let user = db.get_user(id).unwrap();
}

// --- correctness/no-expect-in-prod (error) ---
fn _expect() {
    let conn = pool.get().expect("pool exhausted");
}

// --- correctness/no-ignored-result (error) ---
fn _ignored() {
    let _ = fs::remove_file(path);
}

// --- correctness/no-swallowed-error (warning) ---
fn _swallowed() {
    file.read_to_string(&mut buf).map_err(|_| AppError::ReadFailed);
}

// --- correctness/no-silent-fallback (warning) ---
fn _silent() {
    let name = user.name.unwrap_or("");
}

// --- correctness/no-double-fallback (warning) ---
fn _double() {
    let x = a.unwrap_or_else(|| x).unwrap_or_else(|| y);
}

// --- correctness/no-ok-chain (warning) ---
fn _ok_chain() {
    let val = parse_int(s).ok().filter(|n| *n > 0);
}

// --- correctness/pub-fn-needs-tracing (warning) ---
pub fn create_user(name: &str) -> Result<User> {
    Ok(User { name: name.to_string() })
}

// --- correctness/test-needs-timeout (warning) ---
#[tokio::test]
async fn test_fetch() {
    let result = fetch().await;
    assert!(result.is_ok());
}
