use std::fs::read_to_string;
use std::path::Path;

/// The GitLab template persists the signing key through an untracked-only
/// cached path, so a key committed to the repository is never installed.
#[test]
fn gitlab_template_persists_cache_key_untracked_only() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("ci")
        .join("slopguard.gitlab-ci.yml");
    let template = read_to_string(path).expect("read GitLab CI template");

    assert!(template.contains("      - .cache/slopguard-key/"));
    assert!(template.contains("after_script"));
    assert!(template.contains("git ls-files"));
}
