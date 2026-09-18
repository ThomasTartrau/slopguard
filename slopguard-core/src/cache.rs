use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::finding::Finding;
use crate::rule::Rule;

const RULES_HASH_FILE: &str = "rules.hash";
const CACHE_GITIGNORE: &str = "*\n";

/// Hex-encoded SHA256 of `data`. Shared by every cache key in the workspace.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Create `dir` (and parents) if missing and drop a `.gitignore` that ignores
/// the entire cache directory. Idempotent.
///
/// # Errors
///
/// Returns an [`io::Error`] if the directory or `.gitignore` cannot be written.
pub fn ensure_gitignored_dir(dir: &Path) -> Result<(), io::Error> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(".gitignore"), CACHE_GITIGNORE)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Compute a stable hash of the active rules by sorting their ids and hashing
/// the concatenated id list together with each rule's YAML-serialized body.
pub fn rules_hash(rules: &[Rule]) -> String {
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    ids.sort();

    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

/// Compute the SHA256 hash of a file's content.
pub fn file_content_hash(content: &[u8]) -> String {
    sha256_hex(content)
}

/// A file-based cache store for scan findings.
pub struct CacheStore {
    dir: PathBuf,
    /// Prepended to every entry filename so that scans run with different
    /// rulesets never collide on the same content-hashed entry. Empty when the
    /// store is not scoped to a ruleset.
    key_prefix: String,
}

impl CacheStore {
    pub fn new(project_root: &Path) -> Self {
        Self {
            dir: project_root.join(".slopguard-cache"),
            key_prefix: String::new(),
        }
    }

    /// Create a cache store that writes directly to the given directory
    /// instead of appending `.slopguard-cache`.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self {
            dir,
            key_prefix: String::new(),
        }
    }

    /// Scope this store's entries to a ruleset. Entries written by a scan with
    /// a different active ruleset use a different prefix, so a concurrent scan
    /// with fewer or disabled rules cannot serve its (correctly empty) result
    /// to a scan that expects the full ruleset to fire.
    pub fn scoped_to_rules(mut self, rules_hash: &str) -> Self {
        self.key_prefix = format!("{rules_hash}-");
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> Result<(), CacheError> {
        ensure_gitignored_dir(&self.dir)?;
        Ok(())
    }

    fn stored_rules_hash(&self) -> Option<String> {
        fs::read_to_string(self.dir.join(RULES_HASH_FILE)).ok()
    }

    fn write_rules_hash(&self, hash: &str) -> Result<(), CacheError> {
        self.ensure_dir()?;
        fs::write(self.dir.join(RULES_HASH_FILE), hash)?;
        Ok(())
    }

    /// Check if the rules have changed since the last scan. If they have,
    /// invalidate the entire cache.
    pub fn check_rules_changed(&self, current_hash: &str) -> Result<bool, CacheError> {
        match self.stored_rules_hash() {
            Some(stored) if stored == current_hash => Ok(false),
            _ => {
                self.invalidate_all()?;
                self.write_rules_hash(current_hash)?;
                Ok(true)
            }
        }
    }

    fn invalidate_all(&self) -> Result<(), CacheError> {
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str != ".gitignore" && name_str != RULES_HASH_FILE {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(())
    }

    fn entry_path(&self, file_hash: &str) -> PathBuf {
        self.dir.join(format!("{}{file_hash}.bin", self.key_prefix))
    }

    /// Look up cached findings for a file by its content hash.
    pub fn get(&self, file_hash: &str) -> Option<Vec<Finding>> {
        let path = self.entry_path(file_hash);
        let data = fs::read(&path).ok()?;
        rmp_serde::from_slice(&data).ok()
    }

    /// Store findings for a file identified by its content hash.
    pub fn put(&self, file_hash: &str, findings: &[Finding]) -> Result<(), CacheError> {
        self.ensure_dir()?;
        let data = rmp_serde::to_vec_named(findings).map_err(io::Error::other)?;
        fs::write(self.entry_path(file_hash), data)?;
        Ok(())
    }

    /// Remove cache entries whose hash no longer appears in the set of
    /// current file hashes.
    pub fn cleanup(&self, current_hashes: &[String]) -> Result<usize, CacheError> {
        if !self.dir.exists() {
            return Ok(0);
        }
        let mut removed = 0;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == ".gitignore" || name_str == RULES_HASH_FILE {
                continue;
            }
            // Only prune entries written for the active ruleset. Entries from a
            // different ruleset carry a different prefix and are left alone.
            let Some(rest) = name_str.strip_prefix(&self.key_prefix) else {
                continue;
            };
            let hash = rest.trim_end_matches(".bin");
            if !current_hashes.iter().any(|h| h == hash) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::slice;

    use tempfile::tempdir;

    use super::*;
    use crate::rule::{parse_rule, RuleId, Severity};

    fn test_rule() -> Rule {
        parse_rule(
            r#"
id: test-unwrap
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden"
rule:
  kind: call_expression
  regex: '\.unwrap\(\)\s*$'
"#,
        )
        .unwrap()
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: RuleId::from("test-unwrap"),
            severity: Severity::Error,
            category: crate::rule::Category::Correctness,
            message: ".unwrap() forbidden".to_string(),
            note: None,
            fix: None,
            file: PathBuf::from("src/main.rs"),
            line: 2,
            column: 5,
            end_line: 2,
            end_column: 20,
            matched_text: "foo().unwrap()".to_string(),
            confidence: None,
        }
    }

    #[test]
    fn cache_miss() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());
        let hash = file_content_hash(b"fn main() { foo().unwrap(); }");

        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn cache_hit() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());
        let content = b"fn main() { foo().unwrap(); }";
        let hash = file_content_hash(content);
        let findings = vec![sample_finding()];

        store.put(&hash, &findings).unwrap();
        let cached = store.get(&hash).unwrap();

        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].rule_id, RuleId::from("test-unwrap"));
        assert_eq!(cached[0].line, 2);
        assert_eq!(cached[0].matched_text, "foo().unwrap()");
    }

    #[test]
    fn invalidation_file_change() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());

        let content_v1 = b"fn main() { foo().unwrap(); }";
        let content_v2 = b"fn main() { foo()?; }";
        let hash_v1 = file_content_hash(content_v1);
        let hash_v2 = file_content_hash(content_v2);

        store.put(&hash_v1, &[sample_finding()]).unwrap();

        assert!(store.get(&hash_v1).is_some());
        assert!(store.get(&hash_v2).is_none());
    }

    #[test]
    fn invalidation_rule_change() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());

        let rules_v1 = [test_rule()];
        let hash_v1 = rules_hash(&rules_v1);

        let content_hash = file_content_hash(b"fn main() {}");
        store.put(&content_hash, &[]).unwrap();
        store.write_rules_hash(&hash_v1).unwrap();

        assert!(store.get(&content_hash).is_some());

        let mut rule_v2 = test_rule();
        rule_v2.id = RuleId::from("different-rule");
        let rules_v2 = [rule_v2];
        let hash_v2 = rules_hash(&rules_v2);
        assert_ne!(hash_v1, hash_v2);

        store.check_rules_changed(&hash_v2).unwrap();

        assert!(
            store.get(&content_hash).is_none(),
            "cache entries should be invalidated when rules change"
        );
    }

    #[test]
    fn cleanup_orphan_entries() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());

        let hash_a = file_content_hash(b"file a");
        let hash_b = file_content_hash(b"file b");
        store.put(&hash_a, &[]).unwrap();
        store.put(&hash_b, &[sample_finding()]).unwrap();

        let removed = store.cleanup(slice::from_ref(&hash_a)).unwrap();

        assert_eq!(removed, 1);
        assert!(store.get(&hash_a).is_some());
        assert!(store.get(&hash_b).is_none());
    }

    #[test]
    fn corrupted_cache_entry() {
        let dir = tempdir().unwrap();
        let store = CacheStore::new(dir.path());

        store.ensure_dir().unwrap();
        let hash = file_content_hash(b"some content");
        fs::write(store.entry_path(&hash), b"not valid bincode data!!!").unwrap();

        assert!(
            store.get(&hash).is_none(),
            "corrupted entry should return None, not panic"
        );
    }
}
