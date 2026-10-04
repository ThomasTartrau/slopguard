//! On-disk cache for AI verdicts.
//!
//! Keyed by the SHA256 of the file content, the resolved prompt (or classifier
//! instructions), the model, and the identity of the match (rule id, file path
//! and line/column span), so a change to any of them invalidates the entry and
//! two matches of one rule in one file never share a verdict. Verdicts are
//! stored as JSON under `<cache-dir>/ai/`, each prefixed with an HMAC-SHA256
//! tag (see [`CacheKey`]) bound to the entry name: an unsigned, tampered or
//! moved entry is ignored and the verdict recomputed.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use slopguard_core::cache::{ensure_gitignored_dir, sha256_hex, CacheKey};

use crate::pipeline::AiVerdict;

/// Compute a cache key: the SHA256 of `parts` joined by NUL bytes, so a change
/// to any part invalidates the entry. The LLM path hashes
/// `[content, prompt, model, match identity..]`; the classifier path hashes
/// `[content, rule_id, instructions, model, match identity..]` and caches the
/// raw probability under it, so retuning the threshold (applied after the cache
/// read) does not invalidate the entry.
pub fn cache_key(parts: &[&str]) -> String {
    sha256_hex(parts.join("\0").as_bytes())
}

/// A file-based store for AI verdicts, living under `<base>/ai`.
pub struct AiCache {
    dir: PathBuf,
    key: CacheKey,
}

impl AiCache {
    /// Create a cache rooted at `<base>/ai` (where `base` is the scan cache dir),
    /// signing its entries with `key`.
    pub fn new(base: &Path, key: CacheKey) -> Self {
        Self {
            dir: base.join("ai"),
            key,
        }
    }

    /// The directory holding cached verdicts.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // Names the intent and binds self.dir for two callers.
    // slopguard-disable-next-line no-trivial-function
    fn ensure_dir(&self) -> io::Result<()> {
        ensure_gitignored_dir(&self.dir)
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(entry_name(key))
    }

    /// Read, verify and deserialize the entry for `key`. Missing, unsigned,
    /// tampered or corrupted entries return `None`.
    fn read_entry<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let data = fs::read(self.entry_path(key)).ok()?;
        let payload = self.key.open(&entry_name(key), &data)?;
        serde_json::from_slice(payload).ok()
    }

    /// Serialize and sign `value` into the entry for `key`, creating the
    /// directory.
    fn write_entry<T: Serialize>(&self, key: &str, value: &T) -> io::Result<()> {
        self.ensure_dir()?;
        let data = serde_json::to_vec(value).map_err(io::Error::other)?;
        let sealed = self
            .key
            .seal(&entry_name(key), &data)
            .map_err(io::Error::other)?;
        fs::write(self.entry_path(key), sealed)
    }

    /// Look up a cached verdict by key. Corrupted entries return `None`.
    pub fn get(&self, key: &str) -> Option<AiVerdict> {
        self.read_entry(key)
    }

    /// Store a verdict for a key.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the cache directory or file cannot be written.
    pub fn put(&self, key: &str, verdict: &AiVerdict) -> io::Result<()> {
        self.write_entry(key, verdict)
    }

    /// Look up a cached classifier probability by key. Corrupted entries
    /// return `None`. The raw probability is cached, not the thresholded
    /// decision, so the threshold can be retuned without a new call.
    #[cfg(feature = "provider-typesafe")]
    pub fn get_probability(&self, key: &str) -> Option<f64> {
        self.read_entry(key)
    }

    /// Store a classifier probability for a key.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the cache directory or file cannot be written.
    #[cfg(feature = "provider-typesafe")]
    pub fn put_probability(&self, key: &str, probability: f64) -> io::Result<()> {
        self.write_entry(key, &probability)
    }
}

/// File name of the entry for `key`, also bound into its signature.
fn entry_name(key: &str) -> String {
    format!("{key}.json")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn test_key() -> CacheKey {
        CacheKey::from_bytes([7; 32])
    }

    fn verdict() -> AiVerdict {
        AiVerdict {
            is_issue: true,
            reason: "hardcoded credential".to_string(),
            confidence: 0.9,
        }
    }

    #[test]
    fn key_changes_with_each_input() {
        let base = cache_key(&["code", "prompt", "model"]);
        assert_ne!(
            base,
            cache_key(&["code2", "prompt", "model"]),
            "content matters"
        );
        assert_ne!(
            base,
            cache_key(&["code", "prompt2", "model"]),
            "prompt matters"
        );
        assert_ne!(
            base,
            cache_key(&["code", "prompt", "model2"]),
            "model matters"
        );
        assert_ne!(
            base,
            cache_key(&["code", "prompt", "model", "extra"]),
            "part count matters"
        );
        assert_eq!(base, cache_key(&["code", "prompt", "model"]), "stable");
    }

    #[test]
    fn miss_then_hit() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path(), test_key());
        let key = cache_key(&["fn main() {}", "is this slop?", "claude-haiku-4-5"]);

        assert!(cache.get(&key).is_none(), "cold cache misses");
        cache.put(&key, &verdict()).unwrap();
        let hit = cache.get(&key).expect("entry should be present after put");
        assert!(hit.is_issue);
        assert_eq!(hit.reason, "hardcoded credential");
        assert!((hit.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn corrupted_entry_returns_none() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path(), test_key());
        cache.ensure_dir().unwrap();
        let key = cache_key(&["x", "y", "z"]);
        fs::write(cache.entry_path(&key), b"not json!!!").unwrap();
        assert!(cache.get(&key).is_none(), "corrupt entry must not panic");
    }

    #[test]
    fn forged_verdict_without_hmac_is_ignored() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path(), test_key());
        cache.ensure_dir().unwrap();
        let key = cache_key(&["code", "prompt", "model"]);
        // What a repository could ship to silence an AI rule.
        fs::write(
            cache.entry_path(&key),
            br#"{"is_issue":false,"reason":"","confidence":0.0}"#,
        )
        .unwrap();

        assert!(cache.get(&key).is_none(), "an unsigned verdict is ignored");
    }

    #[test]
    fn cache_verdict_signed_with_other_key_is_ignored() {
        let dir = tempdir().unwrap();
        let other = AiCache::new(dir.path(), CacheKey::from_bytes([9; 32]));
        let key = cache_key(&["code", "prompt", "model"]);
        other.put(&key, &verdict()).unwrap();
        assert!(other.get(&key).is_some());

        let cache = AiCache::new(dir.path(), test_key());
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn tampered_cache_verdict_is_ignored() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path(), test_key());
        let key = cache_key(&["code", "prompt", "model"]);
        cache.put(&key, &verdict()).unwrap();
        let path = cache.entry_path(&key);
        let mut data = fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        fs::write(&path, data).unwrap();

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn cache_verdict_moved_to_other_key_is_ignored() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path(), test_key());
        let clean = cache_key(&["code", "prompt", "model", "clean"]);
        let dirty = cache_key(&["code", "prompt", "model", "dirty"]);
        cache
            .put(
                &clean,
                &AiVerdict {
                    is_issue: false,
                    reason: String::new(),
                    confidence: 0.0,
                },
            )
            .unwrap();
        fs::copy(cache.entry_path(&clean), cache.entry_path(&dirty)).unwrap();

        assert!(cache.get(&clean).is_some());
        assert!(cache.get(&dirty).is_none());
    }
}
