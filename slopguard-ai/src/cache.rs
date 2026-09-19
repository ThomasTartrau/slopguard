//! On-disk cache for AI verdicts.
//!
//! Keyed by `sha256(file_content + prompt + model)` so that a change to the
//! file, the resolved prompt, or the model invalidates the entry. Verdicts are
//! stored as JSON under `<cache-dir>/ai/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use slopguard_core::cache::{ensure_gitignored_dir, sha256_hex};

use crate::pipeline::AiVerdict;

/// Compute a cache key: the SHA256 of `parts` joined by NUL bytes, so a change
/// to any part invalidates the entry. The LLM path hashes
/// `[content, prompt, model]`; the classifier path hashes
/// `[content, rule_id, instructions, model]` and caches the raw probability
/// under it, so retuning the threshold (applied after the cache read) does not
/// invalidate the entry.
pub fn cache_key(parts: &[&str]) -> String {
    sha256_hex(parts.join("\0").as_bytes())
}

/// A file-based store for AI verdicts, living under `<base>/ai`.
pub struct AiCache {
    dir: PathBuf,
}

impl AiCache {
    /// Create a cache rooted at `<base>/ai` (where `base` is the scan cache dir).
    pub fn new(base: &Path) -> Self {
        Self {
            dir: base.join("ai"),
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
        self.dir.join(format!("{key}.json"))
    }

    /// Read and deserialize the entry for `key`. Missing or corrupted entries
    /// return `None`.
    fn read_entry<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let data = fs::read(self.entry_path(key)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Serialize `value` into the entry for `key`, creating the directory.
    fn write_entry<T: Serialize>(&self, key: &str, value: &T) -> io::Result<()> {
        self.ensure_dir()?;
        let data = serde_json::to_vec(value).map_err(io::Error::other)?;
        fs::write(self.entry_path(key), data)
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

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

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
        let cache = AiCache::new(dir.path());
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
        let cache = AiCache::new(dir.path());
        cache.ensure_dir().unwrap();
        let key = cache_key(&["x", "y", "z"]);
        fs::write(cache.entry_path(&key), b"not json!!!").unwrap();
        assert!(cache.get(&key).is_none(), "corrupt entry must not panic");
    }
}
