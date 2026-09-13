//! On-disk cache for AI verdicts.
//!
//! Keyed by `sha256(file_content + prompt + model)` so that a change to the
//! file, the resolved prompt, or the model invalidates the entry. Verdicts are
//! stored as JSON under `<cache-dir>/ai/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use slopguard_core::cache::{ensure_gitignored_dir, sha256_hex};

use crate::pipeline::AiVerdict;

/// Compute the cache key for a candidate: `sha256(content \0 prompt \0 model)`,
/// so a change to any of the three invalidates the entry. Reuses the shared
/// SHA256 helper from `slopguard-core`.
pub fn cache_key(file_content: &str, resolved_prompt: &str, model: &str) -> String {
    let mut buf = Vec::with_capacity(file_content.len() + resolved_prompt.len() + model.len() + 2);
    buf.extend_from_slice(file_content.as_bytes());
    buf.push(0);
    buf.extend_from_slice(resolved_prompt.as_bytes());
    buf.push(0);
    buf.extend_from_slice(model.as_bytes());
    sha256_hex(&buf)
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

    fn ensure_dir(&self) -> io::Result<()> {
        ensure_gitignored_dir(&self.dir)
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Look up a cached verdict by key. Corrupted entries return `None`.
    pub fn get(&self, key: &str) -> Option<AiVerdict> {
        let data = fs::read(self.entry_path(key)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Store a verdict for a key.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the cache directory or file cannot be written.
    pub fn put(&self, key: &str, verdict: &AiVerdict) -> io::Result<()> {
        self.ensure_dir()?;
        let data = serde_json::to_vec(verdict).map_err(io::Error::other)?;
        fs::write(self.entry_path(key), data)?;
        Ok(())
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
        let base = cache_key("code", "prompt", "model");
        assert_ne!(
            base,
            cache_key("code2", "prompt", "model"),
            "content matters"
        );
        assert_ne!(
            base,
            cache_key("code", "prompt2", "model"),
            "prompt matters"
        );
        assert_ne!(base, cache_key("code", "prompt", "model2"), "model matters");
        assert_eq!(base, cache_key("code", "prompt", "model"), "stable");
    }

    #[test]
    fn miss_then_hit() {
        let dir = tempdir().unwrap();
        let cache = AiCache::new(dir.path());
        let key = cache_key("fn main() {}", "is this slop?", "claude-haiku-4-5");

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
        let key = cache_key("x", "y", "z");
        fs::write(cache.entry_path(&key), b"not json!!!").unwrap();
        assert!(cache.get(&key).is_none(), "corrupt entry must not panic");
    }
}
