use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use getrandom::fill;
use hmac::{Hmac, Mac};
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cross_file::FileSymbols;
use crate::finding::Finding;
use crate::resolution::FileImports;
use crate::rule::Rule;

const RULES_HASH_FILE: &str = "rules.hash";
/// Extension of every cache entry file.
const CACHE_ENTRY_EXT: &str = "bin";
const CACHE_GITIGNORE: &str = "*\n";

/// Version of the on-disk entry format. Mixed into the rules hash so a bump
/// drops every stale entry instead of trying to deserialize it into the new
/// shape.
const CACHE_SCHEMA_VERSION: &str = "v6";

/// Name of the signing key file, kept in the user cache directory.
const KEY_FILE: &str = "cache.key";
/// Length of the signing key, in bytes.
const KEY_LEN: usize = 32;
/// Length of the HMAC-SHA256 tag prepended to every signed entry.
const MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// What one scanned file leaves in the cache: its findings, the symbols it
/// contributes to the cross-file index, and the imports it contributes to the
/// resolution pass, so a cache hit feeds both project-wide passes without
/// re-parsing the file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheEntry {
    pub findings: Vec<Finding>,
    pub symbols: FileSymbols,
    #[serde(default)]
    pub imports: FileImports,
}

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
    #[error("cache key file {} is not a regular file of 32 bytes", .0.display())]
    InvalidKey(PathBuf),
}

/// Root of every slopguard cache for the current user (`$XDG_CACHE_HOME/slopguard`
/// or the platform equivalent). It lives outside any scanned repository, so a
/// repository cannot ship cache entries of its own.
pub fn user_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("slopguard")
}

/// Default scan cache directory for the project rooted at `project_root`: a
/// subdirectory of [`user_cache_dir`] named after a hash of the canonical root,
/// so two projects never share (nor prune) each other's entries.
pub fn project_cache_dir(project_root: &Path) -> PathBuf {
    let root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let digest = sha256_hex(root.as_os_str().as_encoded_bytes());
    user_cache_dir().join("projects").join(&digest[..16])
}

/// Secret key signing every cache entry with HMAC-SHA256, so an entry written
/// without the key (a committed or planted file) is never trusted.
#[derive(Clone)]
pub struct CacheKey([u8; KEY_LEN]);

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheKey(..)")
    }
}

/// State of the key file on disk.
enum KeyFile {
    Valid(CacheKey),
    Missing,
    /// A regular file whose length is not [`KEY_LEN`].
    WrongLength,
}

impl CacheKey {
    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Load the key stored in `<dir>/cache.key`, creating it (random bytes,
    /// mode 0600 on unix) when missing. A key file of the wrong length is
    /// replaced, which invalidates every entry signed with the old one.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::InvalidKey`] when the key path is not a regular
    /// file (a symlink is never followed), and [`CacheError::Io`] when the key
    /// cannot be read, generated or written.
    pub fn load_or_create(dir: &Path) -> Result<Self, CacheError> {
        let path = dir.join(KEY_FILE);
        match read_key_file(&path)? {
            KeyFile::Valid(key) => return Ok(key),
            KeyFile::Missing => {}
            KeyFile::WrongLength => {
                debug!(
                    "cache key {} has a wrong length, regenerating",
                    path.display()
                );
                fs::remove_file(&path)?;
            }
        }
        let mut bytes = [0u8; KEY_LEN];
        fill(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
        fs::create_dir_all(dir)?;
        match create_key_file(&path, &bytes) {
            Ok(()) => Ok(Self(bytes)),
            // A concurrent run created the key first: use theirs. A file still
            // being written is neither trusted nor removed.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match read_key_file(&path)? {
                KeyFile::Valid(key) => Ok(key),
                KeyFile::Missing | KeyFile::WrongLength => Err(CacheError::InvalidKey(path)),
            },
            Err(err) => Err(err.into()),
        }
    }

    /// [`CacheKey::load_or_create`] in [`user_cache_dir`].
    ///
    /// # Errors
    ///
    /// Same as [`CacheKey::load_or_create`].
    pub fn load_or_create_default() -> Result<Self, CacheError> {
        Self::load_or_create(&user_cache_dir())
    }

    fn mac(&self, name: &str, payload: &[u8]) -> Result<HmacSha256, CacheError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.0).map_err(|err| io::Error::other(err.to_string()))?;
        mac.update(name.as_bytes());
        mac.update(b"\0");
        mac.update(payload);
        Ok(mac)
    }

    /// Sign `payload` for the entry called `name`: the 32-byte HMAC-SHA256 tag
    /// followed by the payload. Binding the name stops a validly signed entry
    /// from being moved onto another key.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Io`] if the HMAC cannot be initialized.
    pub fn seal(&self, name: &str, payload: &[u8]) -> Result<Vec<u8>, CacheError> {
        let tag = self.mac(name, payload)?.finalize().into_bytes();
        let mut out = Vec::with_capacity(MAC_LEN + payload.len());
        out.extend_from_slice(&tag);
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Verify data produced by [`CacheKey::seal`] for the entry called `name`
    /// and return its payload. A missing, truncated or invalid tag (compared in
    /// constant time) yields `None`, so the caller recomputes the entry.
    pub fn open<'a>(&self, name: &str, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() >= MAC_LEN {
            let (tag, payload) = data.split_at(MAC_LEN);
            let valid = self
                .mac(name, payload)
                .is_ok_and(|mac| mac.verify_slice(tag).is_ok());
            if valid {
                return Some(payload);
            }
        }
        debug!("cache entry {name}: missing or invalid HMAC, ignoring");
        None
    }
}

/// Read the key file at `path` without following a symlink.
fn read_key_file(path: &Path) -> Result<KeyFile, CacheError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(KeyFile::Missing),
        Err(err) => return Err(err.into()),
    };
    if !meta.file_type().is_file() {
        return Err(CacheError::InvalidKey(path.to_path_buf()));
    }
    let data = fs::read(path)?;
    Ok(match <[u8; KEY_LEN]>::try_from(data.as_slice()) {
        Ok(bytes) => KeyFile::Valid(CacheKey(bytes)),
        Err(_) => KeyFile::WrongLength,
    })
}

/// Create the key file, failing if it already exists. Owner-only on unix.
fn create_key_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Compute a stable hash of the active rules by sorting them by id and hashing
/// each rule's serialized body along with the scanner's own version.
///
/// The body is mixed in so editing a rule (custom or builtin) invalidates the
/// cache even when its id is unchanged. `CARGO_PKG_VERSION` is mixed in because
/// findings also depend on the scanner's built-in logic (metric computation,
/// test-path detection, cross-file passes): a new binary must drop stale
/// entries even when the rules are byte-for-byte identical.
pub fn rules_hash(rules: &[Rule]) -> String {
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

    let mut hasher = Sha256::new();
    hasher.update(CACHE_SCHEMA_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"\0");
    for rule in &sorted {
        hasher.update(rule.id.as_str().as_bytes());
        hasher.update(b"\0");
        if let Ok(body) = serde_json::to_vec(rule) {
            hasher.update(&body);
        }
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

/// Compute the SHA256 hash of a file's content.
// Domain name over the generic sha256_hex, used across the scanner.
// slopguard-disable-next-line no-trivial-function
pub fn file_content_hash(content: &[u8]) -> String {
    sha256_hex(content)
}

/// A file-based cache store for scan findings. Every entry is signed with the
/// store's [`CacheKey`]; an unsigned or tampered entry reads as a miss.
pub struct CacheStore {
    dir: PathBuf,
    /// Prepended to every entry filename so that scans run with different
    /// rulesets never collide on the same content-hashed entry. Empty when the
    /// store is not scoped to a ruleset.
    key_prefix: String,
    key: CacheKey,
}

impl CacheStore {
    /// Create a cache store that writes directly to `dir`, signing its entries
    /// with `key`.
    pub fn with_dir(dir: PathBuf, key: CacheKey) -> Self {
        Self {
            dir,
            key_prefix: String::new(),
            key,
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

    /// Remove every cache entry, sparing anything slopguard did not write.
    ///
    /// The directory may be user-supplied (`--cache-dir`, env var, config), so
    /// a directory without the `rules.hash` manifest is not treated as a cache
    /// and is left untouched. Inside a cache, only regular files named like an
    /// entry are removed: symlinks, sub-directories and foreign files survive.
    fn invalidate_all(&self) -> Result<(), CacheError> {
        if !self.dir.join(RULES_HASH_FILE).is_file() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            // `file_type` does not follow symlinks.
            if !entry.file_type()?.is_file() {
                continue;
            }
            if is_cache_entry_name(&entry.file_name().to_string_lossy()) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn entry_name(&self, file_hash: &str) -> String {
        format!("{}{file_hash}.{CACHE_ENTRY_EXT}", self.key_prefix)
    }

    fn entry_path(&self, file_hash: &str) -> PathBuf {
        self.dir.join(self.entry_name(file_hash))
    }

    /// Look up a file's cached scan result by its content hash. An entry whose
    /// signature does not verify is ignored.
    pub fn get(&self, file_hash: &str) -> Option<CacheEntry> {
        let name = self.entry_name(file_hash);
        let data = fs::read(self.entry_path(file_hash)).ok()?;
        let payload = self.key.open(&name, &data)?;
        match rmp_serde::from_slice(payload) {
            Ok(entry) => Some(entry),
            Err(err) => {
                debug!("cache entry {name}: undecodable ({err}), ignoring");
                None
            }
        }
    }

    /// Store a file's scan result, identified by its content hash and signed
    /// with the store's key.
    pub fn put(&self, file_hash: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        self.ensure_dir()?;
        let name = self.entry_name(file_hash);
        let data = rmp_serde::to_vec_named(entry).map_err(io::Error::other)?;
        fs::write(self.entry_path(file_hash), self.key.seal(&name, &data)?)?;
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
            // Like `invalidate_all`, never touch what slopguard did not write.
            if !entry.file_type()?.is_file() || !is_cache_entry_name(&name_str) {
                continue;
            }
            // Only prune entries written for the active ruleset. Entries from a
            // different ruleset carry a different prefix and are left alone.
            let Some(hash) = name_str
                .strip_prefix(&self.key_prefix)
                .and_then(strip_entry_ext)
            else {
                continue;
            };
            if !current_hashes.iter().any(|h| h == hash) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// `name` without its `.bin` extension, or `None` when it has another one.
fn strip_entry_ext(name: &str) -> Option<&str> {
    name.strip_suffix(CACHE_ENTRY_EXT)?.strip_suffix('.')
}

/// Whether `name` is shaped like a cache entry: `{rules_hash}-{file_hash}.bin`
/// or `{file_hash}.bin`, with a non-empty stem of hex digits and dashes.
fn is_cache_entry_name(name: &str) -> bool {
    strip_entry_ext(name).is_some_and(|stem| {
        !stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::slice;

    use tempfile::tempdir;

    use super::*;
    use crate::cross_file::{TestHelper, TraitDecl, TraitImpl, UnassertedTest};
    use crate::resolution::ImportRef;
    use crate::rule::{parse_rule, RuleId, Severity};

    fn test_key() -> CacheKey {
        CacheKey::from_bytes([7; 32])
    }

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
            escalated: false,
        }
    }

    #[test]
    fn cache_miss() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash = file_content_hash(b"fn main() { foo().unwrap(); }");

        assert!(store.get(&hash).is_none());
    }

    fn entry_with(findings: Vec<Finding>) -> CacheEntry {
        CacheEntry {
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn cache_hit() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let content = b"fn main() { foo().unwrap(); }";
        let hash = file_content_hash(content);

        store
            .put(&hash, &entry_with(vec![sample_finding()]))
            .unwrap();
        let cached = store.get(&hash).unwrap().findings;

        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].rule_id, RuleId::from("test-unwrap"));
        assert_eq!(cached[0].line, 2);
        assert_eq!(cached[0].matched_text, "foo().unwrap()");
    }

    #[test]
    fn cache_entry_round_trips_symbols() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash = file_content_hash(b"pub trait Repository {}");
        let entry = CacheEntry {
            findings: Vec::new(),
            imports: FileImports::default(),
            symbols: FileSymbols {
                traits: vec![TraitDecl {
                    name: "Repository".to_string(),
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 21,
                    in_cfg_test: false,
                    header: "pub trait Repository".to_string(),
                }],
                impls: vec![TraitImpl {
                    trait_name: "Repository".to_string(),
                    blanket: false,
                    self_type: "PostgresRepository".to_string(),
                }],
                error_messages: Vec::new(),
                types: vec!["PostgresRepository".to_string()],
                helpers: vec![TestHelper {
                    name: "check".to_string(),
                    asserts: true,
                    calls: vec!["parse".to_string()],
                    in_cfg_test: true,
                }],
                unasserted_tests: vec![UnassertedTest {
                    line: 3,
                    column: 1,
                    end_line: 5,
                    end_column: 2,
                    text: "fn t() {\n    check();\n}".to_string(),
                    calls: vec!["check".to_string()],
                }],
            },
        };

        store.put(&hash, &entry).unwrap();
        let cached = store.get(&hash).unwrap();

        assert_eq!(cached.symbols.traits.len(), 1);
        assert_eq!(cached.symbols.traits[0].name, "Repository");
        assert_eq!(cached.symbols.traits[0].header, "pub trait Repository");
        assert_eq!(cached.symbols.impls.len(), 1);
        assert_eq!(cached.symbols.impls[0].trait_name, "Repository");
        assert!(!cached.symbols.impls[0].blanket);
        assert_eq!(cached.symbols.impls[0].self_type, "PostgresRepository");
        assert_eq!(cached.symbols.types, vec!["PostgresRepository".to_string()]);
        assert_eq!(cached.symbols.helpers.len(), 1);
        assert_eq!(cached.symbols.helpers[0].name, "check");
        assert!(cached.symbols.helpers[0].asserts);
        assert_eq!(cached.symbols.helpers[0].calls, vec!["parse".to_string()]);
        assert!(cached.symbols.helpers[0].in_cfg_test);
        assert_eq!(cached.symbols.unasserted_tests.len(), 1);
        assert_eq!(cached.symbols.unasserted_tests[0].line, 3);
        assert_eq!(
            cached.symbols.unasserted_tests[0].text,
            "fn t() {\n    check();\n}"
        );
        assert_eq!(
            cached.symbols.unasserted_tests[0].calls,
            vec!["check".to_string()]
        );
    }

    #[test]
    fn cache_entry_round_trips_imports() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash = file_content_hash(b"use made_up_crate::Thing;");
        let entry = CacheEntry {
            imports: FileImports {
                imports: vec![ImportRef {
                    specifier: "made_up_crate".to_string(),
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 26,
                    matched_text: "use made_up_crate::Thing;".to_string(),
                }],
                local_names: vec!["foo".to_string()],
            },
            ..Default::default()
        };

        store.put(&hash, &entry).unwrap();
        let cached = store.get(&hash).unwrap();

        assert_eq!(cached.imports.imports.len(), 1);
        assert_eq!(cached.imports.imports[0].specifier, "made_up_crate");
        assert_eq!(cached.imports.local_names, vec!["foo".to_string()]);
    }

    #[test]
    fn invalidation_file_change() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());

        let content_v1 = b"fn main() { foo().unwrap(); }";
        let content_v2 = b"fn main() { foo()?; }";
        let hash_v1 = file_content_hash(content_v1);
        let hash_v2 = file_content_hash(content_v2);

        store
            .put(&hash_v1, &entry_with(vec![sample_finding()]))
            .unwrap();

        assert!(store.get(&hash_v1).is_some());
        assert!(store.get(&hash_v2).is_none());
    }

    #[test]
    fn invalidation_rule_change() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());

        let rules_v1 = [test_rule()];
        let hash_v1 = rules_hash(&rules_v1);

        let content_hash = file_content_hash(b"fn main() {}");
        store.put(&content_hash, &entry_with(Vec::new())).unwrap();
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
    fn invalidate_all_spares_foreign_files() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash_v1 = rules_hash(&[test_rule()]);
        let scoped =
            CacheStore::with_dir(dir.path().to_path_buf(), test_key()).scoped_to_rules(&hash_v1);

        let content_hash = file_content_hash(b"fn main() {}");
        scoped.put(&content_hash, &entry_with(Vec::new())).unwrap();
        store.write_rules_hash(&hash_v1).unwrap();
        let entry = scoped.entry_path(&content_hash);
        assert!(entry.is_file());

        let foreign = ["notes.txt", "data.bin", "keep.rs", "Cargo.toml"];
        for name in foreign {
            fs::write(dir.path().join(name), b"user data").unwrap();
        }
        fs::create_dir(dir.path().join("subdir")).unwrap();

        store.check_rules_changed("new-rules-hash").unwrap();

        assert!(!entry.exists(), "the real cache entry must be invalidated");
        for name in foreign {
            assert!(dir.path().join(name).is_file(), "{name} must survive");
        }
        assert!(dir.path().join("subdir").is_dir());
        assert_eq!(
            fs::read_to_string(dir.path().join(RULES_HASH_FILE)).unwrap(),
            "new-rules-hash"
        );
    }

    #[test]
    fn invalidate_all_does_nothing_without_manifest() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let lookalike = dir.path().join("abc123-def456.bin");
        fs::write(&lookalike, b"not ours").unwrap();

        assert!(store.check_rules_changed("rules-hash").unwrap());

        assert!(
            lookalike.is_file(),
            "a directory without manifest is not a cache"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(RULES_HASH_FILE)).unwrap(),
            "rules-hash"
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalidate_all_does_not_follow_symlinks() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("precious.txt");
        fs::write(&target, b"precious").unwrap();

        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        store.write_rules_hash("old-hash").unwrap();
        let link = dir.path().join("abc123-def456.bin");
        symlink(&target, &link).unwrap();

        store.check_rules_changed("new-hash").unwrap();

        assert!(target.is_file(), "the symlink target must survive");
        assert!(link.symlink_metadata().is_ok(), "the symlink is skipped");
    }

    #[test]
    fn cleanup_spares_foreign_files() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash = file_content_hash(b"file a");
        store.put(&hash, &entry_with(Vec::new())).unwrap();
        fs::write(dir.path().join("notes.txt"), b"user data").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();

        let removed = store.cleanup(&[]).unwrap();

        assert_eq!(removed, 1, "only the stale entry is pruned");
        assert!(dir.path().join("notes.txt").is_file());
        assert!(dir.path().join("subdir").is_dir());
    }

    #[test]
    fn cache_entry_name_shape() {
        assert!(is_cache_entry_name("abc123.bin"));
        assert!(is_cache_entry_name("abc123-def456.bin"));
        assert!(!is_cache_entry_name(".bin"));
        assert!(!is_cache_entry_name("data.bin"));
        assert!(!is_cache_entry_name("abc123.txt"));
        assert!(!is_cache_entry_name("abc123bin"));
        assert!(!is_cache_entry_name(RULES_HASH_FILE));
        assert!(!is_cache_entry_name(".gitignore"));
    }

    #[test]
    fn cleanup_orphan_entries() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());

        let hash_a = file_content_hash(b"file a");
        let hash_b = file_content_hash(b"file b");
        store.put(&hash_a, &entry_with(Vec::new())).unwrap();
        store
            .put(&hash_b, &entry_with(vec![sample_finding()]))
            .unwrap();

        let removed = store.cleanup(slice::from_ref(&hash_a)).unwrap();

        assert_eq!(removed, 1);
        assert!(store.get(&hash_a).is_some());
        assert!(store.get(&hash_b).is_none());
    }

    #[test]
    fn corrupted_cache_entry() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());

        store.ensure_dir().unwrap();
        let hash = file_content_hash(b"some content");
        fs::write(store.entry_path(&hash), b"not valid bincode data!!!").unwrap();

        assert!(
            store.get(&hash).is_none(),
            "corrupted entry should return None, not panic"
        );
    }

    #[test]
    fn signed_undecodable_cache_entry_is_ignored() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        store.ensure_dir().unwrap();
        let hash = file_content_hash(b"some content");
        let name = store.entry_name(&hash);
        let sealed = test_key().seal(&name, b"not msgpack").unwrap();
        fs::write(store.entry_path(&hash), sealed).unwrap();

        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn forged_cache_entry_without_hmac_is_ignored() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        store.ensure_dir().unwrap();
        let hash = file_content_hash(b"fn main() { foo().unwrap(); }");
        // What a repository could ship: a well-formed entry claiming the file
        // has no findings, but without a signature.
        let forged = rmp_serde::to_vec_named(&entry_with(Vec::new())).unwrap();
        fs::write(store.entry_path(&hash), forged).unwrap();

        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn truncated_cache_entry_is_ignored() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        store.ensure_dir().unwrap();
        let hash = file_content_hash(b"some content");
        fs::write(store.entry_path(&hash), [0u8; MAC_LEN - 1]).unwrap();

        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn tampered_cache_entry_is_ignored() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let hash = file_content_hash(b"fn main() { foo().unwrap(); }");
        store
            .put(&hash, &entry_with(vec![sample_finding()]))
            .unwrap();
        let path = store.entry_path(&hash);
        let mut data = fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        fs::write(&path, data).unwrap();

        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn cache_entry_signed_with_other_key_is_ignored() {
        let dir = tempdir().unwrap();
        let other = CacheStore::with_dir(dir.path().to_path_buf(), CacheKey::from_bytes([9; 32]));
        let hash = file_content_hash(b"fn main() { foo().unwrap(); }");
        other.put(&hash, &entry_with(Vec::new())).unwrap();
        assert!(other.get(&hash).is_some());

        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        assert!(store.get(&hash).is_none());
    }

    #[test]
    fn cache_entry_moved_to_other_name_is_ignored() {
        let dir = tempdir().unwrap();
        let store = CacheStore::with_dir(dir.path().to_path_buf(), test_key());
        let clean = file_content_hash(b"fn main() {}");
        let dirty = file_content_hash(b"fn main() { foo().unwrap(); }");
        store.put(&clean, &entry_with(Vec::new())).unwrap();
        fs::copy(store.entry_path(&clean), store.entry_path(&dirty)).unwrap();

        assert!(store.get(&clean).is_some());
        assert!(
            store.get(&dirty).is_none(),
            "a signed entry is bound to its own name"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_key_file_is_created_with_0600_and_reused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let key_dir = dir.path().join("slopguard");
        let first = CacheKey::load_or_create(&key_dir).unwrap();
        let second = CacheKey::load_or_create(&key_dir).unwrap();

        assert_eq!(first.0, second.0);
        let key_path = key_dir.join(KEY_FILE);
        assert_eq!(fs::read(&key_path).unwrap(), first.0.to_vec());
        let mode = fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn cache_key_file_wrong_length_is_regenerated() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(KEY_FILE);
        fs::write(&key_path, b"short").unwrap();

        let key = CacheKey::load_or_create(dir.path()).unwrap();

        let stored = fs::read(&key_path).unwrap();
        assert_eq!(stored.len(), KEY_LEN);
        assert_eq!(stored, key.0.to_vec());
    }

    #[test]
    fn cache_key_directory_in_place_of_file_is_rejected() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(KEY_FILE)).unwrap();

        let err = CacheKey::load_or_create(dir.path()).unwrap_err();

        assert!(matches!(err, CacheError::InvalidKey(_)), "got: {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn cache_key_symlink_is_not_followed() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("key");
        fs::write(&target, [3u8; KEY_LEN]).unwrap();
        symlink(&target, dir.path().join(KEY_FILE)).unwrap();

        let err = CacheKey::load_or_create(dir.path()).unwrap_err();

        assert!(matches!(err, CacheError::InvalidKey(_)), "got: {err:?}");
    }

    #[test]
    fn cache_key_debug_hides_bytes() {
        assert_eq!(format!("{:?}", test_key()), "CacheKey(..)");
    }

    #[test]
    fn project_cache_dir_is_outside_project_and_stable() {
        let project = tempdir().unwrap();
        let other = tempdir().unwrap();

        let dir = project_cache_dir(project.path());

        assert!(dir.starts_with(user_cache_dir()));
        assert!(!dir.starts_with(project.path()));
        assert_eq!(dir, project_cache_dir(project.path()));
        assert_ne!(dir, project_cache_dir(other.path()));
    }
}
