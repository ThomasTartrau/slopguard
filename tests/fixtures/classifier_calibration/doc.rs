//! Calibration fixture: public items with doc-comments of varying quality.
//! Items are spread apart so the context radius (25 vs 50) changes how much
//! surrounding code the classifier sees. Labels live in labels.json, keyed by
//! the 1-based line of each `///` doc-comment.

use std::collections::HashMap;

/// Returns the user.
pub fn get_user(id: u64, store: &HashMap<u64, String>) -> Option<String> {
    store.get(&id).cloned()
}

fn normalize(name: &str) -> String {
    name.trim().to_lowercase()
}

fn split_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn count_words(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Parses the header, returning an error when a line lacks a colon or the value
/// is empty; the first duplicate key wins and later ones are ignored.
pub fn parse_header(raw: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for line in raw.lines() {
        let (k, v) = line.split_once(':').ok_or("missing colon")?;
        if v.trim().is_empty() {
            return Err("empty value".to_string());
        }
        out.entry(k.trim().to_string()).or_insert(v.trim().to_string());
    }
    Ok(out)
}

fn to_upper(name: &str) -> String {
    name.to_uppercase()
}

fn join_keys(map: &HashMap<u64, String>) -> String {
    let mut keys: Vec<u64> = map.keys().copied().collect();
    keys.sort_unstable();
    keys.iter().map(|k| k.to_string()).collect::<Vec<_>>().join(",")
}

fn first_char(text: &str) -> Option<char> {
    text.chars().next()
}

/// Creates a new Config.
pub fn new_config(name: String) -> Config {
    Config { name, retries: 0 }
}

fn retry_label(n: u8) -> String {
    format!("retry-{n}")
}

fn clamp_retries(n: u8) -> u8 {
    n.min(5)
}

/// Timeout is in milliseconds, not seconds; a zero value disables the deadline
/// entirely rather than failing fast, which surprises most callers.
pub fn with_timeout(mut config: Config, timeout_ms: u64) -> Config {
    let _ = timeout_ms;
    config.retries = clamp_retries(config.retries);
    config
}

pub struct Config {
    pub name: String,
    pub retries: u8,
}
