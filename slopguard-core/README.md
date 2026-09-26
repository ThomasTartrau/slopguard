# slopguard-core

Core analysis engine for slopguard. Use as a library for programmatic integration.

This crate provides the scanner, rule loading, config parsing, and finding types. For the CLI tool, see [`slopguard-cli`](https://crates.io/crates/slopguard-cli). For the full project, see the [main README](https://gitlab.com/ThomasTartrau/slopguard).

## Key Types

| Type | Module | Description |
|------|--------|-------------|
| `scan()` | `scanner` | Scan paths against a set of rules, returns `ScanResult` |
| `Config` | `config` | Parsed `slopguard.toml` configuration |
| `Rule` | `rule` | A single analysis rule (id, pattern, severity, category) |
| `RuleId` | `rule` | Newtype wrapper for rule identifiers |
| `Severity` | `rule` | `Error` or `Warning` |
| `Category` | `rule` | `Slop`, `Security`, or `Correctness` |
| `Finding` | `finding` | A single rule match (file, line, rule_id, message) |
| `ScanResult` | `finding` | Findings + scan statistics |

## Usage

```rust
use std::path::PathBuf;
use slopguard_core::config::load_config;
use slopguard_core::rule::load_effective_rules;
use slopguard_core::scanner::scan;
use slopguard_core::source::{resolve_sources, SourceOptions};

let config = load_config(&PathBuf::from(".")).unwrap();
// Fetches the `[[rules.sources]]` git repositories into the user cache.
let sources = resolve_sources(&config.rules.sources, &SourceOptions::default()).unwrap();
let rules = load_effective_rules(&config, &sources).unwrap();
let result = scan(&[PathBuf::from("src/")], &rules, &config).unwrap();

for finding in &result.findings {
    println!(
        "{}:{}  [{}] {}",
        finding.file.display(),
        finding.line,
        finding.rule_id,
        finding.message
    );
}
```

## Modules

| Module | Description |
|--------|-------------|
| `config` | Config parsing from `slopguard.toml` (hierarchical: global + project) |
| `preset` | `slopguard init --preset` config rendering |
| `rule` | Rule loading from YAML (builtin via `slopguard-rules`, custom directories, sources) |
| `source` | External rule sources: git repositories and local paths |
| `scanner` | Scan orchestration and the `RuleEngine` trait (ast, metric, cross-file engines) |
| `metric` | File-level metrics (`file_lines`, `import_count`, `function_count`, `comment_ratio`) |
| `cross_file` | Project-wide symbol index and cross-file rule kinds |
| `resolution` | Import resolution against Cargo.toml, package.json and tsconfig.json |
| `cache` | Per-file scan cache keyed by content hash |
| `finding` | Finding and scan result types |
| `disable` | Inline suppression (`// slopguard-disable-next-line`) and the unused-disable report |
| `baseline` | Baseline hashing, persistence and filtering |
| `escalation` | Severity escalation by per-file repetition |
| `fix` | `scan --fix` rewrites |
| `git` | Changed-file lists for `--diff` and the dirty-tree check for `--fix` |
| `testing` | Rule inline test validation (should_match / should_not_match / should_fix) |
| `test_filter` | Filtering findings from test code (`#[cfg(test)]` blocks, test paths) |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ast-grep-core` | AST parsing and pattern matching via tree-sitter |
| `ast-grep-config` | Rule YAML parsing |
| `ast-grep-language` | Tree-sitter language grammars (Rust, TypeScript) |
| `ignore` | Gitignore-aware file walking |
| `rayon` | Parallel file scanning |
| `serde` + `toml` | Config deserialization |

## License

MIT - see [LICENSE](../LICENSE).
