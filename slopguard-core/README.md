# slopguard-core

Core analysis engine for slopguard. Use as a library for programmatic integration.

This crate provides the scanner, rule loading, config parsing, and finding types. For the CLI tool, see [`slopguard-cli`](https://crates.io/crates/slopguard-cli). For the full project, see the [main README](https://gitlab.com/ThomasTartrau/slopguard).

## Key Types

| Type | Module | Description |
|------|--------|-------------|
| `Scanner::scan()` | `scanner` | Scan files against a set of rules, returns `ScanResult` |
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

let config = load_config(&PathBuf::from(".")).unwrap();
let rules = load_effective_rules(&config).unwrap();
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
| `rule` | Rule loading from YAML (builtin via `slopguard-rules` + custom directories) |
| `scanner` | AST scanning via ast-grep-core |
| `finding` | Finding and scan result types |
| `disable` | Inline suppression comment parsing (`// slopguard-disable-next-line`) |
| `testing` | Rule inline test validation (should_match / should_not_match) |
| `test_filter` | Filtering findings from test code (`#[cfg(test)]` blocks) |

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
