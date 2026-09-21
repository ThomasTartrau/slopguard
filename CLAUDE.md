# slopguard

## What is this project

A Rust CLI tool that catches AI-generated code patterns ("slop") and common correctness/security issues via static analysis. Powered by ast-grep-core (tree-sitter) as an embedded library.

Read these files before working:
- ARCHITECTURE.md - workspace structure, crate responsibilities, data flow
- DECISIONS.md - all design decisions with rationale (D1-D22)
- ROADMAP.md - what to build and in what order
- RULES.md - the builtin rules, their YAML format, and ast-grep syntax gotchas

## Current state

The project ships as a 4-crate workspace with roughly 14k lines of Rust. The scan engine, config loading, and CLI are all implemented and published to crates.io.

Delivered features:
- 85 active rules (`slopguard list`), across the `slop`, `security`, and `correctness` rulesets, covering Rust and TypeScript. 97 rule YAML files ship on disk; 12 are disabled by default (`enabled: false`), leaving 85 active.
- Autofix: `slopguard scan --fix` applies in-place rewrites for rules marked `autofix_safe` (`--fix --dry-run` to preview without writing).
- AI pipeline: LLM-backed rules run when a provider is configured; `slopguard scan --no-ai` skips them.
- Cross-file rules and file-level rules, not just single-node AST matches.
- Metrics: `slopguard stats` summarizes findings (top rules, top files).
- Baseline: `slopguard baseline` captures current findings; `scan --baseline`/`--no-baseline` control suppression.
- Diff mode: `slopguard scan --diff` scans only git-changed files (`--base <ref>` for a three-dot diff).
- Severity escalation (`scan --no-escalation` to disable).
- Output formats: `text`, `json`, `sarif`, `html` (`scan --format`).

The rule YAML files live in `slopguard-rules/rules/{correctness,security,slop}/`, each with inline `should_match`/`should_not_match` tests.

## Workspace crates

| Crate | Purpose |
|-------|---------|
| slopguard-cli | Binary crate (clap CLI, output formatting, SARIF/HTML rendering) |
| slopguard-core | Library crate: scan engine, config, rule loading, baseline, diff, escalation |
| slopguard-rules | Builtin YAML rules embedded at compile time |
| slopguard-ai | LLM provider integration for AI-backed rules |

## Build and test

```sh
cargo build
cargo test
cargo run -- scan .
cargo run -- test    # validates rule should_match/should_not_match
cargo run -- list    # shows active rules
cargo run -- init    # generates slopguard.toml
```

## Conventions

- Rust 2021 edition, stable toolchain
- Use `thiserror` for error types, `anyhow` nowhere (library crate)
- Use `clap` derive API for CLI
- No `unwrap()` or `expect()` outside tests
- Every public function has a doc-comment (but not trivial ones)
- Rule YAML: no em dashes in messages, English only, no project-specific references
- Commit messages: conventional commits (feat:, fix:, chore:, test:, docs:)

## Testing strategy

- Every rule MUST have `tests.should_match` and `tests.should_not_match` in its YAML
- `slopguard test` validates all inline rule tests
- Integration tests in `tests/` scan fixture projects and assert exact findings
- Unit tests for config parsing, rule loading, inline disable, output formatting
- Test negative cases: rules must NOT fire on valid/safe code
- Test edge cases: empty files, files with only comments, malformed YAML

## Key dependencies

| Crate | Purpose |
|-------|---------|
| ast-grep-core | AST parsing and pattern matching |
| ast-grep-config | Rule YAML parsing |
| ast-grep-language | Tree-sitter language support (Rust, TypeScript) |
| clap (derive) | CLI |
| serde + toml | Config |
| serde_json | JSON output |
| owo-colors | Terminal colors |
| ignore | Gitignore-aware file walking |
| rust-embed | Embed builtin YAML rules |

## Scope

v0.1.0 shipped AST-only scanning; AI-backed rules and autofix have since landed
(see the feature list under "Current state" and the ROADMAP for version history).
Caching is not yet implemented. Check the ROADMAP before assuming a feature is
missing or present.
