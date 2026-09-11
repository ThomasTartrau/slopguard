# slopguard

## What is this project

A Rust CLI tool that catches AI-generated code patterns ("slop") and common correctness/security issues via static analysis. Powered by ast-grep-core (tree-sitter) as an embedded library.

Read these files before working:
- ARCHITECTURE.md - workspace structure, crate responsibilities, data flow
- DECISIONS.md - all design decisions with rationale (D1-D22)
- ROADMAP.md - what to build and in what order
- RULES.md - all 34 builtin rules, their YAML format, and ast-grep syntax gotchas

## Current state

The project is at scaffolding stage. The architecture is designed, decisions are documented, but no Rust code exists yet. The 34 YAML rules exist in `~/Documents/dev/claude/personal-config/slopguard/rules/` and need to be migrated here with inline tests added.

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

## Scope for v0.1.0

AST-only, no AI. See ROADMAP.md for the full v0.1.0 checklist.
Do not add AI integration, caching, or auto-fix rewriting. Those are v0.2+.
