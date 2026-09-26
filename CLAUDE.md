# slopguard

## What is this project

A Rust CLI tool that catches AI-generated code patterns ("slop") and common correctness/security issues via static analysis. Powered by ast-grep-core (tree-sitter) as an embedded library.

Read these files before working:
- ARCHITECTURE.md - workspace structure, crate responsibilities, data flow
- DECISIONS.md - all design decisions with rationale (D1-D37)
- ROADMAP.md - what to build and in what order
- RULES.md - the builtin rules, their YAML format, and ast-grep syntax gotchas

## Current state

The project ships as a 4-crate workspace with roughly 22k lines of Rust. The scan engine, config loading, and CLI are all implemented and published to crates.io.

Delivered features:
- 103 active rules (`slopguard list`), across the `slop`, `security`, and `correctness` rulesets, covering Rust and TypeScript. 117 rule YAML files ship on disk; 14 are opt-in (`enabled: false`), shown by `slopguard list --all`.
- Five rule types: `ast` (85 active), `metric` (8, file-level), `cross-file` (2, project-wide index), `resolution` (2, import resolution against manifests), `ai` (6, AST pre-filter plus model confirmation).
- Autofix: `slopguard scan --fix` applies in-place rewrites for rules marked `autofix_safe` (`--fix --dry-run` to preview without writing, `--allow-dirty` to bypass the clean-tree guard).
- AI pipeline: LLM-backed rules run when a provider is configured; `slopguard scan --no-ai` skips them. An optional classifier (`[ai.classifier]`, Jev) can replace the LLM confirmation.
- Cache: per-file findings keyed by content hash, AI results under `<cache-dir>/ai/` (`--no-cache`, `--cache-dir`).
- External rule sources: `[[rules.sources]]` loads rules from git repositories or local paths (`--offline` to skip fetching).
- `scan --report-unused-disable` reports inline disables that suppress nothing.
- Metrics: `slopguard stats` summarizes findings (top rules, top files).
- Baseline: `slopguard baseline` captures current findings; `scan --baseline`/`--no-baseline` control suppression.
- Diff mode: `slopguard scan --diff` scans only git-changed files (`--base <ref>` for a three-dot diff).
- Severity escalation (`scan --no-escalation` to disable).
- Output formats: `text`, `json`, `sarif`, `html` (`scan --format`).

The rule YAML files live in `slopguard-rules/rules/{correctness,security,slop}/`, each with inline `should_match`/`should_not_match` tests (except cross-file and resolution rules, see Testing strategy).

## Workspace crates

| Crate | Purpose |
|-------|---------|
| slopguard-cli | Binary crate (clap CLI, output formatting, SARIF/HTML rendering) |
| slopguard-core | Library crate: scan engine, config, rule loading and sources, cache, baseline, diff, escalation, autofix, import resolution |
| slopguard-rules | Builtin YAML rules embedded at compile time |
| slopguard-ai | AI pass for `ai_check` rules: LLM confirmation, optional classifier, AI cache |

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

- Every rule MUST have `tests.should_match` and `tests.should_not_match` in its YAML. Exceptions: cross-file and resolution rules cannot be exercised by a snippet, so they have no `tests` block and are covered by fixtures under `tests/fixtures/` plus CLI integration tests. `slopguard test` reports them as "no tests", which is expected.
- Metric rules test whole files (`should_match_files` / `should_not_match_files`); autofixable rules add `should_fix` (`before` / `after`)
- `slopguard test` validates all inline rule tests
- Integration tests in `slopguard-cli/tests/` scan the fixture projects under `tests/fixtures/` and assert exact findings
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
| similar | Unified diff for `--fix --dry-run` |
| ignore | Gitignore-aware file walking |
| rust-embed | Embed builtin YAML rules |
| ironflow-core | LLM and classifier providers (slopguard-ai only) |

## Scope

v0.1.0 shipped AST-only scanning; AI-backed rules, autofix, caching, import
resolution and external rule sources have since landed (see the feature list
under "Current state"). Crate versions are still 0.1.x: the v0.2/v0.3/v0.4
headings in the ROADMAP are milestones, not published versions. Check the
ROADMAP before assuming a feature is missing or present.
