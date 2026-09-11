# slopguard

Static analysis tool that catches AI-generated code patterns ("slop") and common correctness/security issues. Built in Rust, powered by tree-sitter via ast-grep-core.

## Why

AI code generators produce recurring anti-patterns: trivial doc-comments, swallowed errors, silent fallbacks, filler words in comments, missing timeouts, redundant string conversions. These patterns are structurally detectable but no existing tool catches them for Rust.

slopguard fills that gap with:
- **34 builtin rules** across 3 rulesets (slop, security, correctness)
- **Rust + TypeScript** support via tree-sitter grammars
- **YAML rules** (superset of ast-grep format) with inline tests
- **Custom rules** per project via `slopguard.toml`
- **AI-powered analysis** (v0.2+) for semantic patterns that AST matching cannot catch

## Install

```sh
cargo install slopguard
```

## Usage

```sh
# Scan the current project
slopguard scan

# Scan specific paths
slopguard scan src/api/ src/handlers/

# Output as JSON for CI
slopguard scan --format json

# Output as SARIF for GitHub/GitLab integration
slopguard scan --format sarif

# Only fail on errors, not warnings
slopguard scan --severity-threshold error

# List active rules
slopguard list

# Test all rules (builtin + custom)
slopguard test

# Generate a slopguard.toml config
slopguard init
```

## Configuration

Create a `slopguard.toml` at your project root (or run `slopguard init`):

```toml
[rulesets]
slop = true         # AI-generated code patterns
security = true     # Security anti-patterns
correctness = true  # Error handling, type safety

[rules]
# Disable specific rules
disable = ["pub-fn-needs-tracing"]

# Custom rule directories
custom_dirs = ["./slopguard-rules"]

[scan]
# Files/dirs to ignore
ignores = ["target/", "generated/", "vendor/"]

[ai]
enabled = false     # Enable AI-powered rules (v0.2+)
# provider = "anthropic"
# model = "claude-sonnet-5"
```

Hierarchical config: `~/.config/slopguard/config.toml` (global) is overridden by project-level `slopguard.toml`.

## Inline suppression

```rust
// slopguard-disable-next-line
let value = risky_call().unwrap();

// slopguard-disable-next-line no-unwrap-in-prod
let value = safe_call().unwrap();
```

## Rulesets

### slop (AI code patterns)
Detects patterns that AI code generators produce at abnormally high rates.

### security
Catches security anti-patterns: secrets in Debug, path traversal via format!(), HTTP clients without timeouts, empty env secrets.

### correctness
Error handling issues: unwrap/expect in production, swallowed errors, silent fallbacks, ignored Results.

## Writing custom rules

Rules use YAML with ast-grep pattern syntax:

```yaml
id: no-todo-in-main
language: rust
severity: warning
category: correctness
message: "TODO comment in main branch. Resolve or create an issue."
note: "TODOs rot. Track them in your issue tracker."
rule:
  kind: line_comment
  regex: '//\s*TODO'
files:
  - "**/src/**/*.rs"
tests:
  should_match:
    - "// TODO fix this"
    - "// TODO: handle edge case"
  should_not_match:
    - "// this is done"
    - "// TODOIST integration"
```

Run `slopguard test` to validate your rules.

## License

MIT
