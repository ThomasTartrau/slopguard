# Architecture

## Overview

slopguard is a Rust CLI tool that scans source code for AI-generated anti-patterns and common issues. It embeds ast-grep-core as a library (no external binary dependency) and organizes rules into thematic rulesets.

```
slopguard scan [path]
  |
  +-- Phase 1: AST analysis (ast-grep-core, deterministic, instant)
  |     -> structural findings
  |
  +-- Phase 2: AI analysis (v0.2+, ironflow SDK, on pre-filtered candidates)
  |     -> semantic findings
  |
  +-- Unified output (same format, severity, file:line)
```

## Workspace structure

```
slopguard/
  Cargo.toml              # workspace root
  slopguard-cli/          # binary crate (clap CLI)
  slopguard-core/         # library crate (scan engine, config, rule loading)
  slopguard-rules/        # builtin rules (YAML files embedded at compile time)
  tests/                  # integration tests
```

### slopguard-cli

The binary crate. Responsible for:
- CLI argument parsing via clap (derive API)
- Subcommands: scan, stats, baseline, explain, init, test, list
- Output formatting (text with colors, JSON, SARIF, HTML)
- Exit code logic (0 = clean, 1 = findings, 2 = config error)
- Reading config from slopguard.toml (hierarchical: global + project)

Dependencies: clap, slopguard-core, serde_json, colored/owo-colors, sarif (for SARIF output)

### slopguard-core

The library crate. Responsible for:
- Rule loading and validation (builtin + custom YAML)
- AST scanning via ast-grep-core
- Inline disable comment parsing (// slopguard-disable-next-line)
- Config parsing (slopguard.toml via serde + toml)
- Finding representation (file, line, rule_id, severity, message, note)
- Baseline hashing, persistence and filtering (baseline.rs)
- Project-wide (cross-file) analysis: per-file symbol extraction and the index
  they are folded into (cross_file.rs). A cache entry carries the file's symbol
  contribution alongside its findings, so a cache hit feeds the cross-file pass
  without reparsing.
- Git diff resolution for `--diff` (git.rs)
- Rule testing (should_match / should_not_match validation)
- Ruleset management (slop, security, correctness)

Dependencies: ast-grep-core, ast-grep-config, ast-grep-language, serde, toml, glob/ignore

### slopguard-rules

Contains the builtin YAML rules organized by ruleset:
```
slopguard-rules/
  src/
    lib.rs                # exports embedded rules via include_str! or rust-embed
  rules/
    slop/
      no-slop-words.yml
      no-trivial-doc.yml
      no-paraphrase-doc.yml
      no-and-more-doc.yml
      no-restated-comment.yml
      no-manual-display.yml
      no-manual-rfc3339.yml
      no-inline-qualified-path.yml
      no-glob-reexport.yml
    security/
      no-debug-on-secrets.yml
      no-empty-env-secret.yml
      no-format-path.yml
      no-format-url.yml
      no-unsafe-without-safety.yml
      no-safety-hallucination.yml
      no-allow-dead-code.yml
      no-client-without-timeout.yml
    correctness/
      no-unwrap-in-prod.yml
      no-expect-in-prod.yml
      no-ignored-result.yml
      no-swallowed-error.yml
      no-silent-fallback.yml
      no-double-fallback.yml
      no-ok-chain.yml
      no-sqlx-runtime.yml
      no-index-without-if-not-exists.yml
      no-float-money.yml
      pub-fn-needs-tracing.yml
      test-needs-timeout.yml
      no-any-typescript.yml
      no-async-foreach.yml
      no-replace-single.yml
      no-sort-without-comparator.yml
      no-useeffect-derived-state.yml
```

Dependencies: rust-embed (or include_str! macros)

## Rule format (YAML)

Superset of ast-grep rule format. All ast-grep fields are valid. Additional slopguard fields:

```yaml
# Required (ast-grep compatible)
id: rule-id                    # unique kebab-case identifier
language: rust                 # rust | typescript
severity: error                # error | warning
message: "Short description"  # shown in output, no em dashes
rule:                          # ast-grep rule object (pattern, kind, regex, all, any, not, has, precedes, follows, inside)

# Optional (ast-grep compatible)
note: "Explanation"            # shown below the finding
files: ["**/src/**/*.rs"]      # glob include patterns
ignores: ["**/tests/**"]       # glob exclude patterns

# Slopguard extensions
category: slop                 # slop | security | correctness (derived from ruleset dir if omitted)
fix: "Use X instead of Y"     # textual suggestion (v0.1), ast-grep rewrite pattern (future)
skip_test_code: true           # drop findings inside #[cfg(test)] blocks (Rust only, default false)
tests:                         # inline test cases
  should_match:
    - "code snippet that triggers the rule"
    - "another triggering snippet"
  should_not_match:
    - "code snippet that must NOT trigger"
    - "another safe snippet"
```

### File-level metric rules

`metric` and `threshold` replace `rule`: they are mutually exclusive with it,
and a rule that sets neither (or sets `metric` without `threshold`) is rejected
at parse time. A metric rule measures the whole file and reports a single
finding anchored at line 1 when the measured value is **strictly greater than**
the threshold.

```yaml
metric: file_lines             # file_lines | import_count | function_count | comment_ratio
threshold: 500                 # required with `metric`; firing is strictly `>`
message: "File exceeds 500 lines ($value lines)."   # $value is the measured value
tests:                         # a metric cannot be measured on a snippet
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
  should_not_match_files:
    - "fixtures/metrics/rust_small.rs"
```

| Metric | Measures |
|--------|----------|
| `file_lines` | `str::lines()` count, so a trailing newline terminates the last line (`"a\n"` is 1 line) |
| `import_count` | `use` / `extern crate` (Rust), `import` statements (TypeScript), including nested ones |
| `function_count` | `function_item` (Rust); declarations, function expressions, arrow functions and methods (TypeScript). Nested functions count |
| `comment_ratio` | distinct comment lines divided by total lines; `0.0` for an empty file |

Metric rules are evaluated outside ast-grep, so the scanner applies their
`files` / `ignores` globs itself, and `skip_test_code` drops the whole file
rather than a line range.

Fixture paths are relative: builtin rules resolve them against the embedded
ruleset root, custom rules against the directory they were loaded from.
Absolute paths and `..` components are rejected.

### Cross-file rules

`cross_file` replaces `rule` and `metric` and is mutually exclusive with both.
It names a builtin analysis; the only kind today is `single_impl_trait`.

```yaml
cross_file: single_impl_trait  # the only kind in v0.1
skip_test_code: true           # applies to the declaration site
ignores: ["**/target/**"]      # applies to the declaration site
```

The logic behind a kind is builtin Rust keyed on the discriminant, so a custom
YAML can retune a rule's severity, message, `files` / `ignores` and
`skip_test_code`, but cannot invent a new kind: an unknown discriminant is a
parse error. A cross-file rule carries no `tests` block, since no snippet can
exercise it, and `slopguard test` reports it as untested.

The pass runs after the per-file scan, over the walked paths only. Each scanned
Rust file contributes a `FileSymbols` (its trait declarations and its
`impl Trait for Type` headers) from the same parse that produced its findings;
those contributions are folded into a project-wide `SymbolIndex` and every
active cross-file rule is evaluated against it. `--diff` and any explicit file
list skip evaluation, because their index would be incomplete, but they still
collect and cache contributions so a later full scan is not penalised.

## Config format (slopguard.toml)

```toml
[rulesets]
slop = true
security = true
correctness = true

[rules]
disable = ["pub-fn-needs-tracing", "no-glob-reexport"]
custom_dirs = ["./my-rules"]

[scan]
ignores = ["target/", "generated/", "*.generated.rs"]

[output]
format = "text"    # text | json | sarif | html
colors = true

[ai]
enabled = false
provider = "anthropic"   # anthropic | openai | ollama
model = "claude-sonnet-5"
# api_key via ANTHROPIC_API_KEY / OPENAI_API_KEY env var

[escalation]
enabled = false    # opt-in
threshold = 5      # same rule firing N times in one file becomes an error

[escalation.rules]
no-magic-number = 3    # per-rule override
```

Hierarchical resolution:
1. `~/.config/slopguard/config.toml` (global defaults)
2. `slopguard.toml` at project root (overrides global)
3. CLI flags (override everything)

## Output formats

### Text (default)
Colored output with code snippets, similar to ast-grep/rustc diagnostics:
```
error[no-unwrap-in-prod]: .unwrap() forbidden in production. Use ? or .expect('explicit message').
   --> src/api/handler.rs:42:5
    |
 42 |     let user = db.get_user(id).unwrap();
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = unwrap() crashes the process on a single invalid input.
```

### JSON
```json
{
  "findings": [
    {
      "rule_id": "no-unwrap-in-prod",
      "severity": "error",
      "category": "correctness",
      "message": ".unwrap() forbidden in production.",
      "file": "src/api/handler.rs",
      "line": 42,
      "column": 5,
      "end_line": 42,
      "end_column": 40,
      "note": "unwrap() crashes the process on a single invalid input.",
      "fix": "Use ? or .expect('explicit message').",
      "escalated": false
    }
  ],
  "summary": { "errors": 1, "warnings": 0, "total": 1 },
  "stats": {
    "errors": 1,
    "warnings": 0,
    "total": 1,
    "files_scanned": 12,
    "baseline_filtered": 0,
    "diff_base": "main",
    "files_changed": 3
  }
}
```

`summary` is kept for backward compatibility; `stats` is the full set and the one
to read in CI. `diff_base` and `files_changed` appear only in `--diff` mode; a
normal scan omits them entirely.

### SARIF
Standard SARIF 2.1.0 for GitHub Code Scanning / GitLab SAST integration.

### HTML
A standalone single-file report rendered from `slopguard-cli/templates/report.html`
(embedded with `include_str!`). The CLI expands `{{PLACEHOLDER}}` tokens with
server-rendered markup: the header totals, one horizontal bar per severity,
category and language, and one table row per finding plus a detail row carrying
the matched snippet. Styles and the filter script are inlined, so the document
makes no external request, and colors are CSS custom properties overridden under
`@media (prefers-color-scheme: dark)`.

Every value taken from scanned source (message, note, fix, snippet, file path)
goes through a single-pass HTML escape before it reaches the document.

`-o/--output <path>` writes the report to a file instead of stdout. It works for
every format and never emits ANSI escapes into the file.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No findings (or all below severity threshold) |
| 1    | Findings found at or above severity threshold |
| 2    | Configuration error (invalid rule, missing file, bad TOML) |

`--severity-threshold error` makes slopguard exit 0 on warnings-only.

## Inline suppression

Two forms:
```rust
// slopguard-disable-next-line
let x = foo().unwrap();

// slopguard-disable-next-line no-unwrap-in-prod
let x = foo().unwrap();
```

The core scanner reads the line above each finding. If it contains `slopguard-disable-next-line` (optionally with a rule id), the finding is suppressed.

## Severity escalation

`slopguard_core::escalation` groups the reported findings by `(file, rule id)`
and, when a group reaches its threshold, raises that group's warnings to errors
and marks them `escalated: true`.

Pipeline position: the CLI applies it after baseline filtering (suppressed
findings must not inflate the per-file count) and before the severity threshold
is evaluated and the report rendered. So an escalated finding can fail a
`--severity-threshold error` run, and the text, JSON, SARIF and HTML outputs all
see the raised severity.

One level only: a finding already at `error` counts toward the threshold but is
never modified, and its `escalated` stays `false`.

The scan cache sits below this transform and always stores the un-escalated
severity, so a cached re-scan escalates again from the raw findings. Baseline
hashes exclude severity, so escalation can never invalidate an existing
baseline. `--no-escalation` skips the transform for a single run.

## Testing rules

Each rule MUST have inline tests:

```yaml
tests:
  should_match:
    - "let _ = foo();"
  should_not_match:
    - "let result = foo();"
```

`slopguard test` iterates all rules (builtin + custom), parses each snippet as the rule's language, runs the rule's matcher, and asserts:
- Every should_match snippet produces at least one finding
- Every should_not_match snippet produces zero findings

Metric rules are tested on whole files instead of snippets: every entry of
`should_match` / `should_not_match` is itself a complete file, and
`should_match_files` / `should_not_match_files` name fixtures on disk. A
failure reports the fixture path rather than its contents.

## Key dependencies

| Crate | Purpose | Version |
|-------|---------|---------|
| ast-grep-core | AST parsing, pattern matching | 0.43.x |
| ast-grep-config | Rule YAML parsing | latest |
| ast-grep-language | Tree-sitter language support | latest |
| clap | CLI argument parsing (derive) | 4.x |
| serde + toml | Config parsing | latest |
| serde_json | JSON output | latest |
| owo-colors | Terminal colors | latest |
| ignore | Gitignore-aware file walking | latest |
| rust-embed | Embed builtin YAML rules | latest |

## Future (v0.2+)

- AI-powered rules via ironflow SDK (LlmProvider trait for multi-provider: Claude, OpenAI, ollama)
- AI rules use ironflow Operations for tracked, structured LLM calls
- Cache by file content hash to avoid re-analyzing unchanged files
- `ai_check` field in rule YAML with a prompt template
- `--no-ai` flag to skip AI rules in local dev (fast mode)
