# Architecture

## Overview

slopguard is a Rust CLI tool that scans source code for AI-generated anti-patterns and common issues. It embeds ast-grep-core as a library (no external binary dependency) and organizes rules into thematic rulesets.

```
slopguard scan [path]
  |
  +-- Phase 1: per-file pass, one parse per file (deterministic, cached)
  |     ast + metric engines, import extraction, symbol extraction
  |
  +-- Phase 2: project pass
  |     cross-file engine over the symbol index of the whole project,
  |     reporting only in the scanned files (also under --diff)
  |
  +-- Import resolution against the manifests on disk (re-run every scan)
  |
  +-- Phase 3: AI pass (slopguard-ai, on AST pre-filtered candidates)
  |     LLM confirmation, or the optional classifier
  |
  +-- baseline filter -> severity escalation -> severity threshold
  |
  +-- Unified output (text / json / sarif / html)
```

## Workspace structure

```
slopguard/
  Cargo.toml              # workspace root
  slopguard-cli/          # binary crate (clap CLI, output rendering)
  slopguard-core/         # library crate (scan engine, config, rule loading)
  slopguard-rules/        # builtin rules (YAML files embedded at compile time)
  slopguard-ai/           # AI pass for rules with an `ai_check`
  tests/fixtures/         # fixture projects shared by the integration tests
  ci/                     # GitLab CI template for user projects
  .github/actions/        # GitHub Action for user projects
  benchmarks/             # reproducible scans of real repositories (bench.sh)
```

### slopguard-cli

The binary crate. Responsible for:
- CLI argument parsing via clap (derive API)
- Subcommands: scan, stats, baseline, explain, init, test, list
- Output formatting (text with colors, JSON, SARIF, HTML)
- Exit code logic (0 = clean, 1 = findings, 2 = config error)
- Reading config from slopguard.toml (hierarchical: global + project, repo file untrusted unless `--trust-repo-config`)

Dependencies: clap, slopguard-core, slopguard-ai, serde_json, strsim (rule id suggestions), similar (the `--fix --dry-run` diff). Colors are raw ANSI escapes and SARIF is built with serde_json, with no dedicated crate.

### slopguard-core

The library crate. Responsible for:
- Rule loading and validation (builtin + custom YAML), external rule sources
  from git or local paths with their provenance (rule/, source/)
- Scan orchestration (scanner/): every in-process rule kind implements the
  `RuleEngine` trait (engine.rs, D30), the orchestrator parses each file once
  and hands the tree to every per-file engine
- File-level metrics (metric.rs)
- Project-wide (cross-file) analysis: per-file symbol extraction and the index
  they are folded into (cross_file/), and which files feed the index in a
  partial scan (scanner/project.rs). A cache entry carries the file's symbol
  contribution alongside its findings, so a cache hit feeds the cross-file pass
  without reparsing.
- Import resolution against Cargo.toml / package.json / tsconfig.json
  (resolution/, D32)
- Per-file scan cache keyed by content hash (cache.rs)
- Inline disable comment parsing and the unused-disable report (disable.rs)
- `#[cfg(test)]` and test-path detection for `skip_test_code` (test_filter.rs)
- Autofix: `rewrite` application, fix point, dry-run diff (fix/, D31)
- Config parsing (slopguard.toml via serde + toml) and `init` presets (preset.rs)
- Finding representation (file, line, rule_id, severity, message, note)
- Baseline hashing, persistence and filtering (baseline.rs)
- Severity escalation (escalation.rs)
- Git integration: `--diff` file lists and the `--fix` dirty-tree check (git.rs)
- Rule testing (should_match / should_not_match / should_fix validation, testing/)
- Ruleset management (slop, security, correctness)

Dependencies: ast-grep-core, ast-grep-config, ast-grep-language, serde, toml, glob/ignore

### slopguard-ai

Runs the rules that carry an `ai_check`. The CLI collects their AST matches as
candidates, then this crate confirms or rejects each one:
- provider.rs: builds the generative provider from `[ai]` (`api` with the
  Anthropic or OpenAI vendor, or `cli` for the local `claude` binary)
- pipeline.rs: bounded-concurrency LLM confirmation, one call per candidate,
  on a private tokio runtime
- pipeline/classifier.rs: the optional System One classifier (Jev), which
  returns a probability per candidate, batched per context cluster (D35, D36)
- pipeline/context.rs: the code window sent with a candidate (25 lines each
  side)
- cache.rs: AI verdicts and probabilities under `<cache-dir>/ai/`

It is not a `RuleEngine`: it is async, needs an external provider and is
orchestrated by `slopguard-cli` (D30). Dependencies: ironflow-core, tokio.

### slopguard-rules

Contains the builtin YAML rules organized by ruleset, one file per
(rule, language) pair:
```
slopguard-rules/
  src/
    lib.rs                # exports the embedded rules (rust-embed)
  rules/
    slop/                 # 44 files
    security/             # 22 files
    correctness/          # 51 files
    fixtures/             # whole-file fixtures for metric rule tests
```

117 files ship, 14 of them opt-in (`enabled: false`). `slopguard list --all`
is the source of truth for the inventory, and RULES.md describes each rule.

Dependencies: rust-embed

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
enabled: false                 # opt-in rule, activated by `rules.enable` (default true)
fix: "Use X instead of Y"     # human message, never applied
rewrite: "$R"                  # ast-grep rewrite template applied by `scan --fix` (D31)
autofix_safe: true             # required for `rewrite` to be applied (default false)
skip_test_code: true           # drop findings inside #[cfg(test)] blocks (Rust only, default false)
ai_check:                      # turns the rule into an AI rule: `rule` only collects candidates
  prompt: "..."                # template with {{filename}}, {{rule_context}}, {{code}}
  model: "..."                 # optional per-rule LLM model
  reason: static               # static | generated (classifier only, D35)
  threshold: 0.8               # optional per-rule classifier threshold
  if_true: "..."               # optional classifier criteria (prose)
  if_false: "..."
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
It names a builtin analysis. Three kinds exist: `single_impl_trait` (a trait
with exactly one implementor of the trait's own crate, D29),
`duplicate_error_message` (the same error value message of 10 characters or
more, passed to `bail!`, `anyhow!`, `eyre!`, `format_err!` or `ensure!`, in two
or more files, D37) and `assertion_free_test` (a test that checks nothing and
calls no test code that asserts, D38).

```yaml
cross_file: single_impl_trait  # or duplicate_error_message, assertion_free_test
skip_test_code: true           # applies to the declaration site
ignores: ["**/target/**"]      # applies to the declaration site
```

A kind may read options from `[rules.options.<id>]` in the config, a typed
table where an unknown rule id or key is a config error. Today only
`assertion_free_test` has one: `assert_functions`, the names (globs) of
functions from outside the project that assert.

The logic behind a kind is builtin Rust keyed on the discriminant, so a custom
YAML can retune a rule's severity, message, `files` / `ignores` and
`skip_test_code`, but cannot invent a new kind: an unknown discriminant is a
parse error. A cross-file rule carries no `tests` block, since no snippet can
exercise it, and `slopguard test` reports it as untested.

The pass runs after the per-file scan. Each scanned Rust file contributes a
`FileSymbols` (its trait declarations, its `impl Trait for Type` headers with
the implementing type, the structs, enums and unions it declares, its error
message literals, its unasserted tests and the functions and macros a test may
delegate to, each with the names it calls) from the same parse that produced
its findings; those contributions are folded into a project-wide `SymbolIndex`
and every active cross-file rule is evaluated against it.

A directory walk indexes what it walks. A file target (`--diff`, or the files
the pre-commit hook passes) widens the index to its project, the nearest
ancestor holding a `slopguard.toml` or a `.git` (D39): those extra files go
through the cache like any other but only contribute symbols, and a
project-level finding is reported only when it lies in a scanned file
(`scanner/project.rs`). A partial scan therefore gives the same verdicts as a
full one, restricted to the files it was asked about.

### Resolution rules

`resolution` replaces `rule`, `metric` and `cross_file`. The only kind is
`unresolved_import`, with one YAML per language (D32).

```yaml
resolution: unresolved_import
message: "Import '$import' does not resolve."   # $import is the specifier
```

Each file's imports are extracted from its parse and cached with it, then
resolved on every scan against the manifests found by walking up from the file
(`Cargo.toml`, `package.json`, `tsconfig.json`). Rust checks the crate root
only, and skips roots the file already has in scope: a name bound by a `mod`
or another `use`, an uppercase item name, or any root in a module that holds a
non-std glob import. The pass is per file, so it runs under `--diff` too. Like cross-file
rules, resolution rules carry no `tests` block; their coverage lives in
`tests/fixtures/resolution` and the CLI integration tests.

### Rule sources

Builtin rules are embedded; everything else is loaded at startup from
`rules.custom_dirs` and `[[rules.sources]]` (D33):

```toml
[[rules.sources]]
git = "https://gitlab.com/org/slopguard-rules.git"
ref = "v1.2.0"          # tag, branch or sha; default branch when omitted
path = "rules/"         # sub-directory inside the repository

[[rules.sources]]
path = "../shared-rules"
```

Git sources are shallow-fetched with the machine's `git` into
`<user cache>/slopguard/sources/<hash>` (`SLOPGUARD_SOURCES_CACHE` overrides
the root) and refreshed best-effort on each run; `--offline` reuses the cache
only. `SLOPGUARD_GIT_TOKEN` provides an https token without writing it to
disk. An external rule reusing a builtin (id, language) is rejected.
`slopguard list` shows each rule's `source`.

## Config format (slopguard.toml)

```toml
[rulesets]
slop = true
security = true
correctness = true

[rules]
disable = ["no-glob-reexport"]
enable = ["pub-fn-needs-tracing"]   # opt-in rules (enabled: false) are off otherwise
custom_dirs = ["./my-rules"]

[[rules.sources]]                   # see "Rule sources"
git = "https://gitlab.com/org/slopguard-rules.git"

[rules.options.no-assertion-free-test]   # per-rule options (D38)
assert_functions = ["run", "check_*"]    # external helpers that assert

[scan]
ignores = ["target/", "generated/", "*.generated.rs"]
test_paths = ["**/it/**"]           # extra globs treated as test code
# cache_dir = ".slopguard-cache"

[output]
format = "text"    # text | json | sarif | html
colors = true

[ai]
enabled = false
provider = "api"          # api (HTTP) | cli (local claude binary)
vendor = "anthropic"      # anthropic | openai, for provider = "api"
model = "claude-haiku-4-5"
concurrency = 4
# api_key via ANTHROPIC_API_KEY / OPENAI_API_KEY env var

[ai.classifier]           # optional, replaces the LLM confirmation (D35)
enabled = false
transport = "direct"      # direct (TYPESAFE_API_KEY) | openrouter (OPENROUTER_API_KEY)
threshold = 0.7
batch = true
batch_max_questions = 8
batch_max_state_lines = 200

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

The project file is untrusted by default (D40): `[ai]` and `scan.cache_dir`
are dropped from it with a warning, and its `rules.custom_dirs` / local
`[[rules.sources]] path` must resolve inside the repository.
`--trust-repo-config` lifts both restrictions; a `--config` file is always
trusted. `[ai].concurrency` must lie in `1..=64` in every file.

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

`scan --report-unused-disable` reports every directive that suppresses nothing
as an `unused-disable` warning on the comment line. Consumption is judged on a
separate, uncached raw scan, against the AST matches of every active rule, AI
rules included before any model verdict, so the report does not depend on the
provider (D34).

## Autofix

`scan --fix` applies the `rewrite` of every `autofix_safe` rule in place
(`slopguard-core::fix`, D31):

1. Refuse when the scanned paths have uncommitted changes, unless
   `--allow-dirty` (outside a git repository the check passes).
2. Match each autofixable rule (or its narrower `autofix_rule`) directly on the
   source, skipping matches that detection would suppress: test code, inline
   disable, baseline.
3. Apply the non-overlapping edits, then match the new buffer again, until a
   fix point or 10 iterations.
4. Rescan from disk and exit 1 if findings remain.

`--dry-run` prints the unified diff and writes nothing.

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

Autofixable rules add `should_fix` cases (`before` / `after`): `slopguard test`
applies the `rewrite` to `before` and requires the result to equal `after`.

Cross-file and resolution rules are the exception: a snippet cannot exercise a
project index or a manifest, so they carry no `tests` block, `slopguard test`
lists them as "no tests", and they are covered by fixture projects under
`tests/fixtures/` driven by the CLI integration tests.

## Key dependencies

| Crate | Purpose | Version |
|-------|---------|---------|
| ast-grep-core | AST parsing, pattern matching | 0.43.x |
| ast-grep-config | Rule YAML parsing | latest |
| ast-grep-language | Tree-sitter language support | latest |
| clap | CLI argument parsing (derive) | 4.x |
| serde + toml | Config parsing | latest |
| serde_json | JSON output | latest |
| similar | Unified diff for `--fix --dry-run` | latest |
| ignore | Gitignore-aware file walking | latest |
| rust-embed | Embed builtin YAML rules | latest |
| ironflow-core | LLM and classifier providers (slopguard-ai) | 3.x |
| tokio | Async runtime for the AI pass (slopguard-ai) | 1.x |

## What is next

See ROADMAP.md for the open items.
