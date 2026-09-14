<div align="center">

```text
     _                                       _
 ___| | ___  _ __   __ _ _   _  __ _ _ __ __| |
/ __| |/ _ \| '_ \ / _` | | | |/ _` | '__/ _` |
\__ \ | (_) | |_) | (_| | |_| | (_| | | | (_| |
|___/_|\___/| .__/ \__, |\__,_|\__,_|_|  \__,_|
            |_|    |___/
```

# slopguard

[![pipeline status](https://img.shields.io/gitlab/pipeline-status/ThomasTartrau%2Fslopguard?branch=main&style=for-the-badge&logo=gitlab&logoColor=white)](https://gitlab.com/ThomasTartrau/slopguard/-/pipelines)
[![slopguard-cli](https://img.shields.io/crates/v/slopguard-cli.svg?style=for-the-badge&logo=rust&logoColor=white&label=cli)](https://crates.io/crates/slopguard-cli)
[![slopguard-core](https://img.shields.io/crates/v/slopguard-core.svg?style=for-the-badge&logo=rust&logoColor=white&label=core)](https://crates.io/crates/slopguard-core)
[![slopguard-rules](https://img.shields.io/crates/v/slopguard-rules.svg?style=for-the-badge&logo=rust&logoColor=white&label=rules)](https://crates.io/crates/slopguard-rules)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)

**Catch AI-generated code patterns and common correctness/security issues via static analysis.**

[Quick Start](#-quick-start) -
[Architecture](#%EF%B8%8F-architecture) -
[Rulesets](#-rulesets) -
[Configuration](#%EF%B8%8F-configuration) -
[Custom Rules](#-custom-rules) -
[AI Rules](#-ai-rules)

</div>

---

## What is slopguard?

AI code generators produce recurring anti-patterns: trivial doc-comments, swallowed errors, silent fallbacks, filler words in comments, missing timeouts, redundant string conversions. These patterns are structurally detectable but no existing tool catches them systematically.

slopguard fills that gap with builtin rules organized into three rulesets (**slop**, **security**, **correctness**), covering both **Rust and TypeScript**. Rules are defined in YAML using ast-grep pattern syntax, powered by tree-sitter for AST-level matching. Every rule ships with inline tests.

You can extend slopguard with your own YAML rules, disable rules per-line with inline suppression comments, and output findings as colored text (rustc-style), JSON, or SARIF for CI integration.

---

## 🏗️ Architecture

| Crate | Version | Role |
| --- | --- | --- |
| [`slopguard-cli`](https://crates.io/crates/slopguard-cli) | ![](https://img.shields.io/crates/v/slopguard-cli.svg?label=) | CLI binary: scan, init, test, list, explain commands |
| [`slopguard-core`](https://crates.io/crates/slopguard-core) | ![](https://img.shields.io/crates/v/slopguard-core.svg?label=) | Analysis engine: scanner, config, rule loading, inline disable |
| [`slopguard-rules`](https://crates.io/crates/slopguard-rules) | ![](https://img.shields.io/crates/v/slopguard-rules.svg?label=) | Builtin YAML rules embedded at compile time |
| [`slopguard-ai`](https://gitlab.com/ThomasTartrau/slopguard/-/tree/main/slopguard-ai) | - | AI confirmation pipeline: provider selection, prompt, cache |

```text
  files on disk
       |
       v
  file walker (ignore crate, respects .gitignore)
       |
       v
  AST parser (tree-sitter via ast-grep-core)
       |
       v
  rule matcher (pattern + kind + regex combinators)
       |
       v
  inline disable filter (// slopguard-disable-next-line)
       |
       v
  findings
       |
       v
  formatter (text / json / sarif)
```

---

## ⚡ Quick Start

### Install

**Pre-built binary (recommended):**

```bash
curl -fsSL https://gitlab.com/ThomasTartrau/slopguard/-/raw/main/install.sh | sh
```

Or install a specific version:

```bash
curl -fsSL https://gitlab.com/ThomasTartrau/slopguard/-/raw/main/install.sh | VERSION=0.1.0 sh
```

By default, the binary is installed to `~/.local/bin/`. Override with `INSTALL_DIR`:

```bash
curl -fsSL https://gitlab.com/ThomasTartrau/slopguard/-/raw/main/install.sh | INSTALL_DIR=/usr/local/bin sh
```

Pre-built binaries are available for:

| OS | Architecture | Target |
| ---- | ------------- | -------- |
| Linux | x86_64 | `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` |
| macOS | ARM (M1+) | `aarch64-apple-darwin` |
| macOS | Intel | `x86_64-apple-darwin` |

You can also download archives directly from the [releases page](https://gitlab.com/ThomasTartrau/slopguard/-/releases).

**From source (requires Rust toolchain):**

```bash
cargo install slopguard-cli
```

### Usage

```bash
slopguard scan .
```

Example output:

```text
error[no-unwrap-in-prod]: .unwrap() forbidden in production. Use ? or .expect('explicit message').
   --> src/api/handler.rs:42:5
    |
 42 |     let user = db.get_user(id).unwrap();
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = unwrap() crashes the process on a single invalid input.
```

Other commands:

```bash
slopguard scan src/ --format json    # JSON output for CI
slopguard scan --format sarif        # SARIF for GitLab/GitHub integration
slopguard scan --severity-threshold error  # exit 0 on warnings-only
slopguard scan --no-ai               # AST-only, skip AI rules (no LLM calls)
slopguard scan --no-baseline         # force a full scan, ignore .slopguard-baseline.json
slopguard scan --baseline path.json  # use a specific baseline file
slopguard baseline .                 # capture current findings into .slopguard-baseline.json
slopguard list                       # show active rules (with ast/ai type)
slopguard explain no-unwrap-in-prod  # rule details (prompt template for AI rules)
slopguard test                       # validate all rule inline tests
slopguard init                       # generate slopguard.toml
```

### Baseline

`slopguard baseline .` scans the project with the AST rules and writes a
`.slopguard-baseline.json` file recording the findings that already exist.
Commit this file: subsequent `slopguard scan` runs silently drop any finding
matching an entry in the baseline, so CI only reports newly introduced
issues. Use `--no-baseline` to force a full scan or `--baseline <path>` to
point at a baseline file outside the project root.

---

## 📋 Rulesets

| Ruleset | What it catches |
| --------- | ----------------- |
| **slop** | AI-generated code patterns: filler words, trivial doc-comments, restated comments, unnecessary manual impls |
| **security** | Security anti-patterns: secrets in Debug, path traversal, URL injection, unsafe without SAFETY comment, HTTP clients without timeout |
| **correctness** | Error handling issues: unwrap/expect in production, swallowed errors, silent fallbacks, ignored Results, float money |

Run `slopguard list` for the full list with notes, or see [RULES.md](RULES.md) for detailed documentation.

---

## ⚙️ Configuration

Create a `slopguard.toml` at your project root (or run `slopguard init`):

```toml
[rulesets]
slop = true         # AI-generated code patterns
security = true     # Security anti-patterns
correctness = true  # Error handling, type safety

[rules]
disable = ["no-glob-reexport"]
enable = ["pub-fn-needs-tracing"]  # opt-in rules are off by default
custom_dirs = ["./my-rules"]

[scan]
ignores = ["target/", "generated/", "vendor/"]
```

Hierarchical config: `~/.config/slopguard/config.toml` (global defaults) is overridden by project-level `slopguard.toml`, which is overridden by CLI flags.

---

## 🔧 Custom Rules

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

Place your rules in a directory and point to it in `slopguard.toml`:

```toml
[rules]
custom_dirs = ["./slopguard-rules"]
```

Run `slopguard test` to validate all rules (builtin + custom) against their inline tests.

---

## 🤖 AI Rules

Some rules cannot be decided by an AST pattern alone: whether a `// SAFETY:`
comment states a real invariant, or whether a doc-comment adds information
beyond the function name, is a judgement call. slopguard expresses these as
**AI rules**: the `rule` AST pattern is a cheap pre-filter, and each match
becomes a *candidate* that an LLM confirms or rejects before it is ever
reported.

AI rules are marked `ai` in the `type` column of `slopguard list`; every other
rule is `ast` and never triggers a network call.

### Pipeline (AST + LLM)

1. The AST pattern runs like any other rule and collects candidates.
2. Each candidate's file content plus the rule's prompt template is sent to the
   configured provider.
3. Only candidates the model confirms are reported. Unconfirmed candidates are
   dropped, so a passing AST match never produces a false positive on its own.
4. Results are cached by file content hash, so unchanged files are not
   re-sent on the next scan.

### Configuration

AI is **off by default**. Enable it in `slopguard.toml`:

```toml
[ai]
enabled = true
provider = "api"          # "api" (HTTP) or "cli" (local claude binary)
vendor = "anthropic"      # "anthropic" or "openai" (only for provider = "api")
model = "claude-haiku-4-5" # optional; per-rule model overrides win
concurrency = 4            # candidates confirmed in parallel
# api_key = "..."          # optional; prefer the env var below
```

**Provider `api`** reads the key from `[ai].api_key`, or from the vendor's
environment variable when omitted:

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # vendor = "anthropic"
export OPENAI_API_KEY=sk-...          # vendor = "openai"
```

**Provider `cli`** shells out to the local `claude` binary and requires:

```bash
export CLAUDE_CODE_OAUTH_TOKEN=...    # and `claude` on your PATH
```

If a provider is enabled but its credentials are missing, slopguard prints a
single clear warning naming the missing credential and continues with the AST
findings only. It never fails the scan on a missing key.

### Skipping AI

Use `--no-ai` for a fast, fully local, deterministic scan. It skips every AI
rule with no LLM call and no warning:

```bash
slopguard scan . --no-ai
```

### Builtin AI rules

| Rule | Ruleset | What it catches |
| ---- | ------- | --------------- |
| `ai-safety-comment-validation` | security | `// SAFETY:` comments that reassure instead of stating real invariants |
| `ai-doc-comment-quality` | slop | Doc-comments that only restate the function name |
| `ai-intermediate-row-struct` | correctness | Redundant `*Row` structs mirroring an already-typed struct |
| `ai-redundant-to-string-serialize` | correctness | `.to_string()` on values that are already `Serialize` |

Inspect any of them, including the exact prompt sent to the model, with
`slopguard explain <rule-id>`.

---

## 🚫 Inline Suppression

```rust
// slopguard-disable-next-line
let value = risky_call().unwrap();

// slopguard-disable-next-line no-unwrap-in-prod
let value = safe_call().unwrap();
```

The first form suppresses all rules for the next line. The second form suppresses only the named rule.

---

## CI Integration

### GitLab CI

Include the template in your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://gitlab.com/ThomasTartrau/slopguard/-/raw/main/ci/slopguard.gitlab-ci.yml'
```

Or copy `ci/slopguard.gitlab-ci.yml` into your project and adjust as needed.

### GitHub Action

```yaml
- uses: ThomasTartrau/slopguard/.github/actions/slopguard@main
  with:
    severity-threshold: warning  # or 'error' to ignore warnings
    format: text                 # text, json, or sarif
```

### Pre-commit

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://gitlab.com/ThomasTartrau/slopguard
    rev: v0.1.5
    hooks:
      - id: slopguard
```

### Cache in CI

slopguard supports a `--cache-dir` flag (and `SLOPGUARD_CACHE_DIR` env var) to persist scan cache across CI runs. The templates above configure this automatically.

Resolution order: `--cache-dir` (CLI) > `SLOPGUARD_CACHE_DIR` (env) > `cache_dir` in `slopguard.toml` > `.slopguard-cache/` in the working directory.

---

## License

MIT - see [LICENSE](LICENSE).

---

<div align="center">

**[GitLab](https://gitlab.com/ThomasTartrau/slopguard)**

[cli](https://crates.io/crates/slopguard-cli) -
[core](https://crates.io/crates/slopguard-core) -
[rules](https://crates.io/crates/slopguard-rules)

</div>
