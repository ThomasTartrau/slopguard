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
  formatter (text / json / sarif / html)
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
slopguard scan --format html -o report.html   # standalone visual report
slopguard scan --severity-threshold error  # exit 0 on warnings-only
slopguard scan --no-ai               # AST-only, skip AI rules (no LLM calls)
slopguard stats .                    # distribution of findings by severity/category/language
slopguard stats . --format json      # same data as structured JSON
slopguard baseline .                 # capture current findings into .slopguard-baseline.json
slopguard scan --no-baseline         # ignore the baseline, report everything
slopguard scan --diff                 # only files changed vs HEAD (staged + unstaged)
slopguard scan --diff --base main     # only files changed vs main (three-dot diff)
slopguard list                       # show active rules (with ast/ai type)
slopguard explain no-unwrap-in-prod  # rule details (prompt template for AI rules)
slopguard test                       # validate all rule inline tests
slopguard init                       # generate slopguard.toml
slopguard init --preset strict       # generate a preset config
slopguard init --preset              # list the available presets
```

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

### Presets

`slopguard init --preset <name>` writes a ready-made config. Run `slopguard init --preset` with no name to list them.

| Preset | What it generates |
| -------- | ------------------- |
| `default` | All rulesets on, opt-in rules off. Same as running `init` with no preset. |
| `strict` | Everything on, including every opt-in rule. Warnings fail the scan. |
| `relaxed` | Security plus correctness errors only. Slop and correctness warnings off. |
| `ai` | Default rules plus the AI confirmation pass (`api` provider, haiku model). |

The rule id lists in `strict` and `relaxed` are generated from the builtin ruleset, so they never name a rule that no longer ships.

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

## 📏 File-Level Rules

Some problems are not in any single line: a 900-line module, a file with 60
imports, or a file where the comments outnumber the code. slopguard expresses
these as **metric rules**: instead of an AST pattern, they measure a structural
property of the whole file and report one finding, anchored at line 1, when the
measured value is **strictly greater than** the threshold.

Metric rules are marked `metric` in the `type` column of `slopguard list`, and
`slopguard list --format json` emits them with `"type": "metric"`:

```bash
slopguard list --format json | jq '[.[] | select(.type == "metric")] | length'
```

### Builtin file-level rules

| Rule | Language | Metric | Threshold |
| ---- | -------- | ------ | --------- |
| `max-file-lines` | rust | `file_lines` | 500 |
| `max-file-lines-ts` | typescript | `file_lines` | 500 |
| `max-import-count` | rust | `import_count` | 40 |
| `max-import-count-ts` | typescript | `import_count` | 40 |
| `max-function-count` | rust | `function_count` | 30 |
| `max-function-count-ts` | typescript | `function_count` | 30 |
| `high-comment-ratio` | rust | `comment_ratio` | 0.4 |
| `high-comment-ratio-ts` | typescript | `comment_ratio` | 0.4 |

`function_count` counts nested functions, and in TypeScript also arrow
functions and class methods. `comment_ratio` counts distinct comment lines, so
a five-line block comment counts as five.

### Writing one

```yaml
id: max-file-lines
language: rust
severity: warning
category: slop
metric: file_lines          # file_lines | import_count | function_count | comment_ratio
threshold: 500              # fires above this value, never at it
message: "File exceeds 500 lines ($value lines). Split it into focused modules."
tests:
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
  should_not_match_files:
    - "fixtures/metrics/rust_small.rs"
```

`metric` replaces `rule`; setting both is an error. `$value` in the message is
substituted with the measured value (an integer for counts, two decimals for
ratios). A metric cannot be measured on a snippet, so tests point at whole
files: paths are relative to the rule's own directory, and `should_match` /
`should_not_match` may still be used with complete file contents inline.

### Two things to know

- **Inline suppression does not work on them.** `// slopguard-disable-next-line`
  targets the line *after* the comment, so it can never target line 1. Use the
  rule's `ignores` globs or `rules.disable` in `slopguard.toml` instead.
- **A baselined file-level finding comes back when the value changes.** The
  baseline hash mixes the matched text, which for these rules is the measured
  value, so a file baselined at 547 lines is reported again at 548. That is the
  point: the file grew.

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

## 📊 Stats

`scan` tells you what every finding is. `stats` answers where they are: it runs
the exact same pipeline, then prints the distribution instead of the findings.

```bash
slopguard stats .
```

```text
42 findings in 128 files
3 findings filtered by baseline

severity  count
--------  -----
error        18
warning      24

category     count
-----------  -----
slop            12
security         5
correctness     25

language    count
----------  -----
rust           40
typescript      2

rule                count
------------------  -----
no-unwrap-in-prod      18
no-magic-number         9
no-obvious-comment      7

file                count
------------------  -----
src/api/handler.rs      9
src/db/pool.rs          6
```

The top rules table is capped at 10 entries and the top files table at 5, both
sorted by count and then by name so the output is stable between runs.

`--format json` prints the same data as one object. Every key is always present,
even at zero, so CI can index into it without guarding:

```json
{
  "total": 42,
  "files_scanned": 128,
  "baseline_filtered": 3,
  "by_severity": { "error": 18, "warning": 24 },
  "by_category": { "slop": 12, "security": 5, "correctness": 25 },
  "by_language": { "rust": 40, "typescript": 2 },
  "top_rules": [{ "rule_id": "no-unwrap-in-prod", "count": 18 }],
  "top_files": [{ "file": "src/api/handler.rs", "count": 9 }]
}
```

`stats` accepts the same `--baseline`, `--no-baseline`, `--no-ai`, `--rule`,
`--disable`, `--enable` and `--config` flags as `scan`. Unlike `scan` it always
exits 0 when it ran, findings or not, so it can be piped into `jq` under
`set -o pipefail`:

```bash
slopguard stats . --format json | jq '.by_category'
```

---

## 🖼️ HTML Report

`--format html` renders a standalone visual report: a header with the project
name, the generation date and the run totals, horizontal bars for the severity,
category and language distributions, and a findings table sorted errors first
with the matched snippet, note and suggested fix under each row. Four filters
(severity, category, language, file path) narrow the table client side.

The report is a single file: styles and script are inlined, so it makes zero
external requests and opens straight from disk. It follows
`prefers-color-scheme`, so it is readable in light and dark mode.

```bash
slopguard scan --format html > report.html
slopguard scan --format html -o report.html
```

`-o`/`--output` is not HTML specific: it writes any format to a file and leaves
stdout empty, so `slopguard scan --format json -o findings.json` works too.
Colors are never written to a file, and the exit code is unchanged.

---

## 📊 Baseline

Adopting slopguard on an existing codebase usually means hundreds of pre-existing
findings. A baseline records them once so CI only fails on newly introduced ones.

```bash
slopguard baseline .     # writes .slopguard-baseline.json at the project root
git add .slopguard-baseline.json
```

From then on, `slopguard scan` silently drops every finding already recorded and
reports only the new ones. The summary line tells you how many were suppressed:

```
3 findings filtered by baseline
0 errors, 0 warnings in 12 files
```

**Commit the baseline file.** Unlike `.slopguard-cache/`, it is shared state: it
must be in git so every developer and every CI job filters the same findings. Do
not add it to `.gitignore`.

| Flag | Effect |
|------|--------|
| `slopguard baseline .` | Capture current findings (exit 0 even when findings exist) |
| `slopguard baseline -o <path>` | Write the baseline somewhere else |
| `slopguard scan --baseline <path>` | Use a specific baseline file (error if missing) |
| `slopguard scan --no-baseline` | Ignore the baseline entirely and report everything |

Without `--baseline`, the file is looked up in the working directory and its
parents, so scanning from a subdirectory still applies the project baseline.

A finding is identified by its rule id, its path relative to the baseline file,
its matched text, and the lines surrounding it. Line numbers are not part of that
identity: inserting code above a baselined finding keeps it suppressed. Rewriting
the code around it makes it resurface, which is deliberate. Baseline entries that
no longer match anything (the code was fixed) are ignored silently.

Re-run `slopguard baseline .` to recapture, for instance after adding rules. The
entries are sorted, so the git diff stays readable. Note that `baseline` runs the
AI rules like `scan` does; use `--no-ai` to skip the LLM calls.

---

## 🔀 Diff Mode

`slopguard scan --diff` narrows the scan to the files git reports as changed, so
a merge request pipeline only pays for the code it touched.

```bash
slopguard scan --diff                  # staged + unstaged changes vs HEAD
slopguard scan --diff --base main      # everything this branch adds on top of main
slopguard scan src/ --diff             # changed files under src/ only
```

With `--base <ref>`, the comparison is a three-dot diff (`<ref>...HEAD`): only the
commits the branch adds are considered, so a target branch that moved ahead does
not resurface unrelated findings.

What the file set contains:

- Deleted files are skipped: there is nothing left to scan.
- Renamed files are scanned under their new name.
- Untracked files are not included. `git diff` does not see them, so `git add`
  the new file to have it scanned.
- Changed files are scanned even when hidden or gitignored, since git already
  decided they matter. The `scan.ignores` globs from the config still apply.

`--diff` requires a git repository: outside one, the scan exits with code 2 and an
explicit error. The same happens for an unknown `--base` ref. A clean working tree
is not an error: the scan reports zero changed files and exits 0.

In diff mode the JSON output carries two extra fields in `stats`, absent from a
normal scan:

```json
{
  "stats": {
    "errors": 1,
    "warnings": 0,
    "total": 1,
    "files_scanned": 2,
    "baseline_filtered": 0,
    "diff_base": "main",
    "files_changed": 3
  }
}
```

`files_changed` counts the files git reported; `files_scanned` counts the ones
slopguard actually parsed (a changed `README.md` is in the first, not the second).

Diff mode composes with every other flag: baseline filtering, `--format`,
`--severity-threshold`, `--rule`, `--no-ai` and the cache all behave as usual. A
partial scan never prunes cache entries for files it did not look at.

GitLab CI, on merge requests only:

```yaml
slopguard:mr:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - slopguard scan --diff --base "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
```

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
    format: text                 # text, json, sarif, or html
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
