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
[Severity Escalation](#-severity-escalation) -
[Custom Rules](#-custom-rules) -
[AI Rules](#-ai-rules) -
[Autofix](#autofix)

</div>

---

## What is slopguard?

AI code generators produce recurring anti-patterns: trivial doc-comments, swallowed errors, silent fallbacks, filler words in comments, missing timeouts, redundant string conversions. These patterns are structurally detectable but no existing tool catches them systematically.

slopguard fills that gap with 117 builtin rules (103 active by default) organized into three rulesets (**slop**, **security**, **correctness**), covering both **Rust and TypeScript**. Rules are defined in YAML using ast-grep pattern syntax, powered by tree-sitter for AST-level matching. Beyond single-node patterns, slopguard measures whole files, builds a project-wide index for cross-file rules, checks that imports resolve against your manifests, and can confirm ambiguous matches with an LLM.

You can extend slopguard with your own YAML rules or shared rulesets from git, disable rules per-line with inline suppression comments, apply safe rewrites with `--fix`, and output findings as colored text (rustc-style), JSON, SARIF or a standalone HTML report.

---

## 🏗️ Architecture

| Crate | Version | Role |
| --- | --- | --- |
| [`slopguard-cli`](https://crates.io/crates/slopguard-cli) | ![](https://img.shields.io/crates/v/slopguard-cli.svg?label=) | CLI binary: scan, stats, baseline, init, test, list, explain commands |
| [`slopguard-core`](https://crates.io/crates/slopguard-core) | ![](https://img.shields.io/crates/v/slopguard-core.svg?label=) | Analysis engine: scanner, config, rule loading and sources, cache, baseline, autofix, import resolution |
| [`slopguard-rules`](https://crates.io/crates/slopguard-rules) | ![](https://img.shields.io/crates/v/slopguard-rules.svg?label=) | Builtin YAML rules embedded at compile time |
| [`slopguard-ai`](https://gitlab.com/ThomasTartrau/slopguard/-/tree/main/slopguard-ai) | - | AI confirmation pipeline: provider selection, prompt, cache |

```text
  files on disk
       |
       v
  file walker (ignore crate, respects .gitignore)
       |
       v
  AST parser (tree-sitter via ast-grep-core, one parse per file, cached)
       |
       v
  per-file engines (ast patterns, file metrics) + import resolution,
  inline disable (// slopguard-disable-next-line) applied per finding
       |
       v
  project pass (cross-file rules over a symbol index, full scans only)
       |
       v
  AI pass (LLM or classifier confirms AI rule candidates, optional)
       |
       v
  baseline filter, severity escalation
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
slopguard scan --fix                  # apply autofix-safe rewrites in place
slopguard scan --fix --dry-run        # preview the rewrites as a unified diff, write nothing
slopguard scan --fix --allow-dirty    # rewrite even with uncommitted changes (else refused)
slopguard scan --report-unused-disable  # also report disable comments that suppress nothing
slopguard scan --offline              # never fetch git rule sources, reuse the cache
slopguard list                       # show active rules with their type and source
slopguard list --all                 # include the opt-in rules
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
| **slop** | AI-generated code patterns: filler words, trivial doc-comments, restated comments, unnecessary manual impls, oversized files, single-impl traits |
| **security** | Security anti-patterns: secrets in Debug or source, path traversal, URL and shell injection, unsafe without SAFETY comment, HTTP clients without timeout, SSRF |
| **correctness** | Error handling and type safety: unwrap/expect in production, swallowed errors, silent fallbacks, ignored Results, `unknown`/`any` leaks, assertion-free tests, hallucinated imports |

Every rule has a type, shown in the `type` column of `slopguard list`:

| Type | Active | What it does |
| ---- | ------ | ------------ |
| `ast` | 84 | ast-grep pattern on the syntax tree |
| `metric` | 8 | measures the whole file (lines, imports, functions, comment ratio) |
| `cross-file` | 3 | evaluated once over a project-wide index |
| `resolution` | 2 | checks imports against Cargo.toml / package.json |
| `ai` | 6 | AST pre-filter confirmed by a model |

14 more rules are opt-in (`slopguard list --all`). Run `slopguard explain <rule-id>` for a rule's details, or see [RULES.md](RULES.md) for the full reference.

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

[rules.options.no-assertion-free-test]
assert_functions = ["check_*"]  # test helpers from a dependency that assert

[scan]
ignores = ["target/", "generated/", "vendor/"]

[escalation]
enabled = false     # opt-in, see Severity Escalation below
threshold = 5
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

### Shared rulesets from git

To share rules between projects without copying YAML, declare them as sources:

```toml
[[rules.sources]]
git = "https://gitlab.com/your-org/slopguard-rules.git"
ref = "v1.2.0"          # tag, branch or sha (default branch when omitted)
path = "rules/"         # sub-directory inside the repository (default: root)

[[rules.sources]]
path = "../shared-rules"   # or a local directory
```

- Git sources are shallow-fetched with your own `git` (ssh-agent, credential
  helpers and `~/.gitconfig` apply) into `~/.cache/slopguard/sources/` (Linux;
  the platform cache directory elsewhere, `SLOPGUARD_SOURCES_CACHE` to
  override). For a private https repository in CI, set `SLOPGUARD_GIT_TOKEN`;
  it is never written to disk.
- Each run refreshes the checkout. If the remote is unreachable, the cached copy
  is used. `--offline` never fetches and fails when the cache is empty.
- There is no lockfile yet: pin a tag or a sha for reproducible CI.
- A source rule cannot reuse the id of a builtin rule for the same language;
  that is an error, not an override.
- `slopguard list` shows where each rule comes from in its `source` column, and
  `slopguard test` validates source rules like any other.

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

### Classifier (optional)

Confirming a candidate is a yes/no question. Instead of a generative LLM,
slopguard can ask a classifier (Jev, from TypeSafe) that returns a probability,
and report the candidate when it reaches a threshold:

```toml
[ai.classifier]
enabled = true
transport = "direct"      # "direct" (TYPESAFE_API_KEY) or "openrouter" (OPENROUTER_API_KEY)
threshold = 0.7           # fire when p >= threshold; rules can override it
batch = true              # group candidates with overlapping context into one request
```

When the classifier is enabled it replaces the LLM confirmation for every AI
rule. Two rules (`ai-ssrf-unvalidated-url`, `ai-open-redirect-unvalidated`) are
marked `reason: generated`: once the classifier fires, they ask the `[ai]` LLM
to explain that specific instance, and fall back to their static note when no
LLM is configured. Probabilities are cached, and the threshold is applied after
the cache, so tuning it never triggers new calls. The classifier is a
proprietary SaaS and stays strictly opt-in.

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
| `ai-ssrf-unvalidated-url` | security | Outbound HTTP request whose URL is an unvalidated external-input variable (SSRF) |
| `ai-open-redirect-unvalidated` | security | Redirect target taken from request input without an allowlist check (open redirect) |
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

## 🔗 Cross-File Rules

Some problems are not in any single file: a trait defined in `repository.rs`
with its one and only implementation in `postgres.rs` is an indirection that
adds no choice, and neither file shows it on its own. slopguard expresses these
as **cross-file rules**: after the per-file scan, every scanned file's symbols
are folded into a project-wide index, and each cross-file rule is evaluated
against it once.

Cross-file rules are marked `cross-file` in the `type` column of
`slopguard list`, and `slopguard list --format json` emits them with
`"type": "cross-file"`:

```bash
slopguard list --format json | jq '[.[] | select(.type == "cross-file")] | length'
```

### Builtin cross-file rules

| Rule | Language | Kind |
| ---- | -------- | ---- |
| `no-single-impl-trait` | rust | `single_impl_trait` |
| `no-duplicate-error-message` | rust | `duplicate_error_message` |
| `no-assertion-free-test` | rust | `assertion_free_test` |

`no-assertion-free-test` reports a `#[test]` that checks nothing: no
`assert`/`panic`, no `?`, no `.unwrap()`/`.expect()`, no inline snapshot, no
`#[should_panic]`. Delegating is fine: a test that calls, directly or through
other helpers, test code that asserts (a `#[cfg(test)]` function,
`tests/common/mod.rs`, a crate your workspace uses only as a dev-dependency
such as `cargo-test-support`) is not reported. A production function with a
precondition `assert!` does not count, and neither do compile-only tests
(item declarations and typed `let _: T` bindings) or trybuild directories. For
test helpers that come from a dependency, name them in the config:

```toml
[rules.options.no-assertion-free-test]
assert_functions = ["run", "check_*"]   # bare names, * is a wildcard
```

`no-duplicate-error-message` reports an error message literal (from `bail!`,
`anyhow!`, `eyre!`, `format_err!` or `ensure!`, 10 characters or more) that
appears verbatim in two or more files: define it once as a constant or an error
variant. An error value carries no location, so two sites with the same text
cannot be told apart in a log. Panic messages (`panic!`, `.expect()`) are left
out: a panic prints its own file and line.

`no-single-impl-trait` fires only when a trait has **exactly 1 declaration,
exactly 1 concrete implementation and 0 blanket implementations** in the scanned
project. It stays silent otherwise:

- **0 impls** - the implementor is probably outside the crate.
- **2 or more impls** - the abstraction is doing its job. A `#[cfg(test)]` mock
  counts as a second implementation, so "the trait exists to be mocked" is not
  reported.
- **a blanket `impl<T> Foo for T`** - the trait already covers a family of types.
- **the same trait name declared twice** - matching is by bare name, so a
  homonym makes the project ambiguous and the rule abstains.
- **an extension trait** - the single impl targets a type that is not a
  struct, enum or union of the trait's own crate (`impl VersionExt for
  semver::Version`, a type alias, or a type from a sibling workspace crate).
  Rust only allows inherent methods in the type's crate, so the trait is the
  only way to add them.

The finding points at the declaration, not the impl, and is reported there:

```rust
// slopguard-disable-next-line no-single-impl-trait
pub trait Repository {
    fn get(&self, id: u64) -> Option<String>;
}
```

### One thing to know

- **Partial scans see the whole project.** `--diff` and the pre-commit hook
  scan only some files, but the index is still built from the whole project
  they belong to (the nearest directory with a `slopguard.toml` or a `.git`),
  so the verdicts match a full scan. Only the findings located in the scanned
  files are reported: adding the only impl of a trait whose file did not
  change does not report the trait until its file is scanned.

---

## Import Resolution

AI generators invent crates and packages. `unresolved-import` (Rust and
TypeScript) checks that every import resolves, without compiling anything and
without any network call:

- **Rust**: the crate root of each `use` / `extern crate` must be declared in
  the nearest `Cargo.toml` (dependencies, dev, build, `[workspace.dependencies]`,
  `[target.*]`), be a standard crate (`std`, `core`, `alloc`, `proc_macro`,
  `test`), a `crate` / `self` / `super` path, or a name the file already has in
  scope: a `mod`, another `use` (`use crate::runtime::scheduler;` then
  `use scheduler::Context;`), or an uppercase item name (`use Ordering::*`).
  A module holding a non-std glob (`use super::*;`) is not asserted, since the
  glob may bring the root into scope. Deep paths are not checked.
- **TypeScript**: each `import` / `require` must be in `package.json`, a
  relative file that exists, or a Node builtin.

It stays silent when no manifest is found, on `import type`, on re-exports and
on tsconfig `paths` aliases. The rule is per file, so it works under `--diff`.
Editing a manifest is picked up on the next scan even for cached files.

```text
error[unresolved-import]: Unresolved import 'serde_jsonx': not a Cargo.toml dependency, a std crate, or a local module.
  --> ./src/main.rs:1:1
  |
1 | use serde_jsonx::Value;
  | ^^^^^^^^^^^^^^^^^^^^^^^
```

---

## 🚫 Inline Suppression

```rust
// slopguard-disable-next-line
let value = risky_call().unwrap();

// slopguard-disable-next-line no-unwrap-in-prod
let value = safe_call().unwrap();
```

The first form suppresses all rules for the next line. The second form suppresses only the named rule.

Disable comments rot: the code below changes, and the comment keeps hiding
whatever lands there next. `slopguard scan --report-unused-disable` reports
each directive that suppresses nothing as an `unused-disable` warning on the
comment line. A directive on an AI rule candidate counts as used as soon as the
AST pre-filter matches, whatever the model decides, so the report is the same
with or without a provider.

---

## Autofix

Rules marked `autofix_safe` carry a `rewrite` that `--fix` applies in place:

```bash
slopguard scan --fix --dry-run    # unified diff of the rewrites, nothing written
slopguard scan --fix              # apply them
```

- Today `no-dbg-in-prod` and `no-unnecessary-clone` are autofixable
  (`(autofix)` in [RULES.md](RULES.md)).
- `--fix` refuses to run when the scanned paths have uncommitted changes, so
  every rewrite can be reviewed and reverted with git. `--allow-dirty` bypasses
  the check; outside a git repository there is nothing to check.
- Findings you suppressed inline, recorded in the baseline, or located in test
  code (for rules with `skip_test_code`) are never rewritten.
- After rewriting, slopguard scans again and exits 1 if findings remain.

To make a custom rule autofixable, add `rewrite` and `autofix_safe: true`, and
prove the rewrite with `tests.should_fix` (`before` / `after` pairs).

---

## 🔺 Severity Escalation

One `// TODO` is noise. Twenty of them in the same file is a quality problem.
Severity escalation turns the second case into an error: when a rule produces at
least `threshold` findings in a single file, that rule's warnings in that file
become errors.

```toml
[escalation]
enabled = true      # off by default
threshold = 5       # same rule firing 5 times in one file becomes an error

[escalation.rules]
no-todo-fixme = 3   # per-rule override of `threshold`
no-magic-number = 10
```

Rules:

- **Opt-in.** `enabled = false` by default, so existing CI results are unchanged
  until you switch it on.
- **Per file, per rule.** Counts never mix files or rule ids.
- **One level only.** A finding already at `error` counts toward the threshold
  but is never modified.
- **After the baseline.** Findings suppressed by a baseline do not inflate the
  count.

`slopguard scan --no-escalation` (also on `stats`) skips it for a single run,
whatever the config says.

Escalated findings are marked in every output:

```text
error[escalated][no-todo-fixme]: TODO/FIXME left in code. Resolve it or open an issue.
...
5 findings escalated to error
```

- **JSON**: `"escalated": true` on the finding, with `"severity": "error"`.
- **SARIF**: `properties.escalated: true`, with `level: "error"`.
- **HTML**: an `escalated` badge next to the severity chip, plus
  `data-escalated` on the row.

Because escalated findings are errors, `--severity-threshold error` now fails a
warnings-only run once a rule crosses its threshold. That is the point of the
feature, and why it ships off by default.

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
Cross-file rules still index the whole project (the unchanged files come from
the cache) and report the findings located in the changed files, so diff mode
agrees with a full scan.

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
    rev: slopguard-cli-v0.1.29   # any slopguard-cli-v* tag
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
