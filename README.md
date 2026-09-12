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
[Custom Rules](#-custom-rules)

</div>

---

## What is slopguard?

AI code generators produce recurring anti-patterns: trivial doc-comments, swallowed errors, silent fallbacks, filler words in comments, missing timeouts, redundant string conversions. These patterns are structurally detectable but no existing tool catches them systematically.

slopguard fills that gap with builtin rules organized into three rulesets (**slop**, **security**, **correctness**), covering both **Rust and TypeScript**. Rules are defined in YAML using ast-grep pattern syntax, powered by tree-sitter for AST-level matching. Every rule ships with inline tests.

You can extend slopguard with your own YAML rules, disable rules per-line with inline suppression comments, and output findings as colored text (rustc-style), JSON, or SARIF for CI integration.

---

## 🏗️ Architecture

| Crate | Version | Role |
|---|---|---|
| [`slopguard-cli`](https://crates.io/crates/slopguard-cli) | ![](https://img.shields.io/crates/v/slopguard-cli.svg?label=) | CLI binary: scan, init, test, list commands |
| [`slopguard-core`](https://crates.io/crates/slopguard-core) | ![](https://img.shields.io/crates/v/slopguard-core.svg?label=) | Analysis engine: scanner, config, rule loading, inline disable |
| [`slopguard-rules`](https://crates.io/crates/slopguard-rules) | ![](https://img.shields.io/crates/v/slopguard-rules.svg?label=) | Builtin YAML rules embedded at compile time |

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
|----|-------------|--------|
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
slopguard list                       # show active rules
slopguard test                       # validate all rule inline tests
slopguard init                       # generate slopguard.toml
```

---

## 📋 Rulesets

| Ruleset | What it catches |
|---------|-----------------|
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

## 🚫 Inline Suppression

```rust
// slopguard-disable-next-line
let value = risky_call().unwrap();

// slopguard-disable-next-line no-unwrap-in-prod
let value = safe_call().unwrap();
```

The first form suppresses all rules for the next line. The second form suppresses only the named rule.

---

## 📄 License

MIT - see [LICENSE](LICENSE).

---

<div align="center">

**[GitLab](https://gitlab.com/ThomasTartrau/slopguard)**

[cli](https://crates.io/crates/slopguard-cli) -
[core](https://crates.io/crates/slopguard-core) -
[rules](https://crates.io/crates/slopguard-rules)

</div>
