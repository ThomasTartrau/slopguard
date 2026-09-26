# slopguard-cli

CLI binary for slopguard. Catches AI-generated code patterns and common correctness/security issues via static analysis.

This crate provides the `slopguard` command-line tool. For the core library, see [`slopguard-core`](https://crates.io/crates/slopguard-core). For the full project, see the [main README](https://gitlab.com/ThomasTartrau/slopguard).

## Install

```bash
cargo install slopguard-cli
```

## Commands

| Command | Description |
|---------|-------------|
| `slopguard scan [paths...]` | Scan files for rule violations |
| `slopguard stats [paths...]` | Show the distribution of findings instead of listing them |
| `slopguard baseline [paths...]` | Capture current findings into `.slopguard-baseline.json` |
| `slopguard list` | List active rules (`--all` includes opt-in rules) |
| `slopguard explain <rule-id>` | Show a rule's details, including the prompt of an AI rule |
| `slopguard test` | Validate all rule inline tests (should_match / should_not_match / should_fix) |
| `slopguard init` | Generate a `slopguard.toml` configuration file |

## Scan Options

| Flag | Description |
|------|-------------|
| `--format <text\|json\|sarif\|html>` | Output format (default: text) |
| `-o, --output <path>` | Write the report to a file instead of stdout |
| `--severity-threshold <error\|warning>` | Only exit non-zero for findings at or above this severity (default: warning) |
| `--config <path>` | Path to a slopguard.toml config file |
| `--no-colors` | Disable colored output |
| `--rule <id>` | Scan with only this rule |
| `--enable <id>` / `--disable <id>` | Enable or disable a rule for this run (repeatable) |
| `--test-path <glob>` | Extra glob marking files as test code (repeatable) |
| `--no-cache` / `--cache-dir <path>` | Force a full rescan / choose the cache directory |
| `--no-ai` | Skip AI rules entirely, no LLM or classifier calls |
| `--baseline <path>` / `--no-baseline` | Use a specific baseline file / ignore the baseline |
| `--no-escalation` | Disable severity escalation for this run |
| `--report-unused-disable` | Report disable comments that suppress no finding |
| `--diff` / `--base <ref>` | Only scan files changed in git (three-dot diff with `--base`) |
| `--fix` | Apply autofix-safe rewrites in place |
| `--dry-run` / `--allow-dirty` | With `--fix`: preview the diff / rewrite a dirty tree |
| `--offline` | Never fetch git rule sources, reuse the cache |

## Init Options

| Flag | Description |
|------|-------------|
| `--force` | Overwrite an existing `slopguard.toml` |
| `--preset <default\|strict\|relaxed\|ai>` | Config preset to generate. Pass `--preset` with no value to list the presets |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or all below severity threshold) |
| 1 | Findings found at or above severity threshold |
| 2 | Configuration error (invalid rule, missing file, bad TOML) |

## Examples

```bash
# Scan the current project
slopguard scan .

# Scan specific directories
slopguard scan src/api/ src/handlers/

# JSON output for CI pipelines
slopguard scan --format json

# SARIF for GitLab/GitHub code scanning integration
slopguard scan --format sarif

# Standalone visual report, single file, no external requests
slopguard scan --format html -o report.html

# Only fail on errors, not warnings
slopguard scan --severity-threshold error

# Only the files a merge request changed
slopguard scan --diff --base main

# Preview, then apply, the safe rewrites
slopguard scan --fix --dry-run
slopguard scan --fix

# Generate a config that only reports security and correctness errors
slopguard init --preset relaxed
```

## License

MIT - see [LICENSE](../LICENSE).
