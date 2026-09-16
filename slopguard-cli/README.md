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
| `slopguard list` | List all active rules |
| `slopguard test` | Validate all rule inline tests (should_match / should_not_match) |
| `slopguard init` | Generate a `slopguard.toml` configuration file |

## Scan Options

| Flag | Description |
|------|-------------|
| `--format <text\|json\|sarif>` | Output format (default: text) |
| `--severity-threshold <error\|warning>` | Minimum severity to report (default: warning) |
| `--config <path>` | Path to a slopguard.toml config file |
| `--no-colors` | Disable colored output |

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

# Only fail on errors, not warnings
slopguard scan --severity-threshold error

# Generate a config that only reports security and correctness errors
slopguard init --preset relaxed
```

## License

MIT - see [LICENSE](../LICENSE).
