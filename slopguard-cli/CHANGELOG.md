# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.14](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.13...slopguard-cli-v0.1.14) - 2026-09-16

### Changed

- #27 move preset parsing logic to core

## [0.1.13](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.12...slopguard-cli-v0.1.13) - 2026-09-16

### Added

- #26 add stats subcommand with findings distribution


### Changed

- #26 extract common JSON and plural helpers into output module

## [0.1.12](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.11...slopguard-cli-v0.1.12) - 2026-09-16

### Added

- #25 add diff-aware scanning with --diff and --base


### Changed

- #25 extract count_severities for reuse across CLI

## [0.1.11](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.10...slopguard-cli-v0.1.11) - 2026-09-16
## [0.1.8](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.7...slopguard-cli-v0.1.8) - 2026-09-14

### Added

- #23 add 18 builtin rules for Rust and TypeScript

## [0.1.7](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.6...slopguard-cli-v0.1.7) - 2026-09-13

### Added

- #20 #21 #22 AI rule pipeline, 4 builtin AI rules, CLI integration

## [0.1.6](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.5...slopguard-cli-v0.1.6) - 2026-09-12

### Added

- #18 add CI integration templates and --cache-dir flag

## [0.1.5](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.4...slopguard-cli-v0.1.5) - 2026-09-12

### Added

- #17 add file-based scan cache with SHA256 content hashing

## [0.1.3](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.2...slopguard-cli-v0.1.3) - 2026-09-12

### Added

- #16 add explain command, --rule scan filter, fuzzy suggestions

## [0.1.2](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.1...slopguard-cli-v0.1.2) - 2026-09-12

### Added

- #14 add opt-in rules, reduce false positives, reproducible benchmarks

## [0.1.1](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-cli-v0.1.0...slopguard-cli-v0.1.1) - 2026-09-12

### Documentation

- #12 add per-crate READMEs and improve main documentation for crates.io

## [0.1.0](https://gitlab.com/ThomasTartrau/slopguard/releases/tag/slopguard-cli-v0.1.0) - 2026-09-12

### Added

- #8 implement init, test, and list commands with filtering options

- #7 implement output formatters (text, json, sarif) with cli options

- #1 scaffold Cargo workspace (cli, core, rules)

