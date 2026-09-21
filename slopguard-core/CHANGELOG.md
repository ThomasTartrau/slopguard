# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.21](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.20...slopguard-core-v0.1.21) - 2026-09-21

### Added

- #35 add import resolution for unresolved/hallucinated imports

## [0.1.20](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.19...slopguard-core-v0.1.20) - 2026-09-21

### Added

- #33 add scan --fix autofix-safe rewrites

## [0.1.19](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.18...slopguard-core-v0.1.19) - 2026-09-19

### Added

- #34 add System One classifier (Jev/TypeSafe) pass

## [0.1.18](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.17...slopguard-core-v0.1.18) - 2026-09-19

### Changed

- separate module tests into dedicated files and extract scan logic

## [0.1.17](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.16...slopguard-core-v0.1.17) - 2026-09-19

### Added

- #32 add cross-file rule pass and no-single-impl-trait


### Changed

- #32 move is_test_path to test_filter module and simplify cross-file compilation

## [0.1.16](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.15...slopguard-core-v0.1.16) - 2026-09-18

### Added

- #31 add ai-ssrf-unvalidated-url and ai-open-redirect-unvalidated rules

## [0.1.15](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.14...slopguard-core-v0.1.15) - 2026-09-18

### Added

- #30 add file-level metric rules with per-file structural thresholds


### Fixed

- #30 fix CI failures in file-level metric rules

## [0.1.14](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.13...slopguard-core-v0.1.14) - 2026-09-17

### Added

- #29 escalate repeated warnings to errors per file


### Fixed

- #29 deduplicate escalation block across presets

## [0.1.13](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.12...slopguard-core-v0.1.13) - 2026-09-17

### Added

- #28 add HTML report output format with --output flag

## [0.1.12](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.11...slopguard-core-v0.1.12) - 2026-09-16

### Added

- #27 add config presets to slopguard init


### Changed

- #27 move preset parsing logic to core

## [0.1.11](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.10...slopguard-core-v0.1.11) - 2026-09-16

### Added

- #25 add diff-aware scanning with --diff and --base


### Changed

- #25 extract count_severities for reuse across CLI

## [0.1.10](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.9...slopguard-core-v0.1.10) - 2026-09-16

### Fixed

- update builtin rule count to 86 and bump rustls to 0.23.45

## [0.1.9](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.8...slopguard-core-v0.1.9) - 2026-09-14

### Fixed

- reduce false positive rate by 63% on real-world codebase

## [0.1.8](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.7...slopguard-core-v0.1.8) - 2026-09-14

### Added

- #23 add 18 builtin rules for Rust and TypeScript

## [0.1.7](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.6...slopguard-core-v0.1.7) - 2026-09-13

### Added

- #20 #21 #22 AI rule pipeline, 4 builtin AI rules, CLI integration

## [0.1.6](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.5...slopguard-core-v0.1.6) - 2026-09-12

### Added

- #18 add CI integration templates and --cache-dir flag

## [0.1.5](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.4...slopguard-core-v0.1.5) - 2026-09-12

### Added

- #17 add file-based scan cache with SHA256 content hashing

## [0.1.4](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.3...slopguard-core-v0.1.4) - 2026-09-12

### Added

- #15 add 21 builtin rules with multi-language support

## [0.1.3](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.2...slopguard-core-v0.1.3) - 2026-09-12

### Added

- #16 add explain command, --rule scan filter, fuzzy suggestions

## [0.1.2](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.1...slopguard-core-v0.1.2) - 2026-09-12

### Added

- #14 add opt-in rules, reduce false positives, reproducible benchmarks

## [0.1.1](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-core-v0.1.0...slopguard-core-v0.1.1) - 2026-09-12

### Documentation

- #12 add per-crate READMEs and improve main documentation for crates.io

## [0.1.0](https://gitlab.com/ThomasTartrau/slopguard/releases/tag/slopguard-core-v0.1.0) - 2026-09-12

### Added

- #9 add skip_test_code flag to filter findings in #[cfg(test)] blocks

- #8 implement init, test, and list commands with filtering options

- #7 implement output formatters (text, json, sarif) with cli options

- #11 introduce RuleId newtype for type safety

- #6 implement inline disable directives

- #5 implement scanner core with parallel file processing

- #4 implement config system

- #3 add inline tests and validation for builtin rules

- #2 implement rule loading and builtin rule set

- #1 scaffold Cargo workspace (cli, core, rules)

