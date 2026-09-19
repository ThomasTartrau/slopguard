# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.11](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.10...slopguard-rules-v0.1.11) - 2026-09-19

### Changed

- separate module tests into dedicated files and extract scan logic

## [0.1.10](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.9...slopguard-rules-v0.1.10) - 2026-09-19

### Added

- #32 add cross-file rule pass and no-single-impl-trait

## [0.1.9](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.8...slopguard-rules-v0.1.9) - 2026-09-18

### Added

- #31 add ai-ssrf-unvalidated-url and ai-open-redirect-unvalidated rules

## [0.1.8](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.7...slopguard-rules-v0.1.8) - 2026-09-18

### Added

- #30 add file-level metric rules with per-file structural thresholds

## [0.1.7](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.6...slopguard-rules-v0.1.7) - 2026-09-16

### Added

- add 5 security rules (exec injection, hardcoded tokens, JWT bypass, shell format arg)

## [0.1.6](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.5...slopguard-rules-v0.1.6) - 2026-09-14

### Fixed

- reduce false positive rate by 63% on real-world codebase

## [0.1.5](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.4...slopguard-rules-v0.1.5) - 2026-09-14

### Added

- #23 add 18 builtin rules for Rust and TypeScript

## [0.1.4](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.3...slopguard-rules-v0.1.4) - 2026-09-13

### Added

- #20 #21 #22 AI rule pipeline, 4 builtin AI rules, CLI integration

## [0.1.3](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.2...slopguard-rules-v0.1.3) - 2026-09-12

### Added

- #15 add 21 builtin rules with multi-language support

## [0.1.2](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.1...slopguard-rules-v0.1.2) - 2026-09-12

### Added

- #14 add opt-in rules, reduce false positives, reproducible benchmarks

## [0.1.1](https://gitlab.com/ThomasTartrau/slopguard/compare/slopguard-rules-v0.1.0...slopguard-rules-v0.1.1) - 2026-09-12

### Documentation

- #12 add per-crate READMEs and improve main documentation for crates.io

