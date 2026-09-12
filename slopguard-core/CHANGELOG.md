# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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

