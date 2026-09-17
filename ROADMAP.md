# Roadmap

## v0.1.0 - MVP (ast-grep only)

### Core

- [x] Cargo workspace: slopguard-cli, slopguard-core, slopguard-rules
- [x] Embed ast-grep-core + ast-grep-language + ast-grep-config as lib dependencies
- [x] Rule loader: parse YAML rules from embedded builtin + custom dirs
- [x] AST scanner: run rules against source files, collect findings
- [x] Inline disable: parse `// slopguard-disable-next-line [rule-id]` comments
- [x] Config: parse slopguard.toml (hierarchical global + project)
- [x] File walker: gitignore-aware traversal via `ignore` crate, respect `files`/`ignores` globs

### CLI (clap)

- [x] `slopguard scan [paths]` with `--format text|json|sarif`, `--severity-threshold`, `--config`
- [x] `slopguard init` generates slopguard.toml with defaults, or from `--preset default|strict|relaxed|ai`
- [x] `slopguard test` validates should_match/should_not_match for all rules
- [x] `slopguard list` shows active rules with severity/category/language
- [x] Exit codes: 0 clean, 1 findings, 2 config error
- [x] Colored text output (rustc-style diagnostics)

### Rules (55 builtin)

- [x] Migrate 27 Rust rules from personal-config/slopguard/rules/
- [x] Migrate 5 TypeScript rules from personal-config/slopguard/rules/
- [x] Migrate 2 new rules (no-manual-display, no-manual-rfc3339)
- [x] Organize into rulesets: slop/, security/, correctness/
- [x] Add inline tests (should_match + should_not_match) to every rule
- [x] Add `category` field to every rule

### Testing

- [x] Unit tests for config parsing
- [x] Unit tests for rule loading and validation
- [x] Unit tests for inline disable parsing
- [x] Integration tests: scan a fixture project, assert expected findings
- [x] Rule tests: every rule has should_match and should_not_match cases
- [x] Negative tests: ensure rules do NOT fire on valid code
- [x] Test SARIF output structure
- [x] Test JSON output structure
- [x] Test exit codes

### Distribution

- [x] Publish to crates.io as `slopguard`
- [x] CI: GitLab CI (test, clippy, fmt, release via release-plz)

---

## v0.1.x - Polish and validation

### Documentation

- [x] Refaire le README principal (badges, ASCII art, table des crates, architecture diagram, quick start)
- [x] Creer README pour slopguard-cli
- [x] Creer README pour slopguard-core
- [x] Creer README pour slopguard-rules
- [x] Ajouter `readme = "README.md"` dans chaque Cargo.toml de sous-crate

### Distribution

- [x] Binaires pre-compiles via GitLab CI ([#19](https://gitlab.com/ThomasTartrau/slopguard/-/issues/19))
- [x] Script d'installation `install.sh` ([#19](https://gitlab.com/ThomasTartrau/slopguard/-/issues/19))
- [x] Republier sur crates.io avec les README

### Validation sur le terrain

- [x] Scanner tokio, axum, ripgrep, cargo, serde pour mesurer faux positifs et performance
- [x] Script de benchmark reproductible (benchmarks/bench.sh + repos.toml)
- [x] Ajuster les regles bruyantes (opt-in pour pub-fn-needs-tracing, test-needs-timeout)
- [x] `--enable`/`--disable` CLI flags et `rules.enable` config

### Nouvelles regles ([#15](https://gitlab.com/ThomasTartrau/slopguard/-/issues/15))

- [x] Tier 1 : no-todo-fixme, no-empty-catch, no-println-in-prod, no-dbg-in-prod, no-commented-out-code, no-hedging-comment, no-deferral-comment, no-hardcoded-secret, no-eval
- [x] Tier 2 : no-unnecessary-clone, no-double-cast, no-ts-ignore-without-reason, no-box-dyn-error, no-excessive-comment-ratio
- [x] Tier 3 : no-arc-mutex-prefer-rwlock, no-doc-hidden-public, no-empty-doc-comment

### Fonctionnalites

- [x] `slopguard explain <rule-id>` + `--rule <id>` ([#16](https://gitlab.com/ThomasTartrau/slopguard/-/issues/16))
- [x] Cache SHA256 des fichiers pour re-scans ([#17](https://gitlab.com/ThomasTartrau/slopguard/-/issues/17))
- [x] `slopguard baseline` pour ignorer les findings pre-existants ([#24](https://gitlab.com/ThomasTartrau/slopguard/-/issues/24))
- [x] `slopguard scan --format html` rapport visuel standalone + flag `-o/--output` ([#28](https://gitlab.com/ThomasTartrau/slopguard/-/issues/28))

### CI integration ([#18](https://gitlab.com/ThomasTartrau/slopguard/-/issues/18))

- [x] GitLab CI template (`.gitlab-ci.yml` snippet pour les projets utilisateurs)
- [x] Pre-commit hook support
- [x] GitHub Action officielle

---

## v0.2.0 - AI analysis

### AI integration

- [x] Add slopguard-ai crate (or module in core)
- [x] Integrate ironflow SDK: LlmProvider trait + Operations
- [x] `ai_check` field in rule YAML (prompt template)
- [x] AI rules: pre-filter candidates with AST, send context to LLM
- [x] Multi-provider support: Anthropic, OpenAI (`api`) and local claude (`cli`)
- [x] Warning when AI rules skipped (no API key / credentials configured)
- [x] `--no-ai` flag for fast local scans
- [x] `ai.enabled`, `ai.provider`, `ai.model` in slopguard.toml
- [x] Runtime provider selection with clear errors on missing credentials
- [x] `slopguard list` shows rule type (ast vs ai); `explain` shows the prompt template

### AI-powered rules (candidates)

- [x] Intermediate Row struct detection (struct with Row suffix, String fields mirroring typed fields)
- [x] Redundant .to_string() on Serialize types
- [x] SAFETY comment content validation (is the justification real or hallucinated?)
- [x] Doc-comment quality (does it add information beyond the function name?)
- [ ] Cross-file pattern: trait with a single impl

### Cache

- [x] Cache AI results by file content hash + rule version
- [x] Store in .slopguard-cache/ (gitignored)
- [x] `--no-cache` flag to force re-analysis

---

## v0.3.0 - Auto-fix and CI integration

### Auto-fix

- [ ] `fix` field supports ast-grep rewrite patterns
- [ ] `slopguard scan --fix` applies safe fixes
- [ ] `slopguard scan --fix --dry-run` previews fixes

### CI integration

- [x] `slopguard scan --diff [--base <ref>]` pour ne scanner que les fichiers changes
- [ ] GitHub Action (`slopguard/action`)
- [ ] GitLab CI template
- [ ] Pre-commit hook support
- [ ] SARIF upload to GitHub Code Scanning

---

## v0.4.0 - Community and extensibility

### Rule sharing

- [ ] `slopguard add <ruleset-url>` installs third-party rulesets
- [ ] Registry of community rulesets
- [ ] Rule documentation site (generated from YAML)

### Additional languages

- [ ] Python support
- [ ] Go support

### Distribution

- [ ] Homebrew tap
- [ ] Pre-compiled binaries via cargo-dist / GitHub Releases
