# Roadmap

## v0.1.0 - MVP (ast-grep only)

### Core

- [x] Cargo workspace: slopguard-cli, slopguard-core, slopguard-rules
- [x] Embed ast-grep-core + ast-grep-language + ast-grep-config as lib dependencies
- [x] Rule loader: parse YAML rules from embedded builtin + custom dirs
- [x] AST scanner: run rules against source files, collect findings
- [x] Inline disable: parse `// slopguard-disable-next-line [rule-id]` comments
- [x] Config: parse slopguard.toml (hierarchical global + project)
- [x] Config trust boundary: the scanned repo's slopguard.toml cannot set `[ai]` / `scan.cache_dir` or point rule paths outside the repo (D40, `--trust-repo-config`)
- [x] File walker: gitignore-aware traversal via `ignore` crate, respect `files`/`ignores` globs

### CLI (clap)

- [x] `slopguard scan [paths]` with `--format text|json|sarif`, `--severity-threshold`, `--config`
- [x] `slopguard init` generates slopguard.toml with defaults, or from `--preset default|strict|relaxed|ai`
- [x] `slopguard test` validates should_match/should_not_match for all rules
- [x] `slopguard list` shows active rules with severity/category/language
- [x] Exit codes: 0 clean, 1 findings, 2 config error
- [x] Colored text output (rustc-style diagnostics)

### Rules (34 at v0.1.0; today 117 shipped, 103 active by default)

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
- [x] Benchmark 2026-09-26 (commits epingles, `bench.sh` sans IA ni config du repo) : faux positifs corriges sur unresolved-import (38 -> 0), no-shell-format-arg (21 -> 0), no-assertion-free-test (3626 -> 680), no-duplicate-error-message (111 -> 29), no-single-impl-trait (21 -> 5)
- [x] no-assertion-free-test devient cross-file et suit les helpers de test du projet, crates dev-dependency comprises, avec l'option `[rules.options.no-assertion-free-test] assert_functions` (680 -> 26, D38)
- [x] Scans partiels (`--diff`, pre-commit) : index cross-file construit sur tout le projet, findings rapportes seulement dans les fichiers scannes (D39)
- [ ] no-assertion-free-test : traiter les verifications de bornes a la compilation ecrites comme des appels (`is_send::<T>()`), qui restent signalees

### Nouvelles regles ([#15](https://gitlab.com/ThomasTartrau/slopguard/-/issues/15))

- [x] Tier 1 : no-todo-fixme, no-empty-catch, no-println-in-prod, no-dbg-in-prod, no-commented-out-code, no-hedging-comment, no-deferral-comment, no-hardcoded-secret, no-eval
- [x] Tier 2 : no-unnecessary-clone, no-double-cast, no-ts-ignore-without-reason, no-box-dyn-error, no-excessive-comment-ratio
- [x] Tier 3 : no-arc-mutex-prefer-rwlock, no-doc-hidden-public, no-empty-doc-comment
- [x] Qualite des tests et stubs : no-assertion-free-test, no-over-mocking, no-weakened-assertion, no-stub-return, no-duplicate-error-message (cross-file) ([#39](https://gitlab.com/ThomasTartrau/slopguard/-/issues/39))
- [x] 10 regles TypeScript et slop (unknown, Reflect, spread dans reduce...) ([#42](https://gitlab.com/ThomasTartrau/slopguard/-/issues/42))

### Fonctionnalites

- [x] `slopguard explain <rule-id>` + `--rule <id>` ([#16](https://gitlab.com/ThomasTartrau/slopguard/-/issues/16))
- [x] Cache SHA256 des fichiers pour re-scans ([#17](https://gitlab.com/ThomasTartrau/slopguard/-/issues/17))
- [x] `slopguard baseline` pour ignorer les findings pre-existants ([#24](https://gitlab.com/ThomasTartrau/slopguard/-/issues/24))
- [x] `slopguard scan --format html` rapport visuel standalone + flag `-o/--output` ([#28](https://gitlab.com/ThomasTartrau/slopguard/-/issues/28))
- [x] Escalade de severite par seuil de repetition (`[escalation]`, `--no-escalation`) ([#29](https://gitlab.com/ThomasTartrau/slopguard/-/issues/29))
- [x] Regles file-level (metriques par fichier) ([#30](https://gitlab.com/ThomasTartrau/slopguard/-/issues/30))
- [x] Resolution des imports hallucines, regle `unresolved-import` Rust + TS ([#35](https://gitlab.com/ThomasTartrau/slopguard/-/issues/35))
- [x] Moteur de regles unifie derriere un trait `RuleEngine` ([#37](https://gitlab.com/ThomasTartrau/slopguard/-/issues/37))
- [x] `scan --report-unused-disable` ([#40](https://gitlab.com/ThomasTartrau/slopguard/-/issues/40))

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
- [x] Optional System One classifier (Jev / TypeSafe) with a calibrated threshold, `ai_check.reason: static | generated` ([#34](https://gitlab.com/ThomasTartrau/slopguard/-/issues/34))
- [x] Classifier requests batched per context cluster ([#41](https://gitlab.com/ThomasTartrau/slopguard/-/issues/41))
- [x] AI rules for SSRF and open redirect ([#31](https://gitlab.com/ThomasTartrau/slopguard/-/issues/31))

### AI-powered rules (candidates)

- [x] Intermediate Row struct detection (struct with Row suffix, String fields mirroring typed fields)
- [x] Redundant .to_string() on Serialize types
- [x] SAFETY comment content validation (is the justification real or hallucinated?)
- [x] Doc-comment quality (does it add information beyond the function name?)
- [x] Cross-file pattern: trait with a single impl (shipped as a builtin cross-file rule, not an AI rule, [#32](https://gitlab.com/ThomasTartrau/slopguard/-/issues/32))

### Cache

- [x] Cache AI results by file content hash + rule version
- [x] Store in the user cache dir, entries signed with a per-user key (D41)
- [x] `--no-cache` flag to force re-analysis

---

## v0.3.0 - Auto-fix and CI integration

### Auto-fix

- [x] `rewrite` field (ast-grep rewrite template) gated by `autofix_safe`, separate from the textual `fix` ([#33](https://gitlab.com/ThomasTartrau/slopguard/-/issues/33))
- [x] `slopguard scan --fix` applies safe fixes (refuses a dirty tree unless `--allow-dirty`)
- [x] `slopguard scan --fix --dry-run` previews fixes
- [ ] More autofixable rules (only no-dbg-in-prod and no-unnecessary-clone today)

### CI integration

GitHub Action, GitLab CI template and pre-commit hook shipped in v0.1.x (#18).

- [x] `slopguard scan --diff [--base <ref>]` pour ne scanner que les fichiers changes
- [ ] SARIF upload to GitHub Code Scanning (the action outputs SARIF but does not upload it)

---

## v0.4.0 - Community and extensibility

### Rule sharing

- [x] `[[rules.sources]]`: rulesets from git repositories or local paths, with provenance in `slopguard list` ([#38](https://gitlab.com/ThomasTartrau/slopguard/-/issues/38))
- [ ] `slopguard add <ruleset-url>` writes a `[[rules.sources]]` entry
- [ ] Lockfile pinning the resolved sha of each git source
- [ ] Registry of community rulesets
- [ ] Rule documentation site (generated from YAML)

### Additional languages

- [ ] Python support
- [ ] Go support

### Distribution

- [ ] Homebrew tap (pre-compiled binaries already ship on GitLab Releases, #19)
