# Roadmap

## v0.1.0 - MVP (ast-grep only)

### Core
- [ ] Cargo workspace: slopguard-cli, slopguard-core, slopguard-rules
- [ ] Embed ast-grep-core + ast-grep-language + ast-grep-config as lib dependencies
- [ ] Rule loader: parse YAML rules from embedded builtin + custom dirs
- [ ] AST scanner: run rules against source files, collect findings
- [ ] Inline disable: parse `// slopguard-disable-next-line [rule-id]` comments
- [ ] Config: parse slopguard.toml (hierarchical global + project)
- [ ] File walker: gitignore-aware traversal via `ignore` crate, respect `files`/`ignores` globs

### CLI (clap)
- [ ] `slopguard scan [paths]` with `--format text|json|sarif`, `--severity-threshold`, `--config`
- [ ] `slopguard init` generates slopguard.toml with defaults
- [ ] `slopguard test` validates should_match/should_not_match for all rules
- [ ] `slopguard list` shows active rules with severity/category/language
- [ ] Exit codes: 0 clean, 1 findings, 2 config error
- [ ] Colored text output (rustc-style diagnostics)

### Rules (34 builtin)
- [ ] Migrate 27 Rust rules from personal-config/slopguard/rules/
- [ ] Migrate 5 TypeScript rules from personal-config/slopguard/rules/
- [ ] Migrate 2 new rules (no-manual-display, no-manual-rfc3339)
- [ ] Organize into rulesets: slop/, security/, correctness/
- [ ] Add inline tests (should_match + should_not_match) to every rule
- [ ] Add `category` field to every rule

### Testing
- [ ] Unit tests for config parsing
- [ ] Unit tests for rule loading and validation
- [ ] Unit tests for inline disable parsing
- [ ] Integration tests: scan a fixture project, assert expected findings
- [ ] Rule tests: every rule has should_match and should_not_match cases
- [ ] Negative tests: ensure rules do NOT fire on valid code
- [ ] Test SARIF output structure
- [ ] Test JSON output structure
- [ ] Test exit codes

### Distribution
- [ ] Publish to crates.io as `slopguard`
- [ ] CI: GitHub Actions (test, clippy, fmt, release)

---

## v0.2.0 - AI analysis

### AI integration
- [ ] Add slopguard-ai crate (or module in core)
- [ ] Integrate ironflow SDK: LlmProvider trait + Operations
- [ ] `ai_check` field in rule YAML (prompt template)
- [ ] AI rules: pre-filter candidates with AST, send context to LLM
- [ ] Multi-provider support: Anthropic, OpenAI, ollama
- [ ] Warning when AI rules skipped (no API key configured)
- [ ] `--no-ai` flag for fast local scans
- [ ] `ai.enabled`, `ai.provider`, `ai.model` in slopguard.toml

### AI-powered rules (candidates)
- [ ] Intermediate Row struct detection (struct with Row suffix, String fields mirroring typed fields)
- [ ] Redundant .to_string() on Serialize types
- [ ] SAFETY comment content validation (is the justification real or hallucinated?)
- [ ] Doc-comment quality (does it add information beyond the function name?)
- [ ] Cross-file pattern: trait with a single impl

### Cache
- [ ] Cache AI results by file content hash + rule version
- [ ] Store in .slopguard-cache/ (gitignored)
- [ ] `--no-cache` flag to force re-analysis

---

## v0.3.0 - Auto-fix and CI integration

### Auto-fix
- [ ] `fix` field supports ast-grep rewrite patterns
- [ ] `slopguard scan --fix` applies safe fixes
- [ ] `slopguard scan --fix --dry-run` previews fixes

### CI integration
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
