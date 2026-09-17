# Design decisions

Decisions made during the architecture phase. This document is the source of truth for any implementing agent.

## D1: Language coverage
**Decision**: Rust + TypeScript at launch.
**Why**: 27 Rust rules and 5 TypeScript rules already exist. Both are supported by ast-grep/tree-sitter. Covers the author's projects without adding complexity.

## D2: Target audience
**Decision**: Individual developers + CI/teams from the start.
**Why**: The tool must work as a local linter (fast, colored output) AND in CI pipelines (JSON/SARIF output, strict exit codes, --severity-threshold).

## D3: Distribution
**Decision**: cargo install only for v0.1.0.
**Why**: Users are Rust developers who already have cargo. Brew and binary releases come later.

## D4: Naming
**Decision**: slopguard.
**Why**: Descriptive, memorable, available on crates.io and GitHub.

## D5: Workspace structure
**Decision**: Multi-crate workspace from the start (slopguard-cli, slopguard-core, slopguard-rules).
**Why**: Clean separation of concerns. The core crate can be used as a library for programmatic integration. Rules are embedded at compile time. Each crate is independently testable.

## D6: Rule format
**Decision**: YAML superset of ast-grep format.
**Why**: 100% compatible with ast-grep (id, language, rule, severity, message). Slopguard adds: category, fix (textual suggestion), tests (should_match/should_not_match), and later ai_check. Users familiar with ast-grep can write rules immediately.

## D7: Configuration
**Decision**: slopguard.toml with hierarchical resolution (global ~/.config/slopguard/config.toml + project slopguard.toml + CLI flags).
**Why**: Familiar pattern (eslint, rustfmt). Global config sets personal defaults, project config enforces team standards, CLI flags override for one-off runs.

## D8: Output formats
**Decision**: Text (default, colored) + JSON + SARIF.
**Why**: Text for humans, JSON for scripting/dashboards, SARIF for GitHub Code Scanning / GitLab SAST native integration. JUnit was considered but dropped (legacy only).

## D9: AI integration
**Decision**: Ironflow SDK (LlmProvider trait + Operations). Multi-provider (Claude, OpenAI, ollama). Deferred to v0.2.0.
**Why**: Ironflow SDK already provides the multi-provider abstraction and operation tracking. Using LlmProvider + Operations gives structured, tracked AI calls. Not in MVP to ship faster and validate the AST layer first.

## D10: AI fallback behavior
**Decision**: Warning per skipped AI rule when no API key is configured.
**Why**: The user must know which rules are not running. A silent skip would give false confidence. An error would be too strict for optional features.

## D11: Exit codes
**Decision**: 0 = clean, 1 = findings, 2 = config error. --severity-threshold controls what counts as a finding.
**Why**: Standard linter convention. --severity-threshold error makes warnings non-blocking in CI.

## D12: Inline suppression
**Decision**: `// slopguard-disable-next-line` and `// slopguard-disable-next-line <rule-id>`.
**Why**: Same pattern as eslint-disable-next-line. Allows suppressing false positives without touching config. Rule-specific suppression is optional but recommended.

## D13: ast-grep integration
**Decision**: Embed ast-grep-core + ast-grep-config + ast-grep-language as Rust library dependencies.
**Why**: Zero external binary dependency. Full control over execution, error handling, and output format. The crates are MIT licensed, actively maintained (v0.43.0, 172k downloads/month), and designed for library use.

## D14: Rulesets
**Decision**: Three thematic rulesets: slop, security, correctness. Each can be enabled/disabled in slopguard.toml.
**Why**: Lets users opt into what they care about. A security-focused team might disable slop rules. A solo dev might enable everything. Categorization also improves the `slopguard list` output.

## D15: Rule testing
**Decision**: Inline YAML tests (should_match / should_not_match). `slopguard test` command validates them.
**Why**: One file per rule = the rule definition + its tests. No need to navigate between files. Forces every rule to prove it works. Should_not_match prevents false positives. External test files can supplement for complex multi-line cases.

## D16: Auto-fix
**Decision**: Textual suggestion only in v0.1.0 (fix field contains a human-readable message).
**Why**: Safe and simple. AST-based auto-rewriting comes in v0.3.0 once the rule format is validated.

## D17: Cache
**Decision**: Deferred to v0.2.0. Cache AI results by file content hash + rule version in .slopguard-cache/.
**Why**: Not needed for AST-only scanning (already fast). Essential for AI rules to avoid redundant API calls and costs. In CI, the cache directory would be a CI cache artifact.

## D18: License
**Decision**: MIT.
**Why**: Permissive, standard for Rust CLI tools, no friction for enterprise adoption.

## D19: CLI commands
**Decision**: scan, init, test, list.
**Why**: scan = core functionality. init = onboarding. test = rule validation. list = discoverability. Covers all essential use cases. `explain <rule-id>` deferred to post-MVP.

## D20: MVP scope
**Decision**: v0.1.0 is AST-only with all 34 builtin rules. No AI.
**Why**: Ship fast, validate the format and DX. AI is additive and can layer on top without breaking changes.

## D21: No dylint
**Decision**: Skip dylint (custom Rust compiler lints). Use AI for type-aware patterns instead.
**Why**: dylint requires nightly, couples to unstable compiler internals, and each lint is 100-300 lines of Rust with undocumented APIs. For 2-5 type-aware patterns, the maintenance cost exceeds the value. AI with targeted context achieves similar precision with 1% of the effort.

## D22: Patterns that need AI (cannot be AST-detected)
The following patterns are deferred to v0.2.0 (AI rules):
- **Intermediate Row struct**: e.g. `JobRow { status: String }` that mirrors `Job { status: JobStatus }` with weaker types, plus a manual conversion function. Needs cross-struct comparison.
- **Redundant .to_string()**: e.g. `status: job.status.to_string()` when `JobStatus` already derives Serialize. Needs type information.
- **SAFETY comment content validation**: the comment exists (AST-detectable) but is the justification real or hallucinated? Needs semantic understanding.
- **Doc-comment quality**: the comment exists and is non-trivial, but does it actually add information? Needs NLP judgment.
- **Cross-file trait with single impl**: a trait defined in one file with exactly one implementation in another. Needs cross-file analysis.

## D23: Inline test code is filtered by an explicit rule flag
**Decision**: Rules opt into skipping `#[cfg(test)]` blocks with `skip_test_code: true`. The scanner locates those blocks on the tree-sitter AST (an `attribute_item` and the item it annotates) and drops the findings of opted-in rules inside them, after ast-grep matching. A textual brace scan was rejected: braces inside string literals or comments silently break it.
**Why**: `ignores` globs only filter whole files, but Rust convention puts unit tests inline in `src/`. Inferring the intent from the glob list (e.g. "contains `tests`") is fragile and invisible to rule authors. An explicit field keeps the YAML self-describing and lets a rule that must fire in tests (e.g. no-safety-hallucination) leave it off.

## D24: Baseline hash sans numero de ligne
**Decision**: un finding baseline est identifie par un SHA256 de `rule_id + chemin relatif au fichier baseline + matched_text + 2 lignes de contexte avant/apres, trimees`. Ni la ligne ni la colonne n'entrent dans le hash. Les doublons ne sont pas dedupliques : N occurrences identiques produisent N entrees, et le filtrage decompte (N baselinees, N+1 au scan -> 1 reporte).
**Why**: un hash incluant le numero de ligne invalide la baseline des la premiere insertion de code au-dessus, ce qui fait reapparaitre en masse des findings deja acceptes. Le contexte suffit a distinguer deux occurrences distinctes du meme pattern dans un meme fichier. La semantique de comptage evite qu'une occurrence baselinee masque une nouvelle occurrence identique.
**Cost**: modifier le code autour d'un finding baseline le fait reapparaitre. C'est assume : le code a change, la revue de ce finding aussi.

## D25: Config presets defined in code
**Decision**: `slopguard init --preset <default|strict|relaxed|ai>` renders its TOML from Rust in `slopguard-core::preset`. Fixed sections are string constants; the rule id lists (`strict`'s `enable`, `relaxed`'s `disable`) are computed from `load_builtin_rules()` at render time, sorted and deduped. No preset file ships on disk. The `strict` preset documents the warning severity threshold as a comment instead of a config key.
**Why**: a preset stored as data (a YAML or TOML file listing rule ids) drifts the moment a rule is renamed, retired, or flips its default, and nothing catches it. Deriving the lists from the shipped ruleset makes drift impossible by construction, and the unit tests round-trip every preset through `toml::from_str::<Config>` plus `is_rule_active` so a preset can never generate a config the scanner rejects. `--severity-threshold` is a `scan` flag with no `Config` key: adding one would mean making the flag optional and reworking scan resolution for a value that already defaults to `warning`, which is what strict wants. A comment in the generated file states the intent without inventing config surface.

## D26: Mode diff via git CLI
**Decision**: `slopguard scan --diff [--base <ref>]` resout la liste des fichiers changes en appelant le binaire `git` (`std::process::Command`), sans dependance `git2`/`gix`. Sans `--base`, la comparaison est `git diff HEAD` (staged + unstaged) ; avec `--base b`, c'est un diff trois points `b...HEAD`. Le filtre est `--diff-filter=ACMR` et la sortie est lue en `-z`. Les fichiers resultants sont passes tels quels au scanner via `scan_files` / `scan_files_cached`, sans parcours de repertoire, et un scan partiel ne purge jamais le cache.
**Why**: shell out vers `git` ne coute aucune dependance et utilise exactement la version de git que l'image CI embarque, y compris sa config (worktrees, submodules, `core.quotepath` neutralise par `-z`). Le diff trois points evite qu'une branche cible qui a avance fasse remonter des findings sans rapport avec la MR. `ACMR` exclut les suppressions (il n'y a plus rien a scanner) et rapporte les renommages sous leur nouveau nom. La liste explicite permet de scanner un fichier change meme s'il est cache ou gitignore, ce qu'un `WalkBuilder` refuserait. Enfin, purger le cache sur un scan partiel evincerait toutes les entrees encore valides des fichiers non regardes, et le scan complet suivant repartirait de zero.
**Cost**: les fichiers untracked ne sont pas inclus, puisque `git diff` ne les voit pas : il faut `git add` un nouveau fichier pour qu'il soit scanne. `--diff` exige un depot git, sinon exit 2.

## D27: File-level metric rules
**Decision**: a rule carries either an ast-grep `rule` matcher or a `metric` plus a `threshold`, never both. The four metrics (`file_lines`, `import_count`, `function_count`, `comment_ratio`) are computed directly on the parsed tree in `slopguard-core::metric`, outside ast-grep, and produce at most one finding per file, anchored at line 1 column 1, with `matched_text` set to the measured value and its unit ("547 lines"). Firing is strictly `value > threshold`, so `threshold: 500` does not flag a file of exactly 500 lines. Test cases are whole files: inline entries in `tests.should_match` / `should_not_match`, or fixture paths in `tests.should_match_files` / `should_not_match_files`.
**Why**: ast-grep matches nodes, not files. There is no node that represents "this file has 547 lines", so a metric cannot be expressed as a pattern and must be evaluated outside the matcher. Anchoring at line 1 is the only position a whole-file property can honestly claim; inventing a position (the last line, the widest function) would make the caret in the text output point at code that is not the problem. Strict `>` lets a threshold be read as "up to N is fine", which is how a size budget is written everywhere else. Snippet-based tests are useless for a metric: measuring a five-line snippet against a 500-line threshold proves nothing, so the fixtures are real files of the right size.
**Cost**: `// slopguard-disable-next-line` targets the line after the comment, so it can never target line 1: a file-level finding is not inline-suppressible. The escape hatches are the rule's `ignores` globs and `rules.disable` in config. Because `finding_hash` mixes `matched_text`, a baselined file-level finding reappears as soon as the measured value changes. That is correct (the file grew), but it means a baseline does not freeze a metric finding the way it freezes a pattern finding.
