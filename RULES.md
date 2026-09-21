# Builtin rules reference

All 34 rules with their current YAML definitions. Source files are in `personal-config/slopguard/rules/`.

## Ruleset: slop (9 rules)

AI-generated code patterns detected at abnormally high rates.

| Rule | Lang | Severity | What it catches |
| ------ | ------ | ---------- | ----------------- |
| no-slop-words | rust | warning | AI filler words in comments (comprehensive, robust, seamless, leverage...) |
| no-trivial-doc | rust | warning | Doc-comments like "This method provides..." that restate the name |
| no-paraphrase-doc | rust | warning | Doc-comments like "Create a new X" on every constructor |
| no-and-more-doc | rust | warning | Vague docs with "and more", "etc.", "various" |
| no-restated-comment | rust | warning | Comments that restate the code ("// increment the counter") |
| no-manual-display | rust | warning | Manual `impl fmt::Display` instead of derive(Display) from strum |
| no-manual-rfc3339 | rust | warning | `.to_rfc3339()` when serde + chrono handles it natively |
| no-inline-qualified-path | rust | warning | `std::collections::HashMap` inline instead of a `use` import |
| no-glob-reexport | rust | warning | `pub use module::*` instead of explicit re-exports |

## Ruleset: security (7 rules)

Security anti-patterns.

| Rule | Lang | Severity | What it catches |
| ------ | ------ | ---------- | ----------------- |
| no-debug-on-secrets | rust | error | derive(Debug) on structs with secret/token/password fields |
| no-empty-env-secret | rust | error | env::var() for secrets without rejecting empty strings |
| no-format-path | rust | error | format!() to build file paths (path traversal risk) |
| no-format-url | rust | error | format!() to build URLs (parameter injection risk) |
| no-unsafe-without-safety | rust | error | unsafe block without // SAFETY: comment |
| no-safety-hallucination | rust | error | // SAFETY: comment on code that is not actually unsafe |
| no-allow-dead-code | rust | error | #[allow(dead_code)] in src/ (remove dead code instead) |
| no-client-without-timeout | rust | error | reqwest::Client::new() without timeout configuration |

## Ruleset: correctness (18 rules)

Error handling, type safety, and correctness issues.

### Rust (13 rules)

| Rule | Lang | Severity | What it catches |
| ------ | ------ | ---------- | ----------------- |
| no-unwrap-in-prod | rust | error | .unwrap() outside tests/examples |
| no-expect-in-prod | rust | error | .expect() outside tests/examples/main |
| no-ignored-result | rust | error | `let _ = fallible_call()` |
| no-swallowed-error | rust | warning | `map_err(\|_\| ...)` discarding the original error |
| no-silent-fallback | rust | warning | unwrap_or("") / unwrap_or_default() hiding errors |
| no-double-fallback | rust | warning | Chained fallbacks (.ok().unwrap_or()) |
| no-ok-chain | rust | warning | .ok() silently converting errors to None |
| no-sqlx-runtime | rust | error | sqlx::query() instead of sqlx::query!() (no compile-time check) |
| no-index-without-if-not-exists | rust | error | CREATE INDEX without IF NOT EXISTS in migrations |
| no-float-money | rust | error | FLOAT/REAL/DOUBLE in SQL migrations for monetary values |
| pub-fn-needs-tracing | rust | warning | Public methods without #[tracing::instrument] |
| test-needs-timeout | rust | warning | Async tests without tokio::time::timeout |

### TypeScript (5 rules)

| Rule | Lang | Severity | What it catches |
| ------ | ------ | ---------- | ----------------- |
| no-any-typescript | ts | error | `any` type usage |
| no-async-foreach | ts | error | Async callbacks in forEach/map/filter/reduce |
| no-replace-single | ts | warning | .replace() without /g (only replaces first occurrence) |
| no-sort-without-comparator | ts | error | .sort() without comparator (lexicographic, not numeric) |
| no-useeffect-derived-state | ts | warning | useEffect + setState for derived state |

## AI rules (6 rules)

Rules that pair an AST pre-filter with an LLM confirmation step. The `rule`
pattern collects candidates; the `ai_check.prompt` template is sent to the
configured provider, and only confirmed candidates are reported. They are off
unless `[ai].enabled = true`, are skipped entirely with `--no-ai`, and show as
`type: ai` in `slopguard list`. See the "AI Rules" section of the README for
configuration.

| Rule | Ruleset | Lang | Severity | What it catches |
| ------ | --------- | ------ | ---------- | ----------------- |
| ai-safety-comment-validation | security | rust | error | `// SAFETY:` comments that reassure ("trust me", "this is safe") instead of stating the concrete invariants that make the unsafe block sound |
| ai-ssrf-unvalidated-url | security | rust | error | Outbound HTTP call (reqwest `.get`/`.post`/... or `reqwest::get`) whose URL is a bare variable, when that variable is unvalidated external input (SSRF) |
| ai-open-redirect-unvalidated | security | typescript | error | `.redirect(...)` whose target is derived from `req.query`/`body`/`params` without an allowlist check (open redirect) |
| ai-doc-comment-quality | slop | rust | warning | Doc-comments that only restate the function name and add no information a reader could not get from the signature |
| ai-intermediate-row-struct | correctness | rust | warning | Redundant `*Row` structs with String fields mirroring an already-typed struct, an artifact of AI-generated data mapping |
| ai-redundant-to-string-serialize | correctness | rust | warning | `.to_string()` calls on values that already implement `Serialize` and are about to be serialized |

Inspect the exact prompt sent to the model with `slopguard explain <rule-id>`.

## File-level rules (8 rules)

These carry a `metric` and a `threshold` instead of an AST `rule`. They measure
the whole file and report one finding at line 1 when the value is strictly
greater than the threshold.

| Rule | Language | Metric | Threshold | What it catches |
| ---- | -------- | ------ | --------- | --------------- |
| `max-file-lines` | rust | `file_lines` | 500 | Modules that kept growing instead of being split |
| `max-file-lines-ts` | typescript | `file_lines` | 500 | Same, for TypeScript |
| `max-import-count` | rust | `import_count` | 40 | Files with no single responsibility |
| `max-import-count-ts` | typescript | `import_count` | 40 | Same, for TypeScript |
| `max-function-count` | rust | `function_count` | 30 | Files with too many entry points to review as a unit |
| `max-function-count-ts` | typescript | `function_count` | 30 | Same, counting arrow functions and methods |
| `high-comment-ratio` | rust | `comment_ratio` | 0.4 | Code narrated line by line instead of explained |
| `high-comment-ratio-ts` | typescript | `comment_ratio` | 0.4 | Same, for TypeScript |

## Cross-file rules (1 rule)

These carry a `cross_file` kind instead of an AST `rule` or a `metric`. They are
evaluated once per scan, against a project-wide index built from every scanned
file, so they see facts no single file can show.

| Rule | Language | Kind | What it catches |
| ---- | -------- | ---- | --------------- |
| `no-single-impl-trait` | rust | `single_impl_trait` | A trait with exactly one implementor: an indirection that adds no choice |

`no-single-impl-trait` stays silent when the trait has no local impl (it is
implemented outside the crate), two or more impls, a blanket `impl<T> Foo for T`,
or a name declared more than once in the project. A `#[cfg(test)]` mock counts
as a second implementation, which is the point: a trait that exists to be mocked
is not an over-abstraction.

## Rule anatomy

Each rule follows this structure:

```yaml
# Identity
id: rule-id                        # unique, kebab-case
language: rust                     # rust | typescript
severity: error                    # error | warning
category: correctness              # slop | security | correctness

# User-facing text
message: "Short, actionable"      # what's wrong, what to do instead
note: "Explanation"                # why this matters
fix: "Use X instead"              # textual suggestion (human message, never applied)

# Autofix (scan --fix). `rewrite` is the ast-grep replacement template; it may
# reference the matcher's metavariables. It is applied only when the rule is
# also marked autofix_safe (idempotent, no semantic change). Distinct from
# `fix`, which stays a human message.
rewrite: "$R"                      # replacement template, optional
autofix_safe: true                 # opt-in; default false. Without it `rewrite` is inert.

# Optional: a dedicated fix matcher, when detection must be broader than the fix
# (detect broadly, fix narrowly). When set, `scan --fix` locates nodes with this
# matcher instead of `rule`, and detection `constraints` are not applied to it,
# so it must be self-contained. `null` (default) means --fix reuses `rule`.
# Example: flag every dbg!() but only auto-rewrite a single comma-free argument,
# since rewriting dbg!() or dbg!(a, b) would not compile.
autofix_rule:
  all:
    - pattern: dbg!($$$E)
    - not: { regex: '^dbg\s*!\s*\(\s*\)$' }
    - not: { regex: ',' }

# AST matcher (ast-grep syntax)
rule:
  pattern: $R.clone()              # or kind/regex/all/any/not/has/precedes/follows/inside

# Metavariable constraints (sibling of `rule`): restrict a captured metavariable.
# Here, only match when the receiver is an already-owned value.
constraints:
  R:
    any:
      - pattern: $X.to_string()
      - pattern: "format!($$$A)"

# ...or a file-level metric, mutually exclusive with `rule`
metric: file_lines                 # file_lines | import_count | function_count | comment_ratio
threshold: 500                     # required with `metric`; fires only above it, never at it
                                   # `$value` in `message` becomes the measured value

# ...or a project-wide analysis, mutually exclusive with both `rule` and `metric`
cross_file: single_impl_trait      # builtin kind; an unknown value is a parse error
                                   # no `tests` block: a snippet cannot exercise it

# Scope
files: ["**/src/**/*.rs"]          # only scan these
ignores: ["**/tests/**"]           # skip these
skip_test_code: true               # also drop findings inside #[cfg(test)] blocks (Rust)

# Inline tests
tests:
  should_match:
    - "snippet that triggers"
  should_not_match:
    - "snippet that must not trigger"
  # Autofixable rules: assert the rewrite. `slopguard test` applies `rewrite` to
  # `before` and requires the result to equal `after`. This is what proves a
  # rewrite is correct; add one per autofix_safe rule.
  should_fix:
    - before: "fn f() { let s = name.to_string().clone(); }"
      after: "fn f() { let s = name.to_string(); }"
  # Metric rules only: whole-file fixtures, relative to the rule's directory
  should_match_files:
    - "fixtures/metrics/rust_large.rs"
  should_not_match_files:
    - "fixtures/metrics/rust_small.rs"
```

## Key ast-grep syntax notes for implementors

- In tree-sitter-rust, **attributes are siblings of the item**, not children. `#[derive(Debug)]` and `struct Foo {}` are sibling nodes. Use `precedes`/`follows` to relate them, not `has`.
- **SQL is not a supported language**. SQL checks are done by matching `string_literal` nodes in Rust files (for inline migrations).
- **Patterns starting with `.`** (like `.map_err(|_| $$$)`) are not valid standalone patterns. Use `kind: call_expression` + `regex` instead.
- The `field: visibility_modifier` syntax is not valid in ast-grep. Use `has: { kind: visibility_modifier, regex: '^pub' }`.

## Research backing

- **ANTISLOP paper (ICLR 2026)**: certain words appear 1000x more often in LLM text than human text. The no-slop-words rule uses this word list.
- **SlopCodeBench**: 89.8% degradation in agent sessions from accumulated anti-patterns.
- **Tambon et al.**: 333 bugs across 10 categories from AI-generated code.
- **GitClear**: refactoring collapsed from 21% to 3.8% in AI-assisted codebases.
