# Builtin rules reference

117 rule files ship in `slopguard-rules/rules/{slop,security,correctness}/`. 103
are active by default; the other 14 are opt-in (`enabled: false`) and run only
when listed in `rules.enable` or passed with `--enable`. `slopguard list --all`
is the authoritative inventory, and `slopguard explain <rule-id>` prints a
rule's full definition.

| Type | Files | Active by default | Section |
| ---- | ----- | ----------------- | ------- |
| `ast` | 98 | 84 | [AST rules](#ast-rules-98) |
| `ai` | 6 | 6 | [AI rules](#ai-rules-6) |
| `metric` | 8 | 8 | [File-level rules](#file-level-rules-8) |
| `cross-file` | 3 | 3 | [Cross-file rules](#cross-file-rules-3) |
| `resolution` | 2 | 2 | [Resolution rules](#resolution-rules-2) |

A rule id is unique per language, not globally: most rules exist once for Rust
and once for TypeScript under the same id, and a single `rules.disable` entry
covers both variants.

## AST rules (98)

Plain ast-grep matchers. The "What it catches" column is the first sentence of
the rule's `message`; `(autofix)` marks the rules `scan --fix` can rewrite.

### slop (33 rules, 24 on by default)

AI-generated code patterns detected at abnormally high rates.

#### Rust (19)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `max-function-lines` | warning | opt-in | Function exceeds 80 lines. |
| `no-and-more-doc` | warning | on | Vague documentation ('and more', 'etc.', 'various'). |
| `no-commented-out-code` | warning | opt-in | Commented-out code. |
| `no-deferral-comment` | warning | on | Deferral language in comment. |
| `no-doc-hidden-public` | warning | opt-in | #[doc(hidden)] on a public item. |
| `no-em-dash` | warning | on | Em dash (U+2014) in source. |
| `no-empty-doc-comment` | warning | opt-in | Empty doc comment. |
| `no-glob-reexport` | warning | on | pub use module::*. |
| `no-hedging-comment` | warning | on | Hedging language in comment. |
| `no-inline-qualified-path` | warning | opt-in | Inline qualified path. |
| `no-manual-display` | warning | on | Manual Display impl with match. |
| `no-manual-rfc3339` | warning | on | .to_rfc3339() is usually redundant. |
| `no-obvious-comment` | warning | on | Obvious comment restating the code. |
| `no-paraphrase-doc` | warning | on | Doc-comment paraphrasing the method name. |
| `no-restated-comment` | warning | on | Comment restating the code. |
| `no-slop-words` | warning | on | AI filler word in a comment. |
| `no-stub-return` | warning | opt-in | Function body is a single bare constant. |
| `no-trivial-doc` | warning | on | Trivial doc-comment restating the name. |
| `no-trivial-function` | warning | on | Trivial wrapper function. |

#### TypeScript (14)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `max-function-lines` | warning | opt-in | Function exceeds 80 lines. |
| `no-commented-out-code` | warning | opt-in | Commented-out code. |
| `no-conditional-empty-object-spread` | warning | on | Conditional spread with an empty-object branch. |
| `no-deferral-comment` | warning | on | Deferral language in comment. |
| `no-duplicate-logic-block` | warning | on | Consecutive identical statements. |
| `no-em-dash` | warning | on | Em dash (U+2014) in source. |
| `no-hedging-comment` | warning | on | Hedging language in comment. |
| `no-obvious-comment` | warning | on | Obvious comment restating the code. |
| `no-reduce-accumulator-copy` | warning | on | reduce() spreads the accumulator into a new object on every iteration. |
| `no-reflect-apply` | warning | on | Reflect.apply() used where a direct call would do. |
| `no-reflect-get` | warning | on | Reflect.get() used where plain property access would do. |
| `no-static-only-class` | warning | on | Class with only static members. |
| `no-stub-return-ts` | warning | opt-in | Function body is a single bare constant. |
| `no-trivial-function` | warning | on | Trivial wrapper function. |

### security (19 rules, 19 on by default)

Security anti-patterns.

#### Rust (12)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `no-allow-dead-code` | error | on | #[allow(dead_code)] in src/. |
| `no-client-without-timeout` | error | on | reqwest::Client without timeout. |
| `no-debug-on-secrets` | error | on | derive(Debug) on a type with a secret field. |
| `no-empty-env-secret` | error | on | std::env::var() without empty value rejection. |
| `no-format-path` | error | on | format!() to build a file path. |
| `no-format-url` | error | on | format!() to build a URL. |
| `no-hardcoded-cloud-token` | error | on | Hardcoded token matching a known cloud/CI provider format. |
| `no-hardcoded-secret` | error | on | Hardcoded secret in source code. |
| `no-jwt-validation-disabled` | error | on | JWT validate_exp or validate_aud disabled. |
| `no-safety-hallucination` | error | on | Suspicious // SAFETY comment. |
| `no-shell-format-arg` | error | on | Shell command line built with format!(). |
| `no-unsafe-without-safety` | error | on | unsafe block without // SAFETY: comment. |

#### TypeScript (7)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `no-console-in-handler` | warning | on | console call in an HTTP handler. |
| `no-eval` | error | on | eval() is a code injection vector. |
| `no-exec-template-literal` | error | on | exec()/execSync() called with a template literal that interpolates a value. |
| `no-hardcoded-cloud-token` | error | on | Hardcoded token matching a known cloud/CI provider format. |
| `no-hardcoded-secret` | error | on | Hardcoded secret in source code. |
| `no-sql-string-concat` | error | on | SQL built by concatenation. |
| `no-unsafe-json-parse` | error | on | JSON.parse without try/catch. |

### correctness (46 rules, 41 on by default)

Error handling, type safety, test quality and correctness issues.

#### Rust (21)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `no-arc-mutex-prefer-rwlock` | warning | opt-in | Arc<Mutex<T>> when reads dominate writes. |
| `no-box-dyn-error` | warning | on | Box<dyn Error> loses error context. |
| `no-dbg-in-prod` (autofix) | error | on | dbg!() left in production code. |
| `no-dead-branch` | warning | on | Tautological branch condition. |
| `no-double-fallback` | warning | on | Silent double fallback. |
| `no-expect-in-prod` | error | on | .expect() forbidden in production. |
| `no-float-money` | error | on | FLOAT/REAL/DOUBLE in SQL. |
| `no-ignored-result` | warning | on | Result ignored via let _ =. |
| `no-index-without-if-not-exists` | error | on | CREATE INDEX without IF NOT EXISTS in a SQL migration. |
| `no-magic-number` | warning | opt-in | Magic number in logic. |
| `no-ok-chain` | warning | on | .ok() followed by unwrap is redundant. |
| `no-println-in-prod` | warning | on | println!/eprintln! in production code. |
| `no-silent-fallback` | warning | on | unwrap_or/unwrap_or_default hides a potential error. |
| `no-sqlx-runtime` | warning | on | sqlx::query() runtime. |
| `no-swallowed-error` | warning | on | Source error discarded. |
| `no-todo-fixme` | warning | on | TODO/FIXME left in code. |
| `no-unnecessary-clone` (autofix) | warning | on | Unnecessary .clone() on a value that is already owned or trivially copyable. |
| `no-unwrap-in-prod` | error | on | .unwrap() forbidden in production. |
| `no-weakened-assertion` | warning | on | Trivial assertion that can never fail. |
| `pub-fn-needs-tracing` | warning | opt-in | Public async method without #[tracing::instrument]. |
| `test-needs-timeout` | warning | opt-in | Async test without tokio::time::timeout. |

#### TypeScript (25)

| Rule | Severity | Default | What it catches |
| ---- | -------- | ------- | --------------- |
| `no-any-typescript` | error | on | any is forbidden. |
| `no-assertion-free-test-ts` | warning | on | Test with no expect(). |
| `no-async-foreach` | error | on | Async callback in forEach/map/filter/reduce. |
| `no-async-without-await` | warning | on | async function never awaits. |
| `no-broad-catch` | warning | on | Broad catch binding. |
| `no-catch-log-rethrow` | warning | on | Catch that only logs and rethrows. |
| `no-dead-branch` | warning | on | Tautological branch condition. |
| `no-double-cast` | error | on | 'as unknown as T' bypasses type safety. |
| `no-empty-catch` | error | on | Empty catch block silently swallows errors. |
| `no-floating-promise` | error | on | Floating promise. |
| `no-magic-number` | warning | opt-in | Magic number in logic. |
| `no-over-mocking-ts` | warning | on | Mocking a local module. |
| `no-replace-single` | warning | on | .replace() only replaces the first occurrence. |
| `no-sort-without-comparator` | error | on | .sort() without comparator is lexicographic. |
| `no-throw-string` | warning | on | Throwing a string. |
| `no-todo-fixme` | warning | on | TODO/FIXME left in code. |
| `no-ts-ignore-without-reason` | warning | on | @ts-ignore without a justification. |
| `no-unknown-parameters` | error | on | Function parameter typed unknown. |
| `no-unknown-returns` | error | on | Function return type is unknown. |
| `no-unknown-type-aliases` | error | on | Type alias resolves to unknown. |
| `no-unsafe-dictionary-type` | error | on | Record<string, unknown> or a string index signature to unknown. |
| `no-useeffect-derived-state` | warning | on | useEffect for derived state. |
| `no-weakened-assertion-ts` | warning | on | Trivial assertion that can never fail. |
| `no-widen-then-assert` | error | on | Value widened to unknown/object/Record<string, unknown> then re-cast with as. |
| `require-safety-comment-for-type-assertion` | error | on | Type assertion (as T) without a // SAFETY: comment. |

## AI rules (6)

Rules that pair an AST pre-filter with a model confirmation step. The `rule`
pattern collects candidates; each candidate is then confirmed either by the
generative LLM (`[ai].enabled = true`), which receives the `ai_check.prompt`
template, or by the optional classifier (`[ai.classifier].enabled = true`),
which returns a probability compared to a threshold. Only confirmed candidates
are reported. Without a configured provider they are skipped with a single
warning, `--no-ai` skips them entirely, and they show as `type: ai` in
`slopguard list`. See the "AI Rules" section of the README for configuration.

| Rule | Ruleset | Lang | Severity | Reason | What it catches |
| ------ | --------- | ------ | ---------- | ------ | ----------------- |
| ai-safety-comment-validation | security | rust | error | static | `// SAFETY:` comments that reassure ("trust me", "this is safe") instead of stating the concrete invariants that make the unsafe block sound |
| ai-ssrf-unvalidated-url | security | rust | error | generated | Outbound HTTP call (reqwest `.get`/`.post`/... or `reqwest::get`) whose URL is a bare variable, when that variable is unvalidated external input (SSRF) |
| ai-open-redirect-unvalidated | security | typescript | error | generated | `.redirect(...)` whose target is derived from `req.query`/`body`/`params` without an allowlist check (open redirect) |
| ai-doc-comment-quality | slop | rust | warning | static | Doc-comments that only restate the function name and add no information a reader could not get from the signature |
| ai-intermediate-row-struct | correctness | rust | warning | static | Redundant `*Row` structs with String fields mirroring an already-typed struct, an artifact of AI-generated data mapping |
| ai-redundant-to-string-serialize | correctness | rust | warning | static | `.to_string()` calls on values that already implement `Serialize` and are about to be serialized |

`Reason` only matters with the classifier: a `static` rule reports its note,
a `generated` rule asks the LLM to explain each fired candidate.

Inspect the exact prompt sent to the model with `slopguard explain <rule-id>`.

## File-level rules (8)

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

## Cross-file rules (3)

These carry a `cross_file` kind instead of an AST `rule` or a `metric`. They are
evaluated against a project-wide index, so they see facts no single file can
show. A partial scan (`--diff`, or the files a pre-commit hook passes) still
indexes the whole project and reports the findings located in the scanned
files.

| Rule | Language | Kind | What it catches |
| ---- | -------- | ---- | --------------- |
| `no-single-impl-trait` | rust | `single_impl_trait` | A trait with exactly one implementor: an indirection that adds no choice |
| `no-duplicate-error-message` | rust | `duplicate_error_message` | The same error value message (`bail!`, `anyhow!`, `eyre!`, `format_err!`, `ensure!`) copied into two or more files |
| `no-assertion-free-test` | rust | `assertion_free_test` | A test that checks nothing itself and calls no test code that does |

`no-single-impl-trait` stays silent when the trait has no local impl (it is
implemented outside the crate), two or more impls, a blanket `impl<T> Foo for T`,
or a name declared more than once in the project. A `#[cfg(test)]` mock counts
as a second implementation, which is the point: a trait that exists to be mocked
is not an over-abstraction. It also stays silent for an extension trait: when
the single impl targets a type that is not a struct, enum or union of the
trait's own crate (a foreign type, a type alias, or a type from a sibling
workspace crate), Rust does not allow inherent methods there, so the trait is
the only option.

`no-duplicate-error-message` only considers literals of 10 characters or more,
ignores duplication inside a single file, and skips test code. Panic messages
(`panic!`, `.expect()`, `unreachable!`) are not considered: a panic prints its
file and line, so a repeated message is still traced to its site.

`no-assertion-free-test` treats as an assertion any `assert`/`panic`, `?`,
`.unwrap()`/`.expect()` (and their `_err` forms), inline snapshot (`str![..]`,
`expect![..]`) or `#[should_panic]`. A test without one is still fine when it
calls, directly or through other helpers, test code that has one: a function or
`macro_rules!` inside `#[cfg(test)]`, under a test path (`tests/`, `benches/`,
`scan.test_paths`), or in a crate the workspace pulls in only as a
dev-dependency (`cargo-test-support`). Helpers are matched by bare name. A
production function with a precondition `assert!` does not count. Compile-only
tests (item declarations and typed `let _: T = ..` bindings only) and trybuild
directories (`tests/ui`, `tests/fail`, `tests/pass`) are skipped. For test
helpers that live outside the project, list them in the config:

```toml
[rules.options.no-assertion-free-test]
assert_functions = ["run", "check_*"]   # bare names, * is a wildcard
```

## Resolution rules (2)

These carry a `resolution` kind instead of an AST `rule`, a `metric` or a
`cross_file` kind. They check that every import in a file resolves against the
declared dependencies and on-disk paths, without a full compile and with no
network or `cargo`/`npm` invocation. Unlike cross-file rules they are per file,
so they run under `--diff` too. Imports are extracted with the file (and cached
with it) but re-resolved against the manifests on every scan, so adding a
dependency clears a finding even when the importing file is unchanged.

| Rule | Language | Kind | What it catches |
| ---- | -------- | ---- | --------------- |
| `unresolved-import` | rust | `unresolved_import` | A `use` whose crate root is not in Cargo.toml, a standard crate (std, core, alloc, proc_macro, test), a `crate`/`self`/`super` path, or a name the file binds itself |
| `unresolved-import` | typescript | `unresolved_import` | An `import`/`require` absent from package.json and not a relative file, Node builtin, or tsconfig `paths` alias |

Resolution stays silent when no manifest is reachable (nothing can be asserted),
for statement-level `import type` (may resolve to ambient declarations), for
re-exports (`export ... from`, not parsed as imports), and for TypeScript
`compilerOptions.paths` aliases. Rust checks only the crate root, never a deep
path. `$import` in the message is replaced with the unresolved specifier.

In Rust 2018+, a `use` can start from any name already in scope, so a Rust root
also resolves when it is:

- a name the file binds: a `mod` (including one declared inside a macro body
  such as `cfg_if!`), the last segment or alias of another `use`
  (`use crate::runtime::scheduler;` then `use scheduler::Context;`), or the
  parent path of a `self` in a list;
- an uppercase name (`use Ordering::*`): crates are lowercase, so it names an
  item in scope;
- in a module that also holds a non-std glob import (`use super::*;`,
  `use crate::prelude::*;`): the glob may have brought the root into scope, so
  that module's imports are not asserted.

Cross-file and resolution rules have no inline `tests` block: a snippet cannot
carry a project index or a manifest. `slopguard test` lists them as "no tests";
their coverage lives in `tests/fixtures/` and the CLI integration tests.

## Rule anatomy

Each rule follows this structure:

```yaml
# Identity
id: rule-id                        # kebab-case, unique per language
language: rust                     # rust | typescript
severity: error                    # error | warning
category: correctness              # slop | security | correctness
enabled: false                     # opt-in rule; default true

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

# AI confirmation: turns the matcher above into a candidate pre-filter
ai_check:
  prompt: "..."                    # {{filename}}, {{rule_context}} and {{code}} are substituted
  model: "claude-haiku-4-5"        # optional per-rule LLM model
  reason: static                   # static (default) | generated
  threshold: 0.8                   # optional per-rule classifier threshold
  if_true: "..."                   # optional classifier criteria, in prose
  if_false: "..."

# ...or a file-level metric, mutually exclusive with `rule`
metric: file_lines                 # file_lines | import_count | function_count | comment_ratio
threshold: 500                     # required with `metric`; fires only above it, never at it
                                   # `$value` in `message` becomes the measured value

# ...or a per-file import resolution, mutually exclusive with `rule`, `metric` and `cross_file`
resolution: unresolved_import      # builtin kind; an unknown value is a parse error

# ...or a project-wide analysis, mutually exclusive with both `rule` and `metric`
cross_file: single_impl_trait      # or duplicate_error_message; an unknown value is a parse error
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
