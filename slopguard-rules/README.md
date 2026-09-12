# slopguard-rules

Embedded builtin rule definitions for slopguard. YAML rules compiled into the binary at build time via `rust-embed`.

For the CLI tool, see [`slopguard-cli`](https://crates.io/crates/slopguard-cli). For the full project, see the [main README](https://gitlab.com/ThomasTartrau/slopguard).

## Rule Structure

```text
rules/
  slop/           # AI-generated code patterns
  security/       # Security anti-patterns
  correctness/    # Error handling, type safety
```

## Accessing Embedded Rules

The crate exposes a single struct `BuiltinRules` that implements `rust_embed::Embed`:

```rust
use slopguard_rules::BuiltinRules;
use rust_embed::Embed;

// List all embedded rule files
for file in BuiltinRules::iter() {
    println!("{}", file); // e.g. "slop/no-trivial-doc.yml"
}

// Read a specific rule
if let Some(content) = BuiltinRules::get("correctness/no-unwrap-in-prod.yml") {
    let yaml = std::str::from_utf8(&content.data).unwrap();
    println!("{}", yaml);
}
```

In practice, you do not need to use this crate directly. `slopguard-core` handles rule loading through `load_builtin_rules()` and `load_effective_rules()`.

## Rule Format

Each YAML file follows the ast-grep rule format with slopguard extensions:

```yaml
id: no-unwrap-in-prod
language: rust
severity: error
category: correctness
message: ".unwrap() forbidden in production."
note: "unwrap() crashes the process on a single invalid input."
rule:
  pattern: $X.unwrap()
skip_test_code: true
tests:
  should_match:
    - "let x = foo().unwrap();"
  should_not_match:
    - "let x = foo()?;"
```

See [RULES.md](../RULES.md) for detailed documentation on all builtin rules.

## License

MIT - see [LICENSE](../LICENSE).
