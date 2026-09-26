# slopguard-ai

AI analysis pipeline for [slopguard](https://gitlab.com/ThomasTartrau/slopguard).

This crate provides the infrastructure for AI-backed rules:

- **Provider selection** (`provider`): build an `AgentProvider` from `[ai]`
  config. Two transports: `api` (HTTP, via `ironflow-core` `AnthropicApiProvider`
  / `OpenAiProvider`) and `cli` (local `claude` via `ClaudeCodeProvider`).
- **Pipeline** (`pipeline`): AST pre-filter matches become candidates, context
  is extracted (25 lines on each side of the match), a prompt template is
  rendered and sent to the LLM with structured output, and only confirmed
  matches become findings.
- **Classifier** (`pipeline::classifier`, feature `provider-typesafe`): an
  optional System One classifier (Jev, through `ironflow-core`
  `TypeSafeProvider`) that replaces the LLM confirmation when
  `[ai.classifier].enabled`. Each candidate gets a probability compared to a
  threshold; candidates with overlapping context are batched into one request.
  Rules with `ai_check.reason: generated` still call the LLM to write a
  per-instance reason.
- **Cache** (`cache`): LLM verdicts and classifier probabilities are cached
  per candidate under `<cache-dir>/ai/`. The classifier threshold is applied
  after the cache, so changing it never invalidates entries.

The AST layer (`slopguard-core`) never depends on this crate: orchestration
(AST phase then AI phase) happens in `slopguard-cli`.
