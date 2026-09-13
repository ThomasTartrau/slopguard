# slopguard-ai

AI analysis pipeline for [slopguard](https://gitlab.com/ThomasTartrau/slopguard).

This crate provides the infrastructure for AI-backed rules:

- **Provider selection** (`provider`): build an `AgentProvider` from `[ai]`
  config. Two transports: `api` (HTTP, via `ironflow-core` `AnthropicApiProvider`
  / `OpenAiProvider`) and `cli` (local `claude` via `ClaudeCodeProvider`).
- **Pipeline** (`pipeline`): AST pre-filter matches become candidates, context
  is extracted (~50 lines around each match), a prompt template is rendered and
  sent to the LLM with structured output, and only confirmed matches become
  findings.
- **Cache** (`cache`): AI verdicts are cached by
  `sha256(file_content + resolved_prompt + model)` under `<cache-dir>/ai/`.

The AST layer (`slopguard-core`) never depends on this crate: orchestration
(AST phase then AI phase) happens in `slopguard-cli`.
