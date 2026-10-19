# VulnForge v0.2 — Foundation + provider adapters

**Implemented:** typed contracts, CLI diagnostics, OpenAI Chat Completions adapter, Anthropic Messages adapter, Ollama OpenAI-compatible adapter, offline mocked adapter tests.

**Not implemented:** real API integration tests, multi-turn tool result translation, agent loop, tool execution, target lab, oracle, benchmark, reports. Adapters currently accept text-only system/user/assistant messages; provider-native tool-result translation comes next.

## macOS installation

Requires Python 3.12+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
vulnforge doctor
python -m pytest -q
```

## Local inference

```bash
brew install ollama
ollama serve  # run in separate terminal if Ollama is not already serving
ollama pull qwen2.5-coder:7b
```

The Ollama adapter uses `http://127.0.0.1:11434/v1` and requires a running Ollama service. The adapter does not automatically execute tools; future policy-enforced agent code will own tool execution.

## Safety

Use only registered isolated targets. Do not connect the future test executor to external hosts. Keep credentials out of source control.

## Milestone 2.1 — bounded research loop

Added `ResearchAgent`, a strict registered `ToolGateway`, a simulated inspect tool, and provider-native multi-turn message translation. Run `python -m pytest -q` to verify. The simulated tool never makes network requests. The loop records token counts when available, but does not yet enforce wall-clock, token, or monetary budgets. **Do not connect it to arbitrary external tools or real targets yet.**
