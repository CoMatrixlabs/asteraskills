---
name: astera-intelligence-langgraph
description: Use when the user wants an agentic workflow over Astera security tools—questions are routed automatically to a CVE specialist, CWE/CAPEC specialist, MITRE ATT&CK specialist, or general threat-intel agent (LangGraph ReAct subgraphs with domain-scoped tools). Prefer this over picking individual tools when the task is conversational or multi-step.
---

# Astera intelligence LangGraph orchestrator

One parent graph routes each turn to **cve_agent**, **cwe_agent**, **attack_agent**, or **general_agent**. Each agent is a **LangGraph `create_react_agent`** bound to a subset of `TOOL_REGISTRY` tools (see `app/asteraskills/agents/tool_sets.py`).

## When to use

- Open-ended questions (“What’s the risk of CVE-…?”, “Map CWE-79 to ATT&CK”, “Explain T1059 under execution”).
- When you would otherwise chain several CLI `asteraskills run …` calls manually.

## CLI

```bash
# Classify only (no tools)
asteraskills agent route "What does T1190 mean under initial access?"

# Full run (router + specialist ReAct loop; requires LLM + API keys as needed)
asteraskills agent run "Summarize CVE-2024-3400 and likely ATT&CK techniques" --show-domain

# Multi-turn session (same thread_id appends to checkpointed history; handoff across specialists)
export ASTERASKILLS_THREAD_ID=my-session
asteraskills agent run "Tell me about CVE-2024-3400" -t my-session
asteraskills agent run "Now map that vulnerability to MITRE ATT&CK techniques" -t my-session --show-domain
```

The parent graph uses an in-process ``MemorySaver`` checkpointer. For production, swap in a persistent saver (e.g. Postgres) when building the graph in code.

## Requirements

- `pip install -e ".[runtime]"` (includes **langgraph**).
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` per `LLM_PROVIDER` in settings (router + specialists).
- Optional: Postgres / Chroma / OTX / Tavily keys for tools the agent may call.

## Implementation pointers

- Orchestrator: `app/asteraskills/agents/orchestrator.py` (`IntelOrchestratorState`: `messages`, `domain`, `last_specialist`)
- Router + specialist system prompts: `app/asteraskills/agents/prompts/*.md` (loaded by `agents/prompts/__init__.py`)
- Tool groupings: `app/asteraskills/agents/tool_sets.py`
- Public API: `from asteraskills.agents import get_intel_orchestrator, run_intel_turn, invoke_config`
- Pass `config=invoke_config(thread_id)` to `invoke` / use `run_intel_turn(..., thread_id=...)` for checkpointed memory.

## Relation to single-tool skill

Use **`astera-security-intel`** when the user names an exact tool and JSON args. Use **this skill** when the user asks in natural language and should have routing + multi-step tool use.
