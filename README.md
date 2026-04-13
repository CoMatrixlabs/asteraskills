# asteraskills

Open-source security intelligence tooling: LangChain **StructuredTools** (CVE, EPSS, CISA KEV, ATT&CK, CWE/CAPEC, exploits, compliance frameworks, OTX, and more), a **LangGraph** orchestrator for natural-language questions, and an optional **Risk Scanner** CLI for multi-domain artifact analysis (SBOM, code, IaC, logs, evidence).

Licensed under **Apache-2.0** (see `LICENSE`).

## Requirements

- Python 3.10+
- Optional: PostgreSQL and/or Qdrant (or Chroma) for semantic search and indexed intel; many API-based tools work with only network access and API keys.

## Install

```bash
git clone <your-fork-or-upstream-url>
cd asteraskills
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[runtime]"
```

Copy `.env.example` to `.env` and set at least the LLM and embedding keys your setup needs (see [docs/bring-your-own-llm.md](docs/bring-your-own-llm.md)).

## CLI

| Command | Purpose |
|--------|---------|
| `asteraskills doctor` | Verify imports and `TOOL_REGISTRY` load |
| `asteraskills list` | List registered tools and descriptions |
| `asteraskills run <tool> --args '<json>'` | Run one tool; JSON on stdout |
| `asteraskills agent run "<question>"` | LangGraph CVE/CWE/ATT&CK-style orchestration |
| `risk-scanner` | Scan artifacts (see `risk-scanner --help`) |

Example:

```bash
asteraskills run cve_details --args '{"cve_id":"CVE-2024-3400"}'
```

## Repository layout

| Path | Role |
|------|------|
| `app/asteraskills/` | Core package: `tools/`, `agents/`, `ingestion/`, `storage/`, `config/` |
| `risk_scanner/` | Standalone scanner CLI, analyzers, reporters (SARIF, JSON, Markdown, CSV, HTML) |
| `skills/` | Claude Agent Skill definitions (`SKILL.md` per skill) |
| `tests/` | Pytest |
| `docs/` | Architecture and LLM configuration |

## Documentation

- [Setup, usage, and data access](docs/setup-usage-and-access.md) — purpose, install tiers, CLI examples, phased rollout (direct DB for early adopters → hosted API with tokens and rate limits).
- [Architecture](docs/architecture.md) — how the tool registry, agents, storage, and Risk Scanner fit together.
- [Bring your own LLM](docs/bring-your-own-llm.md) — OpenAI vs Anthropic, models, embeddings, optional `config/llm_models.yaml`.
- [Enrichment chain](docs/enrichment-chain.md) — Risk Scanner enrichment pipeline (ATT&CK and controls).

## Claude Code / Agent Skills

Point your agent at the skill folders under `skills/` (for example `skills/astera-security-intel/`). Each skill’s `SKILL.md` describes prompts and when to use the bundled tools.

## Contributing

Issues and pull requests are welcome. Use `ruff` for style (`pip install -e ".[dev]"` then `ruff check app risk_scanner tests`).
