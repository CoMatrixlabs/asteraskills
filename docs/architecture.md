# asteraskills — Architecture

This repository has three main surfaces: **registered LangChain tools**, a **LangGraph agent CLI**, and the **Risk Scanner**. They share configuration (`get_settings()`), optional **Postgres** and **vector stores** (Qdrant or Chroma), and the **LLM factory** (`get_llm()`). See [bring-your-own-llm.md](bring-your-own-llm.md) for model configuration.

## Repository structure

```
asteraskills/
├── app/asteraskills/          # Installable package (setuptools: where = [".", "app"])
│   ├── bridge.py              # bootstrap(.env), load_tool_registry(), run_tool()
│   ├── cli.py                 # asteraskills Typer entrypoint
│   ├── config/settings.py     # Pydantic settings + .env
│   ├── core/llm.py            # get_llm() — OpenAI / Anthropic
│   ├── tools/                 # TOOL_REGISTRY + tool implementations
│   ├── agents/                # LangGraph orchestrator, specialists, prompts
│   ├── ingestion/             # ATT&CK, CWE/CAPEC, KEV, framework YAML, etc.
│   └── storage/               # Vector store helpers, SQLAlchemy session, KEV Postgres
├── risk_scanner/              # risk-scanner CLI package
├── skills/                    # Claude Agent Skill folders (SKILL.md)
├── tests/
└── docs/
```

## Tool registry and CLI

1. **`bridge.bootstrap(repo_root)`** loads `.env` from the repo root (and optional `ASTERASKILLS_ENV_FILE`).
2. **`asteraskills.tools.TOOL_REGISTRY`** maps string names to zero-arg callables that return a LangChain `StructuredTool`.
3. **`asteraskills list`** instantiates each tool for description; **`asteraskills run <name>`** calls `tool.invoke(args)`.

Tools are grouped by concern in `app/asteraskills/tools/` (API lookups, DB-backed intel, semantic search, analysis helpers, etc.). Database- and vector-backed tools no-op or error clearly when the corresponding env vars are unset.

## Agents (LangGraph)

`asteraskills agent run` uses the graph under `app/asteraskills/agents/`: orchestrator routes questions to specialist subgraphs and uses subsets of the same tool surface. Prompts live under `agents/prompts/`.

## Storage and ingestion

- **Vector**: `VECTOR_STORE_TYPE` selects Qdrant or Chroma; collection names for ATT&CK, control mappings, CWE/CAPEC→ATT&CK, and CISA KEV are on `Settings`.
- **Postgres**: CVE/ATT&CK and related intel can be read via DSN fields (`POSTGRES_*` or `SEC_INTEL_*` overrides). Ingestion scripts under `ingestion/` populate or refresh indices; KEV can also be indexed to Qdrant or a `cisa_kev` table.

## Risk Scanner

The Risk Scanner is a separate package in `risk_scanner/` with its own Typer app (`risk-scanner`). It loads artifacts, classifies domain (CVE, CWE, policy, ATT&CK, framework), runs static/behavioral analyzers, enriches findings (often delegating to asteraskills tools in **local** mode), and emits SARIF, JSON, Markdown, CSV, or HTML.

### High-level flow

```
Artifact
  → ArtifactLoader (type detection, unpack)
  → DomainClassifier
  → StaticAnalyzer / BehavioralAnalyzer → Finding[]
  → EnrichmentAnalyzer (ATT&CK, controls, severity context)
  → MetaAnalyzer (dedup, false-positive filter)
  → ScanResult → Reporter
```

### Pack client modes

- **Local (open source)**: enrichment uses asteraskills tools and local indices where configured.
- **Licensed mode** (optional): `pack_client` can call a remote intelligence API for rules and enrichment; same analyzer shape.

### Analyzer pipeline detail

See [enrichment-chain.md](enrichment-chain.md) for the two-hop enrichment (domain → ATT&CK → framework controls) and per-domain flows.

## Risk Scanner domains

| Domain | Typical input | Detection | Enrichment |
|--------|---------------|-----------|------------|
| CVE | SBOM (CycloneDX/SPDX) | Version vs NVD | CVE → ATT&CK → controls |
| CWE | Source (Python/JS/Go/Bash, etc.) | Static/taint-style signals | CWE → ATT&CK → controls |
| POLICY | IaC (Terraform/K8s/CFN, etc.) | Policy checks | Policy → ATT&CK → controls |
| ATTACK | SIEM / alerts | IoC and sequence hints | Controls mapping |
| FRAMEWORK | Evidence (PDF/CSV/XLSX) | Evidence classification | Framework satisfaction (no ATT&CK hop) |

## Reuse from asteraskills (local mode)

| Risk Scanner need | asteraskills side |
|-------------------|-------------------|
| CVE enrichment | CVE / intel tools |
| CVE → ATT&CK | CVE–ATT&CK mappers, pipelines |
| ATT&CK → controls | Attack–control mapping tool |
| Tactic context | Tactic contextualiser |
| CWE → ATT&CK | CWE→ATT&CK intel tool |
| Framework items | Framework item retrieval |
| LLM | `get_llm()` |
| Config | `get_settings()` |

## Configuration

Single source of truth: **`Settings`** in `app/asteraskills/config/settings.py`, populated from environment variables and optional `.env` at repo root. Paths such as `BASE_DIR` and `CONFIG_DIR` resolve to the repository root so tools behave the same from CLI, tests, and agent runtimes.
