# Setup, usage, and data access

This document describes **why** asteraskills exists, **how** to stand it up at different levels, **concrete usage examples**, and how **data access** is expected to evolve. It is documentation only; the repository today still connects to PostgreSQL, Qdrant/Chroma, and public APIs where configured.

---

## Purpose

**asteraskills** is meant to help security engineers and agents answer questions and run workflows that combine:

- **Vulnerability and exposure context** (CVE details, EPSS, CISA KEV, GitHub advisories, NVD-oriented flows).
- **Threat modeling glue** (ATT&CK techniques, mappings to controls, tactic context).
- **Weakness and pattern intel** (CWE, CAPEC, CIS-style control lookups where data is available).
- **Optional deep analysis** via the **Risk Scanner**: classify an artifact (SBOM, code, IaC, logs, evidence), enrich findings, and export SARIF, JSON, Markdown, CSV, or HTML.

You bring your own **LLM** (see [bring-your-own-llm.md](bring-your-own-llm.md)). The project does not ship proprietary intelligence data; it ships **tools and pipelines** that work against **your** databases, vector indices, and API keys—or against **services you operate** that will eventually front those stores.

---

## Setup overview

### 1. Base install (required)

- Python 3.10+
- Clone the repo, create a virtualenv, install: `pip install -e ".[runtime]"`
- `PYTHONPATH` must include `app` when running modules (the editable install handles this for console scripts).
- Copy `.env.example` to `.env` and set **LLM** (and **embedding** keys if you run ingestion or semantic search).

Verify:

```bash
asteraskills doctor
```

### 2. “API-only” mode (no org databases)

Many tools call **public or third-party HTTP APIs** (NVD, GitHub advisories, OTX, etc.) when you set the right keys in `.env`. You still need network egress and valid API keys where the tool requires them.

Typical variables (see `app/asteraskills/config/settings.py` for the full list):

- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` and `LLM_PROVIDER`, `LLM_MODEL` for LLM-backed steps.
- `NVD_API_KEY` (optional but recommended for NVD rate limits).
- `TAVILY_API_KEY` if you use the Tavily search tool.

This tier is enough to try **single-tool** runs and some **agent** flows that do not depend on local Postgres/Qdrant.

### 3. Full intel tier (direct database and vector store)

For **semantic search** over ATT&CK, control mappings, CWE/CAPEC→ATT&CK, CISA KEV in Qdrant, etc., you need:

- **Qdrant** (or Chroma) reachable from the machine running asteraskills, with collection names matching `Settings` (e.g. `QDRANT_HOST`, `QDRANT_PORT`, `ATTACK_TECHNIQUES_COLLECTION`, …).
- **PostgreSQL** for relational intel (CVE/ATT&CK tables, CPE, exploits, compliance slices—depending on what you ingested), via `POSTGRES_*` or the `SEC_INTEL_*` overrides documented in settings.

Ingestion jobs under `app/asteraskills/ingestion/` populate those stores; operators run them on a schedule or ad hoc in the environment that **hosts** the data.

**Early adopter phase:** your team may grant **direct network access** from approved workstations or runners to these Postgres and Qdrant endpoints (VPN, private subnet, firewall rules). That matches “get it working first” before any HTTP API wrapper exists.

---

## Usage examples

Replace JSON payloads with real IDs from your environment.

### List available tools

```bash
asteraskills list
```

### Run one tool (CVE details)

```bash
asteraskills run cve_details --args '{"cve_id":"CVE-2024-3400"}'
```

### EPSS lookup

```bash
asteraskills run epss_lookup --args '{"cve_id":"CVE-2023-44487"}'
```

### CISA KEV check (API-oriented path; behavior depends on configuration)

```bash
asteraskills run cisa_kev_check --args '{"cve_id":"CVE-2024-3400"}'
```

### Natural-language orchestration (LangGraph agent)

```bash
asteraskills agent run "Summarize CVE-2024-3400 and map it to ATT&CK if applicable"
```

### Risk Scanner (artifact on disk)

```bash
risk-scanner scan run /path/to/sbom.json --format sarif --output results.sarif
```

`--format` accepts `markdown`, `sarif`, `json`, `csv`, or `html`. Use `risk-scanner --help` and `risk-scanner scan run --help` for domains, severity thresholds, enrichment flags, and optional intelligence-server token (`--token` / `RISK_SCANNER_LICENSE_TOKEN`).

### Claude Agent Skills

Copy or symlink the relevant folder under `skills/` into your agent’s skill path (for example `skills/astera-security-intel/`). The skill’s `SKILL.md` describes when to invoke which tools and how to phrase tasks.

---

## Data access model (current vs planned)

### Phase A — Direct access (early adopters)

- **Who:** A small set of engineers or internal runners with **direct connectivity** to the **data plane** (PostgreSQL, Qdrant/Chroma) and standard secrets (DB credentials, API keys) in `.env` or your secret store.
- **Goal:** Validate ingestion, tool behavior, Risk Scanner outputs, and agent skills end-to-end without an intermediate API.
- **Operational note:** Restrict by network policy, least-privilege DB roles, and rotated credentials; this phase is **not** intended as the long-term exposure surface for the whole org.

### Phase B — Hosted data services (planned)

- **You** host the databases and vector indices in your environment (same as today, but not exposed broadly).
- **Consumers** (asteraskills, agents, other services) talk to **your HTTP API** instead of opening firewall rules to Postgres/Qdrant for every client.
- **Planned API characteristics** (to be implemented on your side):
  - **Authentication:** API tokens (or similar) per client or workload.
  - **Rate limiting:** Per token or per tenant to protect shared backends.
  - **Stable contracts:** Versioned routes that mirror what tools need (classify, retrieve rules, enrich, semantic search equivalents), so the open-source client can be pointed at a base URL and token rather than raw DSNs.

Until that API exists, the open-source tree continues to assume **direct** configuration via `Settings` / environment variables for database and vector hosts. Migrating callers from Phase A to Phase B will be a **configuration and adapter** change on your fork or upstream contributions later—not something this document implements today.

---

## Quick reference

| Need | Start here |
|------|------------|
| LLM and embedding env vars | [bring-your-own-llm.md](bring-your-own-llm.md) |
| Repo and scanner structure | [architecture.md](architecture.md) |
| Risk Scanner enrichment | [enrichment-chain.md](enrichment-chain.md) |
| Prompt IDs and variables | [prompts.md](prompts.md) |
