---
name: astera-security-intel
description: Use when the user needs standalone Astera security intelligence—CVE enrichment, MITRE ATT&CK lookups, CWE/CAPEC/CIS tools, Postgres security_intel tables, exploit indices, OTX/VirusTotal/Tavily, semantic search over Chroma/Qdrant collections, and tactic/framework retrieval. Tools and storage code live in this repo under app/asteraskills (no complianceskill checkout required).
---

# Astera security intelligence (standalone)

Python implementation: vendored LangChain tools in `app/asteraskills/tools/` with storage in `app/asteraskills/storage/` and settings in `app/asteraskills/config/settings.py`. Configure the same Postgres, Chroma/Qdrant, and API keys you use for security_intel in production.

## Install

```bash
cd /path/to/Lexy/asteraskills
python -m venv .venv && source .venv/bin/activate
pip install -e ".[runtime]"
```

Optional: `ASTERASKILLS_ENV_FILE` points at an extra `.env` file. The repo root `.env` is loaded automatically when present.

## Verify

```bash
asteraskills doctor
asteraskills list
```

## Run a tool

```bash
asteraskills run cve_enrich --args '{"cve_id":"CVE-2024-3400"}'
asteraskills run semantic_attack_technique_search --args '{"query":"credential access","top_k":5}'
```

Use `asteraskills list` for exact registry keys and read each tool’s description for JSON argument fields.

## Skill prompts (copy into system or session)

Structured playbooks live next to this file:

- `prompts/cve_to_controls_session.md` — CVE → ATT&CK → controls pipeline ordering.
- `prompts/threat_intel_hunting.md` — IoC / CVE hunting with OTX, VT, Tavily, semantic DB tools.
- `prompts/exploit_exposure.md` — exploitability and remediation framing.

Load the relevant prompt when the user’s task matches; keep tool names aligned with `TOOL_REGISTRY` keys.

## Registry (39 keys — full parity with complianceskill `app.agents.tools`)

Includes API tools (`cve_intelligence` / `cve_details`, `epss_lookup`, `cisa_kev_check`, `github_advisory_search`, `cpe_lookup`), Postgres mappers (`cve_to_attack_mapper`, `attack_to_control_mapper` / `attack_control_map`, `cpe_resolver`), exploit tools, ATT&CK tools (`attack_technique_lookup`, `attack_tactic_contextualise`, `framework_item_retrieval`, `cve_enrich`, `cve_to_attack_map`), compliance (`framework_control_search`, `cis_benchmark_lookup`, `gap_analysis`), OTX/VT/Tavily, CWE/CAPEC/CIS + `threat_intel_data_*` DB/semantic tools, analysis stubs (`attack_path_builder`, `risk_calculator`, `remediation_prioritizer`), and `tavily_search`.

Note: `create_attack_enrichment_tool` still exists on `asteraskills.tools.attack_tools` but is not registered in `TOOL_REGISTRY` (same as upstream).

## Notes

- Semantic / embedding tools need `OPENAI_API_KEY` (or the configured embedding provider) at **runtime** when invoked; `doctor` only imports the package.
- YAML fallback for `framework_item_retrieval` uses `CVE_DATA_DIR` or `data/cvedata` next to the repo (see `ingestion/framework_yaml/framework_helper.py`).
- Bulk ATT&CK vector ingest from `attack_tools` uses `ingestion/attack_vector_ingest.py` (stub returns 0 unless you replace it with a full pipeline).

## Multi-agent (LangGraph)

For routed, multi-step tool use over the same registry, use the companion skill **`astera-intelligence-langgraph`** (`asteraskills agent run …`).

## References

- Agent Skills layout: [anthropics/skills](https://github.com/anthropics/skills)
