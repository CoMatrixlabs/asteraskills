# Capability 3 (revised) — Related CVEs via Agent Skills Intent Routing

**Replaces:** the direct SQL fan-out model in the original design doc section 4  
**Key change:** Related CVE discovery is now agent-skill-driven. The lookup surface accepts
natural language or structured intent (software name, T-code, tactic label, kill chain phase,
or an SBOM) and routes through an intent classifier rather than a fixed SQL traversal.

---

## 3.1 Core concept

The original design traversed `cve_attack_mappings` directly: fetch techniques for a source CVE,
fan out to sibling CVEs sharing those techniques, score, return. That model is deterministic but
brittle — it only works when you already have a CVE ID and pre-computed mappings.

The agent-skills model inverts this. The caller expresses _what they are looking for_ in whichever
vocabulary they have available:

| Input type | Example | How it resolves |
|---|---|---|
| Software / package | "openssl 3.0.7", `pkg:pypi/cryptography@41.0.3` | CPE normalize → `cve_cpe_links` → CVE list |
| ATT&CK technique | "T1190", "Exploit Public-Facing Application" | `cve_attack_mappings WHERE technique_id = ?` |
| ATT&CK tactic | "Initial Access", "TA0001" | tactic → all T-codes in tactic → `cve_attack_mappings` |
| Kill chain phase | "Delivery", "Exploitation" | phase → tactic cluster map → T-codes → CVEs |
| SBOM | CycloneDX / SPDX file | parse components → `sbom_cve_context` per component → expand |

All paths converge at a single rank-and-dedup stage before emitting results.

---

## 3.2 Intent classifier

**Module:** `app/agents/skills/cve_query_router.py`

The classifier receives a free-text string (from an LLM agent query) or a structured dict
(from a direct tool call) and returns a `QueryIntent`:

```python
class QueryIntent(BaseModel):
    intent_type: Literal["software", "technique", "tactic", "kill_chain", "sbom"]
    resolved_terms: List[str]       # T-codes, CPE URIs, tactic IDs — whatever was extracted
    raw_input: str
    confidence: float               # 0.0–1.0

def classify_cve_query(query: str) -> QueryIntent:
    """
    Rule-based first, LLM fallback.

    Rules (checked in order):
    1. SBOM marker: query is a file path or contains "sbom", "CycloneDX", "SPDX"
    2. T-code pattern: matches r'T\d{4}(\.\d{3})?' → intent_type="technique"
    3. TA-code pattern: matches r'TA\d{4}' → intent_type="tactic"
    4. Tactic label: fuzzy match against known tactic names from attack_techniques collection
    5. Kill chain phase: string match against Lockheed / Unified Kill Chain phase list
    6. Fallback: embed query → cosine search attack_techniques (Qdrant) → classify by top hit
       - top hit is a technique → intent_type="technique"
       - top hit is a tactic → intent_type="tactic"
    7. If cosine score < 0.7 on all ATT&CK hits → intent_type="software" (product lookup)
    """
```

The classifier has no LLM call in the happy path (rules 1–5 cover ~90% of structured queries).
LLM only fires when the query is fully ambiguous prose.

---

## 3.3 Dispatch paths

### Path 1 — Software / package

```
classify → intent_type="software"
         → extract: product_name, version (from purl, semver pattern, or LLM parse)
         → sbom_cve_context(component_name=product_name, version=version)
         → returns CVESourceRecord[] with cpe_uri, version_in_range, technique_ids
```

This reuses `sbom_cve_context` (Capability 2) directly. A software query is just a single-component
SBOM query without the file parsing step.

### Path 2 — ATT&CK technique

```
classify → intent_type="technique", resolved_terms=["T1190", "T1210"]
         → for each T-code:
             SELECT cve_id, cvss_score, epss_score, exploit_maturity
             FROM cve_intelligence ci
             JOIN cve_attack_mappings cam ON ci.cve_id = cam.cve_id
             WHERE cam.technique_id = :t_code
             ORDER BY epss_score DESC, cvss_score DESC
             LIMIT 50
         → union, deduplicate on cve_id
```

No Qdrant call needed. Pure Postgres join. Fastest path.

### Path 3 — ATT&CK tactic

```
classify → intent_type="tactic", resolved_terms=["TA0001"]
         → resolve tactic to technique IDs:
             SELECT DISTINCT technique_id
             FROM attack_techniques_index         -- populated by ATT&CK ingestion
             WHERE tactic_id = :tactic_id
               OR tactic_name ILIKE :tactic_name  -- "Initial Access"
         → same join as Path 2, but WHERE technique_id = ANY(:technique_ids)
```

If `attack_techniques_index` is not populated, fall back to a Qdrant semantic search on the
`attack_techniques` collection filtered by `tactic` payload field.

### Path 4 — Kill chain phase

Kill chain phases (Lockheed Martin, Unified Kill Chain) map to MITRE ATT&CK tactic clusters.
This mapping is static and stored in a small lookup table:

```python
KILL_CHAIN_TO_TACTIC_MAP = {
    # Lockheed Martin
    "reconnaissance":    ["TA0043"],
    "weaponization":     ["TA0001", "TA0002"],
    "delivery":          ["TA0001"],
    "exploitation":      ["TA0002", "TA0004"],
    "installation":      ["TA0003", "TA0005"],
    "command_control":   ["TA0011"],
    "actions_on_object": ["TA0007", "TA0008", "TA0009", "TA0010"],
    # Unified Kill Chain phases map similarly...
}
```

```
classify → intent_type="kill_chain", resolved_terms=["exploitation"]
         → KILL_CHAIN_TO_TACTIC_MAP["exploitation"] = ["TA0002", "TA0004"]
         → resolve each tactic to T-codes (same as Path 3)
         → join cve_attack_mappings
```

---

## 3.4 Rank and deduplicate stage

All four paths emit `List[RawCVEHit]`. The consolidation step:

```python
class RawCVEHit(BaseModel):
    cve_id: str
    cvss_score: float
    epss_score: float
    exploit_maturity: str
    matched_technique_ids: List[str]
    matched_tactic_ids: List[str]
    source_path: str                  # "software" | "technique" | "tactic" | "kill_chain"
    description: str

def rank_and_dedup(hits: List[RawCVEHit], max_results: int = 20) -> List[RankedCVEResult]:
    """
    1. Deduplicate: group by cve_id, merge matched_technique_ids across paths
    2. Score:
         base_score    = normalise(cvss_score, 0, 10) × 0.35
         epss_weight   = epss_score × 0.35           # already 0–1
         exploit_bonus = {"none": 0.0, "poc": 0.1, "weaponised": 0.3}[exploit_maturity]
         technique_cov = len(matched_techniques) / total_query_techniques × 0.20
         composite     = base_score + epss_weight + exploit_bonus + technique_cov
    3. Sort by composite DESC, return top max_results
    """
```

No Qdrant call in the rank stage — description similarity is omitted in this model (the agent
skill's intent classification already handles semantic matching at query time via the Qdrant
`attack_techniques` collection search in the classifier fallback path).

---

## 3.5 SBOM enrichment with related CVE expansion

When the input is an SBOM, the flow adds two steps after the standard `sbom_cve_context` per-component
pass:

**Step: ATT&CK enrich per CVE**

For each `CVESourceRecord` returned by `sbom_cve_context`, hydrate ATT&CK mappings:

```python
def enrich_cve_with_attack(cve_records: List[CVESourceRecord]) -> List[CVESourceRecord]:
    cve_ids = [r.cve_id for r in cve_records if not r.technique_ids]
    if not cve_ids:
        return cve_records    # already hydrated
    # Batch fetch from cve_attack_mappings
    rows = session.execute(
        text("SELECT cve_id, technique_id, tactic FROM cve_attack_mappings WHERE cve_id = ANY(:ids)"),
        {"ids": cve_ids}
    ).fetchall()
    mapping = defaultdict(list)
    for row in rows:
        mapping[row[0]].append({"technique_id": row[1], "tactic": row[2]})
    for record in cve_records:
        if record.cve_id in mapping:
            record.technique_ids = [m["technique_id"] for m in mapping[record.cve_id]]
    return cve_records
```

**Step: Related CVE expansion per component**

After hydration, for each component's CVE list, collect the union of technique IDs and dispatch
through Path 2 (technique lookup) to find sibling CVEs not already in the component's list:

```python
def expand_related_cves_for_component(
    component: str,
    cve_records: List[CVESourceRecord],
    max_related: int = 10,
) -> List[RankedCVEResult]:
    known_cve_ids = {r.cve_id for r in cve_records}
    technique_ids = list({t for r in cve_records for t in r.technique_ids})
    if not technique_ids:
        return []
    hits = _lookup_by_technique_ids(technique_ids)          # Path 2
    hits = [h for h in hits if h.cve_id not in known_cve_ids]  # exclude already found
    return rank_and_dedup(hits, max_results=max_related)
```

The result is attached to the SBOM report under each component's section:

```json
{
  "source_map": {
    "openssl@3.0.7": {
      "cpe_uri": "cpe:2.3:a:openssl:openssl:3.0.7:*",
      "direct_cves": ["CVE-2023-0286", "CVE-2023-0215"],
      "related_cves": [
        {"cve_id": "CVE-2022-0778", "shared_techniques": ["T1190"], "composite_score": 0.82},
        {"cve_id": "CVE-2021-3711", "shared_techniques": ["T1190", "T1210"], "composite_score": 0.79}
      ],
      "max_cvss": 7.4,
      "technique_surface": ["T1190", "T1210"]
    }
  }
}
```

---

## 3.6 New module structure

```
app/
  agents/
    skills/
      cve_query_router.py          ← intent classifier (new)
      kill_chain_tactic_map.py     ← static kill-chain→tactic mapping (new)
    tools/
      related_cves_skill.py        ← StructuredTool wrapping all 4 dispatch paths (new)
      sbom_cve_context.py          ← existing Capability 2, extended with ATT&CK hydration
```

`related_cves_skill.py` exposes a single tool named `related_cves` with:

```python
class RelatedCVEsInput(BaseModel):
    query: str = Field(description=(
        "Natural language or structured query. Examples: "
        "'CVEs for openssl 3.0.7', "
        "'CVEs exploiting T1190', "
        "'CVEs in Initial Access tactic', "
        "'CVEs in Delivery kill chain phase', "
        "'pkg:npm/lodash@4.17.21'"
    ))
    max_results: int = Field(default=20)
    min_cvss: float = Field(default=0.0)
```

The agent calls this one tool for all related-CVE queries; the classifier handles routing internally.

---

## 3.7 CLI additions

```bash
# Software / package query
asteraskills run related_cves --args '{"query":"openssl 3.0.7","max_results":10}'

# ATT&CK technique query
asteraskills run related_cves --args '{"query":"T1190","min_cvss":7.0}'

# Tactic query
asteraskills run related_cves --args '{"query":"Initial Access","max_results":20}'

# Kill chain phase
asteraskills run related_cves --args '{"query":"Exploitation kill chain phase"}'

# SBOM with related CVE expansion
risk-scanner scan run /path/to/sbom.json --related-cves --max-related 10
```

---

## 3.8 What changed from the original design

| Aspect | Original (SQL fan-out) | Revised (agent skills) |
|---|---|---|
| Entry point | CVE ID only | software · T-code · tactic · kill chain · SBOM |
| Routing | Hardcoded SQL fan-out | Intent classifier → 4 dispatch paths |
| ATT&CK lookup | SQL traversal of cve_attack_mappings | Same, but dispatched by intent type |
| Description similarity | Qdrant cve_vectors cosine in rank stage | Qdrant attack_techniques in classifier (query time) |
| Scoring | overlap + CVSS + cosine | CVSS + EPSS + exploit maturity + technique coverage |
| cve_vectors collection | Required for full scoring | Not required (scoring moved to query-time classification) |
| SBOM path | Separate from related-CVE | Integrated: sbom_cve_context → ATT&CK hydrate → expand |
| Tool surface | `related_cves_attack(cve_id=...)` | `related_cves(query=...)` — single polymorphic tool |
