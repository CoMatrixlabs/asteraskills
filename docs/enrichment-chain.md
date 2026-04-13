# Enrichment Chain

Every finding goes through a two-hop enrichment chain:

```
Finding (domain + taxonomy_code + evidence)
    │
    ▼ Hop 1: Domain → ATT&CK
    │
    ├── CVE Finding  → PROMPT-07 (CVE→ATT&CK) → AttackEnrichment[]
    ├── CWE Finding  → PROMPT-08 (CWE→ATT&CK) → AttackEnrichment[]
    ├── POLICY Finding → PROMPT-09 (Policy→ATT&CK) → AttackEnrichment[]
    └── ATTACK Finding → [identity — already a TTP]
    │
    ▼ Hop 2: ATT&CK → Controls
    │
    └── AttackEnrichment[] → PROMPT-10 (ATT&CK→controls) → ControlEnrichment[]
    │
    ▼ Final: Severity Contextualization
    │
    └── PROMPT-11 → final_severity (may upgrade/downgrade) + risk_score
```

## CVE Flow (section 5.1)

```
ingest_sbom
  → parse_components (CycloneDX/SPDX)
  → version_range_check (NVD, server-fetched or asteraskills)
  → reachability_check (transitive dep graph, optional)
  → PROMPT-02 (CVE Detect) → Finding(domain=CVE)
  → PROMPT-07 (CVE→ATT&CK) → AttackEnrichment[]
  → PROMPT-10 (ATT&CK→controls) → ControlEnrichment[]
  → PROMPT-11 (Severity Contextualization) → final_severity
  → emit_finding
```

## CWE Flow (section 5.2)

```
ingest_source
  → ast_parse (Python/JS/Go/Bash)
  → build_cfg
  → forward_dataflow (source → sink taint)
  → cross_file_correlation
  → PROMPT-03 (CWE Detect) → Finding(domain=CWE)
  → PROMPT-08 (CWE→ATT&CK) → AttackEnrichment[]
  → PROMPT-10 (ATT&CK→controls) → ControlEnrichment[]
  → PROMPT-11 → final_severity
  → emit_finding
```

## Policy / Misconfiguration Flow (section 5.3)

```
ingest_config (Terraform/CloudFormation/k8s/JSON)
  → parse_resources
  → baseline_diff (server-fetched baseline)
  → rule_assertion_check (per-resource YAML rules)
  → PROMPT-04 (Policy Detect) → Finding(domain=POLICY)
  → PROMPT-09 (Policy→ATT&CK) → AttackEnrichment[]
  → PROMPT-10 (ATT&CK→controls) → ControlEnrichment[]
  → PROMPT-11 → final_severity
  → emit_finding
```

## ATT&CK Flow (section 5.4)

```
ingest_logs/alerts (SIEM/CEF/JSON)
  → ioc_match (hashes, IPs, domains, command-line)
  → sequence_correlate (temporal kill chain window)
  → PROMPT-05 (ATT&CK Detect) → Finding(domain=ATTACK)
  → [skip enrich_attack — already a TTP]
  → PROMPT-10 (ATT&CK→controls) → ControlEnrichment[]
  → emit_finding
```

## Framework Flow (section 5.5)

```
ingest_evidence (PDF/CSV/XLSX/config exports)
  → evidence_classify (which control does this attest?)
  → coverage_model (satisfied | partial | missing per control)
  → PROMPT-06 (Framework Detect) → Finding(domain=FRAMEWORK)
  → [direct to controls — no ATT&CK hop]
  → emit_finding
```

## Severity Upgrade/Downgrade Rules (PROMPT-11)

| Condition | Effect |
|-----------|--------|
| Exfiltration/impact technique enabled + missing preventive control | Upgrade to CRITICAL |
| All enabled techniques have satisfied preventive controls | Downgrade by one tier |
| No change conditions met | Unchanged |

## Risk Score Breakdown

```
risk_score (0–100) = base_severity_score (0–40)
                   + attack_chain_score (0–30)
                   + control_gap_score (0–30)
```
