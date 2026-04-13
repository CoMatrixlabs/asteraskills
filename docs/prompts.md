# Risk Scanner — Prompts Reference

All 16 LLM prompts used by the risk scanner pipeline. Each prompt is stored as a constant in `risk_scanner/core/prompts.py` and invoked via `format_prompt(prompt_id, **variables)`.

---

## Detection Prompts (PROMPT-01 through PROMPT-06)

### PROMPT-01 — Domain Classifier

**Usage:** `DomainClassifier.classify()` when heuristics are insufficient.

**Input variables:** `artifact_text`, `file_extension`, `retrieved_signals`

**Purpose:** Determines which scan domain (CVE / CWE / POLICY / ATTACK / FRAMEWORK) applies to an artifact. Uses retrieved signals from the pack client as additional context.

**Output:** JSON with `domain` (one of: cve, cwe, policy, attack, framework) and `confidence` (0.0–1.0).

---

### PROMPT-02 — CVE Detect

**Usage:** `StaticAnalyzer` after NVD version range check returns candidate findings.

**Input variables:** `component_name`, `component_version`, `cve_id`, `cvss_score`, `description`, `affected_ranges`

**Purpose:** Confirms whether the component version is genuinely in the affected range and assigns initial severity and a natural-language summary.

**Output:** JSON with `confirmed` (bool), `severity`, `summary`, `remediation`.

---

### PROMPT-03 — CWE Detect

**Usage:** `BehavioralAnalyzer` after AST taint analysis identifies source-sink flows.

**Input variables:** `file_path`, `language`, `source_node`, `sink_node`, `taint_path`, `cwe_id`, `cwe_description`

**Purpose:** Validates the taint flow, confirms the CWE classification, and writes a developer-readable summary explaining the weakness and its exploitability.

**Output:** JSON with `confirmed` (bool), `confidence`, `summary`, `remediation`.

---

### PROMPT-04 — Policy / Misconfiguration Detect

**Usage:** `StaticAnalyzer` after rule assertion check fails for an IaC resource.

**Input variables:** `resource_type`, `resource_name`, `rule_id`, `rule_description`, `actual_value`, `expected_value`, `file_path`, `line`

**Purpose:** Confirms the misconfiguration, contextualizes the risk (e.g., "this S3 bucket is publicly readable"), and produces remediation guidance with corrected HCL/YAML.

**Output:** JSON with `confirmed` (bool), `severity`, `summary`, `remediation`, `code_fix`.

---

### PROMPT-05 — ATT&CK Detect

**Usage:** `BehavioralAnalyzer` sequence correlator after matching IoC signatures in SIEM logs.

**Input variables:** `log_entries`, `matched_iocs`, `technique_id`, `technique_name`, `tactic`, `sequence_window_seconds`

**Purpose:** Validates that the matched log sequence constitutes a genuine ATT&CK technique occurrence rather than a false positive, and assesses confidence based on temporal proximity and context.

**Output:** JSON with `confirmed` (bool), `confidence`, `summary`, `kill_chain_position`.

---

### PROMPT-06 — Framework Detect

**Usage:** `StaticAnalyzer` evidence classification for compliance artifact inputs (PDF/CSV/XLSX).

**Input variables:** `evidence_text`, `control_framework`, `control_id`, `control_description`

**Purpose:** Determines whether the evidence satisfies, partially satisfies, or fails to satisfy the compliance control. Used in Framework domain scans.

**Output:** JSON with `satisfaction` (satisfied | partial | missing), `rationale`, `gap_description`.

---

## Enrichment Prompts (PROMPT-07 through PROMPT-11)

### PROMPT-07 — CVE → ATT&CK Enrichment

**Usage:** `EnrichmentAnalyzer.enrich_cve_finding()` — Hop 1 for CVE domain.

**Input variables:** `cve_id`, `cwe_ids`, `cvss_vector`, `description`, `retrieved_mappings`

**Purpose:** Maps a CVE to relevant ATT&CK techniques using the retrieved mappings as RAG context. The retrieved_mappings come from `pack_client.retrieve_attack_mappings()` which delegates to `_execute_cve_to_attack_map` in local mode.

**Output:** JSON array of `AttackEnrichment` objects: `[{"technique_id": "T1190", "technique_name": "...", "tactic": "initial-access", "confidence": 0.9, "rationale": "..."}]`

---

### PROMPT-08 — CWE → ATT&CK Enrichment

**Usage:** `EnrichmentAnalyzer.enrich_cwe_finding()` — Hop 1 for CWE domain.

**Input variables:** `cwe_id`, `cwe_name`, `taint_description`, `sink_type`, `retrieved_mappings`

**Purpose:** Maps a CWE weakness (e.g., CWE-89 SQL Injection) to ATT&CK techniques that the weakness enables (e.g., T1190 Exploit Public-Facing Application). Uses CAPEC crosswalk data in retrieved_mappings.

**Output:** Same format as PROMPT-07.

---

### PROMPT-09 — Policy → ATT&CK Enrichment

**Usage:** `EnrichmentAnalyzer.enrich_policy_finding()` — Hop 1 for POLICY domain.

**Input variables:** `rule_id`, `rule_description`, `resource_type`, `misconfiguration_summary`, `retrieved_mappings`

**Purpose:** Maps an IaC misconfiguration (e.g., public S3 bucket) to ATT&CK techniques it enables (e.g., T1530 Data from Cloud Storage). Hardcoded high-confidence mappings are used for well-known rules; LLM fills gaps.

**Output:** Same format as PROMPT-07.

---

### PROMPT-10 — ATT&CK → Framework Control Enrichment

**Usage:** `EnrichmentAnalyzer.enrich_controls()` — Hop 2 for all domains.

**Input variables:** `technique_ids`, `technique_names`, `tactics`, `frameworks`, `retrieved_controls`

**Purpose:** For each ATT&CK technique, retrieves the relevant framework controls (CIS v8.1, NIST 800-53, SOC2, ISO 27001) that mitigate or detect it. The retrieved_controls come from `pack_client.retrieve_control_mappings()` which delegates to `_execute_attack_control_map` in local mode.

**Output:** JSON array of `ControlEnrichment` objects: `[{"framework": "nist-800-53", "control_id": "SI-2", "control_name": "Flaw Remediation", "satisfaction": "missing", "rationale": "..."}]`

---

### PROMPT-11 — Severity Contextualization

**Usage:** `EnrichmentAnalyzer` final step after both enrichment hops.

**Input variables:** `finding_domain`, `taxonomy_code`, `initial_severity`, `attack_chain`, `control_gaps`, `evidence_summary`

**Purpose:** Upgrades or downgrades severity based on the enrichment context:
- **Upgrade to CRITICAL** if an exfiltration or impact technique is enabled AND the corresponding preventive control is missing.
- **Downgrade by one tier** if all enabled techniques have satisfied preventive controls.
- **Unchanged** otherwise.

Also computes the final `risk_score` (0–100) as:
```
base_severity_score (0–40) + attack_chain_score (0–30) + control_gap_score (0–30)
```

**Output:** JSON with `final_severity`, `risk_score`, `rationale`.

---

## Meta-Analysis Prompts (PROMPT-12)

### PROMPT-12 — Meta-Analyzer / False Positive Filter

**Usage:** `MetaAnalyzer.filter_false_positives()` after deduplication.

**Input variables:** `findings_json`, `artifact_context`

**Purpose:** Reviews the deduplicated finding set and identifies likely false positives. Never suppresses CRITICAL findings. For HIGH and below, applies a 0.7 threshold on the LLM-assigned `false_positive_score`. Returns a suppression list with rationale for each suppressed finding.

**Output:** JSON with `suppressed_ids` (list of finding IDs) and `rationale` (dict mapping ID to explanation string).

---

## Agent Skill Prompts (PROMPT-13 through PROMPT-16)

### PROMPT-13 — Finding Summary (Agent Skill Output)

**Usage:** `skill.run_scan()` — generates the conversational response after a scan completes.

**Input variables:** `scan_result_json`, `artifact_path`, `total_findings`, `critical_count`, `high_count`

**Purpose:** Converts the full `ScanResult` into a structured markdown summary suitable for a Claude agent turn. Includes: verdict line, severity breakdown table, top 3 critical findings with technique + control gap highlights, and recommended next steps.

**Output:** Markdown string (not JSON).

---

### PROMPT-14 — Remediation Ticket Generator

**Usage:** `skill.remediate_finding()` — generates a Jira/GitHub Issues-compatible ticket.

**Input variables:** `finding_json`, `ticket_format` (jira | github)

**Purpose:** Generates a structured remediation ticket including: title, description, steps to reproduce, recommended fix (with code snippet if applicable), acceptance criteria, priority, and labels derived from the finding's domain and severity.

**Output:** Markdown string formatted as a Jira or GitHub issue body.

---

### PROMPT-15 — Cross-Finding Correlation

**Usage:** `skill.correlate_findings()` — identifies relationships between findings in a session.

**Input variables:** `findings_json`, `scan_metadata`

**Purpose:** Analyzes the full finding set to identify: shared attack chains (multiple findings enabling the same ATT&CK technique), compounding risk paths (finding A creates the precondition for finding B), and redundant coverage (findings addressed by the same control). Groups findings into attack scenarios with a combined risk narrative.

**Output:** Markdown string with correlation groups and narrative.

---

### PROMPT-16 — Kill Chain Sequence Narrative

**Usage:** `skill.explain_finding()` for ATTACK domain findings; also used by correlate_findings for ATT&CK sequences.

**Input variables:** `technique_sequence`, `log_evidence`, `affected_assets`

**Purpose:** Constructs a natural-language kill chain narrative explaining: what the attacker did at each stage, what artifacts they left behind, what controls could have stopped them at each stage, and what the likely business impact is.

**Output:** Markdown string with a stage-by-stage kill chain narrative.

---

## Prompt ID Reference

| ID | Name | Stage | Caller |
|----|------|-------|--------|
| PROMPT-01 | Domain Classifier | Ingestion | `DomainClassifier` |
| PROMPT-02 | CVE Detect | Detection | `StaticAnalyzer` |
| PROMPT-03 | CWE Detect | Detection | `BehavioralAnalyzer` |
| PROMPT-04 | Policy Detect | Detection | `StaticAnalyzer` |
| PROMPT-05 | ATT&CK Detect | Detection | `BehavioralAnalyzer` |
| PROMPT-06 | Framework Detect | Detection | `StaticAnalyzer` |
| PROMPT-07 | CVE → ATT&CK | Enrichment Hop 1 | `EnrichmentAnalyzer` |
| PROMPT-08 | CWE → ATT&CK | Enrichment Hop 1 | `EnrichmentAnalyzer` |
| PROMPT-09 | Policy → ATT&CK | Enrichment Hop 1 | `EnrichmentAnalyzer` |
| PROMPT-10 | ATT&CK → Controls | Enrichment Hop 2 | `EnrichmentAnalyzer` |
| PROMPT-11 | Severity Contextualization | Final Enrichment | `EnrichmentAnalyzer` |
| PROMPT-12 | False Positive Filter | Meta-Analysis | `MetaAnalyzer` |
| PROMPT-13 | Finding Summary | Agent Output | `skill.run_scan` |
| PROMPT-14 | Remediation Ticket | Agent Output | `skill.remediate_finding` |
| PROMPT-15 | Cross-Finding Correlation | Agent Output | `skill.correlate_findings` |
| PROMPT-16 | Kill Chain Narrative | Agent Output | `skill.explain_finding` |
