---
id: PROMPT-11
name: Severity Contextualization and Risk Scoring
stage: enrichment
used_by: risk_scanner/core/enrichment/severity_contextualizer.py
variables:
  domain: Risk domain of the finding (cve, cwe, attack, policy, framework)
  taxonomy_code: The taxonomy identifier for the finding (e.g. CVE-2021-44228, CWE-89, T1190, S3-001)
  initial_severity: Severity assigned at detection stage (CRITICAL, HIGH, MEDIUM, LOW)
  evidence_summary: One-paragraph summary of the finding's evidence and detection context
  attack_enrichment: JSON object from CVE/CWE/policy-to-attack enrichment containing enabled_techniques and attack_narrative
  control_gaps: JSON list of control gap objects from PROMPT-10, each with control_id, satisfaction, and gap_narrative
---

SYSTEM
You are a security risk analyst performing final severity triage. A finding has
been enriched with ATT&CK technique mappings and framework control gaps. Your
job is to produce the final severity, which may differ from the initial detection
severity based on the enrichment evidence.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "final_severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "severity_delta": "<upgraded|downgraded|unchanged>",
  "delta_reason": "<one sentence explaining the change, null if unchanged>",
  "severity_rationale": "<3-4 sentences covering: initial detection severity, ATT&CK techniques enabled, control gaps, and net risk assessment>",
  "risk_score": <0-100>,
  "risk_score_breakdown": {{
    "base_severity_score": <0-40>,
    "attack_chain_score": <0-30>,
    "control_gap_score": <0-30>
  }}
}}

RULES
- Upgrade to CRITICAL if: any exfiltration/impact technique is enabled AND a
  preventive control is MISSING (not partial).
- Downgrade if: all enabled techniques have satisfied preventive controls.
- risk_score = base_severity_score + attack_chain_score + control_gap_score.
- severity_rationale is the primary narrative shown to users — make it readable.

INITIAL FINDING
domain: {domain}
taxonomy_code: {taxonomy_code}
initial_severity: {initial_severity}
evidence_summary: {evidence_summary}

ATT&CK ENRICHMENT
{attack_enrichment}

CONTROL GAPS
{control_gaps}

<!-- DOCS_START -->
## Examples

### Example 1 — CWE-89 SQL injection upgraded to CRITICAL due to missing preventive control and exfiltration technique

**Input variables:**
```
domain: cwe
taxonomy_code: CWE-89
initial_severity: HIGH
evidence_summary: HTTP parameter flows unsanitized into raw SQL cursor.execute() at queries.py:87 in a production Django application handling customer orders. Cross-file taint confirmed by AST analysis.
attack_enrichment: {"enabled_techniques":[{"technique_id":"T1190","technique_name":"Exploit Public-Facing Application","tactic":"Initial Access","kill_chain_pos":1,"likelihood":"high"},{"technique_id":"T1005","technique_name":"Data from Local System","tactic":"Collection","kill_chain_pos":2,"likelihood":"high"},{"technique_id":"T1565.001","technique_name":"Data Manipulation: Stored Data Manipulation","tactic":"Impact","kill_chain_pos":3,"likelihood":"medium"}],"attack_narrative":"SQL injection in orders query enables full database exfiltration and data manipulation."}
control_gaps: [{"control_id":"CC6.6","satisfaction":"partial","gap_narrative":"WAF deployed but no parameterized query enforcement"},{"control_id":"CIS-16.1","satisfaction":"missing","gap_narrative":"No input validation library enforced at framework level"},{"control_id":"A.14.2.5","satisfaction":"missing","gap_narrative":"No secure coding standard requiring parameterized queries"}]
```

**Expected output:**
```json
{
  "final_severity": "CRITICAL",
  "severity_delta": "upgraded",
  "delta_reason": "Impact-stage technique T1565.001 (Stored Data Manipulation) is enabled and both CIS-16.1 and A.14.2.5 preventive controls are missing — upgrade rule triggered.",
  "severity_rationale": "Detection assigned HIGH severity based on network-exploitable SQL injection in production. ATT&CK enrichment confirms this weakness enables Initial Access (T1190), full customer data exfiltration (T1005), and direct database manipulation (T1565.001). Two preventive controls — framework-level input validation (CIS-16.1) and a secure coding standard (A.14.2.5) — are completely missing, meaning there is no defense-in-depth barrier between the vulnerable code path and a complete database compromise. The combination of an impact-stage technique and absent preventive controls triggers upgrade to CRITICAL.",
  "risk_score": 91,
  "risk_score_breakdown": {
    "base_severity_score": 35,
    "attack_chain_score": 28,
    "control_gap_score": 28
  }
}
```

### Example 2 — CVE-2024-3400 held at CRITICAL but risk score reflects mitigating control partial satisfaction

**Input variables:**
```
domain: cve
taxonomy_code: CVE-2024-3400
initial_severity: CRITICAL
evidence_summary: PAN-OS GlobalProtect 11.0.2 confirmed affected by CVE-2024-3400 OS command injection. Deployed as internet-facing VPN gateway in production. No reachability evidence available.
attack_enrichment: {"enabled_techniques":[{"technique_id":"T1190","technique_name":"Exploit Public-Facing Application","tactic":"Initial Access","kill_chain_pos":1,"likelihood":"high"},{"technique_id":"T1059.004","technique_name":"Unix Shell","tactic":"Execution","kill_chain_pos":2,"likelihood":"high"},{"technique_id":"T1136.001","technique_name":"Create Account: Local Account","tactic":"Persistence","kill_chain_pos":3,"likelihood":"medium"}],"attack_narrative":"Unauthenticated OS command injection enables full firewall takeover and persistent backdoor account creation."}
control_gaps: [{"control_id":"CC6.6","satisfaction":"partial","gap_narrative":"Monthly patch cycle does not meet 72-hour SLA for CVSS 10.0 vulnerabilities"},{"control_id":"CIS-7.3","satisfaction":"satisfied","gap_narrative":null},{"control_id":"CC7.1","satisfaction":"partial","gap_narrative":"GuardDuty not enabled; exploit attempts not detected in real time"}]
```

**Expected output:**
```json
{
  "final_severity": "CRITICAL",
  "severity_delta": "unchanged",
  "delta_reason": null,
  "severity_rationale": "CVSS 10.0 CVE-2024-3400 was correctly classified as CRITICAL at detection; ATT&CK enrichment confirms network-exploitable OS command injection enabling persistence and full appliance compromise with no authentication required. While CIS-7.3 patch management is satisfied, the monthly patch cycle (CC6.6 partial) does not meet the 72-hour remediation SLA required for a CVSS 10.0 finding on an internet-facing device. Real-time exploit detection is absent (CC7.1 partial). No preventive controls are fully satisfied for the execution and persistence stages, maintaining CRITICAL severity.",
  "risk_score": 87,
  "risk_score_breakdown": {
    "base_severity_score": 40,
    "attack_chain_score": 27,
    "control_gap_score": 20
  }
}
```

### Example 3 — T1078.004 cloud account technique downgraded from HIGH due to satisfied preventive controls

**Input variables:**
```
domain: attack
taxonomy_code: T1078.004
initial_severity: HIGH
evidence_summary: Valid Accounts: Cloud Accounts technique detected via sequence correlation following credential brute force attempts against AWS console. 847 failed login attempts, no successful authentication observed.
attack_enrichment: {"enabled_techniques":[{"technique_id":"T1078.004","technique_name":"Valid Accounts: Cloud Accounts","tactic":"Initial Access","kill_chain_pos":1,"likelihood":"medium"}],"attack_narrative":"Brute force attempts against AWS console without MFA bypass; attempts failed due to MFA enforcement."}
control_gaps: [{"control_id":"CC6.1","satisfaction":"satisfied","gap_narrative":null},{"control_id":"CIS-5.3","satisfaction":"satisfied","gap_narrative":null},{"control_id":"IA-5","satisfaction":"satisfied","gap_narrative":null}]
```

**Expected output:**
```json
{
  "final_severity": "MEDIUM",
  "severity_delta": "downgraded",
  "delta_reason": "All enabled techniques have satisfied preventive controls — MFA enforcement (CC6.1), account hygiene (CIS-5.3), and authenticator management (IA-5) are all satisfied — downgrade rule triggered.",
  "severity_rationale": "Detection assigned HIGH based on observed brute force activity targeting AWS console accounts. However, enrichment confirms that MFA is fully enforced across all cloud accounts and all relevant preventive controls are satisfied, meaning the brute force attempts cannot succeed even if credentials are guessed correctly. The threat is real and observed, but effectively mitigated by existing controls; severity is downgraded to MEDIUM to reflect residual monitoring and alerting requirements rather than an active exploit risk.",
  "risk_score": 38,
  "risk_score_breakdown": {
    "base_severity_score": 25,
    "attack_chain_score": 8,
    "control_gap_score": 5
  }
}
```

## Customization

> **How to adapt this prompt:**
> - The upgrade and downgrade rules are the most important parameters to tune. Start conservative (upgrade requires both exfiltration/impact AND missing preventive) and loosen as you calibrate false positive rates.
> - To add a business context multiplier to `risk_score`, add a `business_criticality` variable (1-3) and multiply the final score: "risk_score = (base + attack_chain + control_gap) * business_criticality / 2."
> - To calibrate the `risk_score_breakdown` sub-scores, define explicit scoring tables in the prompt: "base_severity_score: CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10; attack_chain_score: +10 per enabled technique; control_gap_score: +10 per missing preventive control."
> - The `severity_rationale` is user-facing narrative — if your audience is executive rather than technical, change the instruction to "Write severity_rationale for a non-technical executive, avoiding CVE IDs and technique IDs."
> - To handle INFO severity (for informational findings with no exploitability), add a rule: "severity=INFO when risk_score < 15 and no enabled techniques have likelihood=high."
