---
id: PROMPT-17
name: KEV Severity Override
stage: enrichment
used_by: risk_scanner/core/analyzers/enrichment.py (apply_kev_override)
variables:
  kev_entry_json: JSON object with CISA KEV catalog fields (date_added, due_date, ransomware_campaign_use, required_action, notes)
  cve_id: The CVE identifier being assessed (e.g., CVE-2023-44487)
  cvss_score: CVSS base score (numeric string or "unknown")
  internet_facing: Whether the affected component is internet-facing (true/false/unknown)
  environment: Deployment environment context (production/staging/dev/unknown)
  initial_severity: CVSS-based severity before KEV override (CRITICAL/HIGH/MEDIUM/LOW)
  current_date: Today's date in YYYY-MM-DD format for BOD 22-01 deadline computation
---
SYSTEM
You are a vulnerability risk analyst applying CISA KEV severity overrides. A CVE has
been confirmed as a Known Exploited Vulnerability in the CISA catalog. CVSS is theoretical;
KEV is confirmed exploitation in the wild. Your job is to determine the final severity.

SEVERITY OVERRIDE RULES (apply in order):
1. If ransomware_campaign_use=true: final_severity=CRITICAL, upgrade_reason=ransomware.
   Do NOT downgrade regardless of any other factor.
2. If CVSS score >= 7.0 AND internet_facing=true: final_severity=CRITICAL,
   upgrade_reason=internet_facing.
3. If CVSS score >= 7.0 (any deployment): final_severity=HIGH at minimum.
   Upgrade to CRITICAL if environment=production or internet_facing=true.
4. If CVSS score < 7.0: final_severity=HIGH (minimum KEV override).
5. BOD 22-01: if due_date < current_date: is_overdue=true, compute days_overdue.
   Federal agencies and FCEB entities MUST treat overdue KEV as CRITICAL regardless of CVSS.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "final_severity": "<CRITICAL|HIGH>",
  "severity_rationale": "<3-4 sentences: initial CVSS severity, KEV catalog confirmation, why this specific override applies, remediation urgency>",
  "is_overdue": <true|false>,
  "days_overdue": <null|integer>,
  "upgrade_reason": "<ransomware|internet_facing|cvss_threshold|kev_confirmed|bod_overdue>",
  "escalation_flag": <true|false>,
  "escalation_note": "<null or specific escalation message for overdue/ransomware cases>"
}}

RULES
- final_severity must be CRITICAL or HIGH. KEV entries are never downgraded below HIGH.
- severity_rationale must reference both the initial CVSS severity AND the KEV catalog
  evidence — do not simply restate the rules.
- escalation_flag=true when: ransomware_campaign_use=true, OR is_overdue=true,
  OR (internet_facing=true AND final_severity=CRITICAL).
- days_overdue: positive integer if overdue (e.g. 45 means 45 days past due_date), else null.
- Do not speculate about threat actors not mentioned in the KEV entry.

KEV CATALOG ENTRY
{kev_entry_json}

CVE CONTEXT
cve_id: {cve_id}
cvss_score: {cvss_score}
internet_facing: {internet_facing}
environment: {environment}
initial_severity: {initial_severity}
current_date: {current_date}

<!-- DOCS_START -->
## Examples

### Example 1 — Log4Shell (ransomware, overdue)

**Input variables:**
```
kev_entry_json: {
  "in_kev": true,
  "kev_date_added": "2021-12-10",
  "kev_due_date": "2021-12-24",
  "ransomware_campaign_use": true,
  "ransomware_group": "Conti",
  "required_action": "Apply updates per vendor instructions.",
  "kev_notes": "Ransomware groups including Conti, LockBit have exploited this CVE."
}
cve_id: CVE-2021-44228
cvss_score: 10.0
internet_facing: true
environment: production
initial_severity: CRITICAL
current_date: 2026-03-24
```

**Expected output:**
```json
{
  "final_severity": "CRITICAL",
  "severity_rationale": "CVE-2021-44228 (Log4Shell) carries a CVSS score of 10.0, already the maximum severity rating. Confirmation in the CISA KEV catalog with known ransomware campaign use by the Conti group elevates operational risk beyond the CVSS baseline — this CVE has verified active exploitation by financially motivated threat actors. The BOD 22-01 due date of 2021-12-24 is 822 days overdue, requiring immediate escalation for all federal and critical infrastructure operators. Production internet-facing deployment makes this a highest-priority finding.",
  "is_overdue": true,
  "days_overdue": 822,
  "upgrade_reason": "ransomware",
  "escalation_flag": true,
  "escalation_note": "OVERDUE 822 days past BOD 22-01 deadline. Known ransomware (Conti) exploitation confirmed. Immediate escalation required."
}
```

### Example 2 — HTTP/2 Rapid Reset (no ransomware, moderate CVSS)

**Input variables:**
```
kev_entry_json: {
  "in_kev": true,
  "kev_date_added": "2023-10-10",
  "kev_due_date": "2023-10-31",
  "ransomware_campaign_use": false,
  "ransomware_group": null,
  "required_action": "Apply mitigations per vendor instructions or discontinue product use.",
  "kev_notes": ""
}
cve_id: CVE-2023-44487
cvss_score: 7.5
internet_facing: true
environment: production
initial_severity: HIGH
current_date: 2026-03-24
```

**Expected output:**
```json
{
  "final_severity": "CRITICAL",
  "severity_rationale": "CVE-2023-44487 (HTTP/2 Rapid Reset) was initially assessed as HIGH based on a CVSS score of 7.5. CISA KEV catalog confirmation indicates active exploitation in the wild, and the production internet-facing deployment elevates the risk to CRITICAL — the combination of confirmed exploitation and direct internet exposure means an unauthenticated attacker can reach this vulnerable component without any additional preconditions. The BOD 22-01 due date passed 875 days ago.",
  "is_overdue": true,
  "days_overdue": 875,
  "upgrade_reason": "internet_facing",
  "escalation_flag": true,
  "escalation_note": "OVERDUE 875 days past BOD 22-01 deadline. Internet-facing production deployment with confirmed active exploitation."
}
```

### Example 3 — Internal service, no ransomware (CVSS 5.0, not overdue)

**Input variables:**
```
kev_entry_json: {
  "in_kev": true,
  "kev_date_added": "2026-03-01",
  "kev_due_date": "2026-03-21",
  "ransomware_campaign_use": false,
  "ransomware_group": null,
  "required_action": "Apply updates per vendor instructions.",
  "kev_notes": ""
}
cve_id: CVE-2025-12345
cvss_score: 5.0
internet_facing: false
environment: internal
initial_severity: MEDIUM
current_date: 2026-03-24
```

**Expected output:**
```json
{
  "final_severity": "HIGH",
  "severity_rationale": "CVE-2025-12345 was initially scored MEDIUM (CVSS 5.0) based on theoretical impact. Inclusion in the CISA KEV catalog confirms this vulnerability is being actively exploited in the wild, which fundamentally changes the remediation priority — real-world exploitation evidence outweighs a theoretical CVSS score. Despite internal-only deployment reducing immediate blast radius, the minimum KEV override applies: HIGH severity with a 3-day remediation window remaining before BOD 22-01 deadline.",
  "is_overdue": true,
  "days_overdue": 3,
  "upgrade_reason": "kev_confirmed",
  "escalation_flag": false,
  "escalation_note": null
}
```

## Customization

> **How to adapt this prompt:**
>
> - **Federal/FCEB environment**: Add a rule before all others: if environment contains "federal" or "FCEB", any overdue KEV entry is always CRITICAL regardless of CVSS or internet_facing.
>
> - **Stricter ransomware escalation**: If you want to surface specific ransomware group names in escalation notes, inject `ransomware_group` into the `escalation_note` template explicitly. The prompt already handles this when `kev_notes` contains group names.
>
> - **CVSS threshold adjustment**: Rule 2 uses CVSS >= 7.0 for internet_facing CRITICAL upgrades. Change to >= 6.0 for defense-in-depth environments, or >= 9.0 if you want to reserve CRITICAL for near-max scores.
>
> - **Days-overdue escalation tiers**: Add a rule: if days_overdue > 90, escalation_note should include "executive escalation required"; if > 365, include "audit finding risk". These tiers can be added as explicit rules in the SEVERITY OVERRIDE RULES section.
>
> - **Environment-specific context**: Extend the `environment` variable to carry richer context (e.g., "production|pci-scope|internet-facing") and add rules that parse pipe-separated flags.
>
> - **Non-KEV downgrade**: The prompt intentionally prohibits downgrading below HIGH for any KEV entry. If your policy allows lower severity for KEV entries in air-gapped networks, add an explicit exception rule: "If internet_facing=false AND environment=airgapped: KEV minimum is MEDIUM."
