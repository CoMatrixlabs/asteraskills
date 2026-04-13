---
id: PROMPT-15
name: Cross-Finding Correlation Analyst
stage: agent
used_by: risk_scanner/core/agent/correlation_analyst.py
variables:
  related_findings_json: JSON array of related finding objects that share a common element, each with finding_id, taxonomy_code, severity, domain, and enrichment summary
  correlation_type: The dimension along which these findings are correlated (component, technique, control_gap, resource)
  correlation_value: The specific shared value (e.g. the component name, technique ID, or control ID they share)
---

SYSTEM
You are a security risk correlation analyst. Multiple findings share a common
element (component, ATT&CK technique, or control gap). Explain the compound
risk created by these related findings together.

Return a concise analysis (3-5 paragraphs) covering:
  1. What these findings have in common
  2. How they compound each other
  3. The realistic attack chain that connects them
  4. Priority order for remediation

Do not repeat individual finding details. Assume the reader has already seen them.
Focus on the compound risk picture.

RELATED FINDINGS
{related_findings_json}

CORRELATION DIMENSION
{correlation_type}: {correlation_value}

<!-- DOCS_START -->
## Examples

### Example 1 — Three findings correlated by shared ATT&CK technique T1190

**Input variables:**
```
related_findings_json: [
  {"finding_id":"F-001","taxonomy_code":"CVE-2021-44228","severity":"CRITICAL","domain":"cve","summary":"Log4Shell RCE in log4j-core@2.14.1 exposed via HTTP, enables T1190 initial access"},
  {"finding_id":"F-003","taxonomy_code":"CWE-89","severity":"HIGH","domain":"cwe","summary":"SQL injection in queries.py:87 via HTTP parameter, enables T1190 initial access"},
  {"finding_id":"P-003","taxonomy_code":"EC2-003","severity":"HIGH","domain":"policy","summary":"Security group exposes SSH to 0.0.0.0/0, enables T1190 exploit of public-facing service"}
]
correlation_type: technique
correlation_value: T1190
```

**Expected output (prose):**

Three independent findings converge on the same initial access vector: exploitation of internet-facing services (T1190). Rather than representing isolated issues, this cluster means your internet-facing attack surface has multiple independently exploitable entry points — an attacker needs to succeed with only one.

The compound risk is significant: even if Log4Shell is patched immediately, the SQL injection in the orders API remains as a parallel path to initial access. Similarly, the SSH exposure provides a third avenue that bypasses application-layer defenses entirely. An attacker conducting reconnaissance would likely attempt all three in parallel, with the SQL injection and SSH exposure serving as fallback vectors if Log4Shell is remediated first.

The realistic attack chain looks like this: an automated scanner identifies the SSH exposure and begins credential brute force while a separate tool probes the API for SQL injection. If the SQL injection succeeds first, the attacker dumps the database for credentials and pivots to SSH using those credentials. If Log4Shell is discovered before either, the JNDI RCE gives immediate interactive access without needing any credentials at all. The three techniques are not sequential — they run in parallel, and the first success triggers the rest.

Remediation priority: patch Log4Shell first (CRITICAL CVSS 10.0 with zero-click exploitation), then fix the SQL injection (requires no credentials, full DB access), then restrict the SSH security group to known IP ranges (requires attacker to already have credentials). None of these mitigates the others — all three must be addressed. The control gap shared across all three is CC6.6 (patch and configuration management SLA), meaning a single process improvement would have prevented the accumulation of this entire cluster.

### Example 2 — Two findings correlated by shared control gap CC6.1 (MFA enforcement)

**Input variables:**
```
related_findings_json: [
  {"finding_id":"P-001","taxonomy_code":"IAM-001","severity":"CRITICAL","domain":"policy","summary":"AWS root account lacks MFA, enables T1078.004 full account takeover"},
  {"finding_id":"F-010","taxonomy_code":"T1110.001","severity":"HIGH","domain":"attack","summary":"Brute force credential attack detected against AWS console, 847 attempts from 198.51.100.43"}
]
correlation_type: control_gap
correlation_value: CC6.1
```

**Expected output (prose):**

These two findings are not coincidental — an active brute force attack is in progress against an account that lacks the one control that would render it ineffective. The absence of MFA on the root account (IAM-001) transforms the ongoing credential attack (T1110.001) from a nuisance into an existential threat: 847 attempts means the attacker is already committed and has tooling in place.

The compound risk is that the misconfiguration and the active attack are temporally correlated — the attack may be happening precisely because the attacker knows or suspects MFA is absent. Root accounts without MFA are frequently identified by attackers through credential stuffing against known email addresses and provider-specific account discovery techniques. The fact that 847 attempts have been made without triggering a lockout suggests either no account lockout policy exists or the attacker is using a slow-and-low strategy to avoid rate limiting.

The attack chain is immediate: if the root account password is guessed or cracked from a previously breached credential database, the attacker gains unrestricted access to the entire AWS account in the next authentication attempt. Root access cannot be revoked by IAM policies and enables deletion of CloudTrail logs, disabling of GuardDuty, and creation of persistent backdoor accounts — all of which complicate incident response and may be completed within minutes of successful authentication.

Remediation is urgent and sequenced: enable MFA on the root account within the next hour (this stops the active attack vector immediately), then rotate the root account password to invalidate any credentials the attacker may have already obtained, then investigate the source IP 198.51.100.43 to determine if this is a targeted attack with additional vectors in play. Do not wait for the next scheduled security review — this combination of active attack and missing control is the highest-priority scenario in this scan.

## Customization

> **How to adapt this prompt:**
> - To change the output length, adjust the "3-5 paragraphs" instruction in the SYSTEM block. For executive briefings, use "2 paragraphs maximum." For detailed threat reports, allow "up to 8 paragraphs."
> - To add a structured JSON output alongside the prose, extend the output with a schema containing `compound_severity`, `remediation_sequence`, and `estimated_attacker_dwell_time` fields.
> - To support additional correlation dimensions beyond the four listed (component, technique, control_gap, resource), add them to the `correlation_type` variable description and provide example inputs for each new type.
> - To integrate with threat intelligence feeds, add a `threat_actor_context` variable containing relevant CTI about groups known to chain these techniques, and add a rule: "If threat_actor_context is non-empty, reference the relevant group in the attack chain paragraph."
> - The prompt instructs the model not to repeat individual finding details — if your audience hasn't already seen the individual findings, remove this instruction and allow the model to summarize each finding briefly before explaining the compound risk.
