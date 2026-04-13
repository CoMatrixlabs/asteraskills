---
id: VALIDATION_USER
name: Mapping Validation User Prompt
stage: validation
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  framework_name: The target compliance or risk framework being validated against (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
  technique_summary: A brief summary of the ATT&CK technique including ID, name, tactics, and key behaviors
  raw_mappings_json: JSON array of proposed mappings from the mapping agent, using the standard mapping schema
---

=== Control Framework ===
{framework_name}

=== ATT&CK Technique Context ===
{technique_summary}

=== Proposed Mappings (from mapping agent) ===
{raw_mappings_json}

Validate against {framework_name} control objectives and return the corrected JSON object.

<!-- DOCS_START -->
## Examples

### Example 1 — SOC 2 validation of T1078.004 mappings

**Input variables:**
```
framework_name: SOC 2 (Trust Services Criteria)
technique_summary: T1078.004 – Valid Accounts: Cloud Accounts. Tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion. Adversaries obtain and abuse cloud account credentials to access IaaS/SaaS environments, often leveraging federated identity providers to generate or modify tokens and blend in with normal user activity.
raw_mappings_json: [{"technique_id": "T1078.004", "scenario_id": "CC6.1", "scenario_name": "Logical and Physical Access Controls", "relevance_score": 0.93, "rationale": "Exploits gaps in logical access controls by using legitimate cloud credentials.", "mapped_controls": ["T1078.004"], "attack_tactics": ["Initial Access", "Persistence"], "attack_platforms": ["IaaS", "SaaS"], "loss_outcomes": ["Unauthorized access"], "confidence": "high"}, {"technique_id": "T1078.004", "scenario_id": "A1.2", "scenario_name": "Environmental Protections", "relevance_score": 0.55, "rationale": "Cloud infrastructure availability could be impacted.", "mapped_controls": ["T1078.004"], "attack_tactics": ["Defense Evasion"], "attack_platforms": ["IaaS"], "loss_outcomes": [], "confidence": "medium"}]
```

**Expected output:**
```json
{
  "is_valid": false,
  "issues": [
    "Mapping A1.2 (Environmental Protections) is misapplied: A1.2 addresses physical and environmental availability controls (power, cooling, physical access), not logical cloud account abuse. A relevance score of 0.55 is not supportable for this technique.",
    "Mapping CC6.1 is well-supported and rationale correctly identifies the logical access control gap."
  ],
  "corrected_mappings": [
    {
      "technique_id": "T1078.004",
      "scenario_id": "CC6.1",
      "scenario_name": "Logical and Physical Access Controls",
      "relevance_score": 0.93,
      "rationale": "T1078.004 exploits gaps in logical access controls by abusing legitimate cloud credentials; SOC 2 CC6.1 requires controls over logical access to protected information assets and directly addresses the IAM weaknesses this technique exploits.",
      "mapped_controls": ["T1078.004"],
      "attack_tactics": ["Initial Access", "Persistence"],
      "attack_platforms": ["IaaS", "SaaS"],
      "loss_outcomes": ["Unauthorized access"],
      "confidence": "high"
    }
  ],
  "validation_notes": "A1.2 was removed — it applies to physical infrastructure availability, not cloud IAM abuse. SOC 2 reviewers should note that T1078.004 maps primarily to the CC6 (Logical Access) and CC7 (System Operations/Monitoring) criteria families, not availability criteria. The missing CC7.2 monitoring mapping should be considered for addition in a subsequent enrichment pass."
}
```

### Example 2 — NIST 800-53 validation of T1059.001 mappings with score corrections

**Input variables:**
```
framework_name: NIST 800-53 Rev 5
technique_summary: T1059.001 – Command and Scripting Interpreter: PowerShell. Tactics: Execution. Adversaries abuse PowerShell for code execution, discovery, and lateral movement on Windows systems. Common abuse patterns include encoded command execution, AMSI bypass, and reflective loading of malicious modules.
raw_mappings_json: [{"technique_id": "T1059.001", "scenario_id": "AU-2", "scenario_name": "Event Logging", "relevance_score": 0.90, "rationale": "PowerShell logging should be enabled.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": ["Audit gaps"], "confidence": "high"}, {"technique_id": "T1059.001", "scenario_id": "SI-3", "scenario_name": "Malicious Code Protection", "relevance_score": 0.78, "rationale": "Anti-malware tools may detect malicious PowerShell scripts by scanning script content and blocking known-bad patterns before execution completes.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": ["Malware execution"], "confidence": "medium"}, {"technique_id": "T1059.001", "scenario_id": "CM-7", "scenario_name": "Least Functionality", "relevance_score": 0.85, "rationale": "Disabling PowerShell where not needed is a configuration management action.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": [], "confidence": "high"}]
```

**Expected output:**
```json
{
  "is_valid": false,
  "issues": [
    "AU-2 mapping score of 0.90 is overstated given the rationale only says 'PowerShell logging should be enabled' without citing the specific AU-2 requirement to identify events. Downscoring to 0.78 and requiring a rationale that cites AU-2's event identification objective.",
    "CM-7 rationale is acceptable but confidence 'high' is appropriate only if application allowlisting is explicitly referenced; 'disabling PowerShell' is an example of least functionality, but CM-7 also covers broader configuration scope."
  ],
  "corrected_mappings": [
    {
      "technique_id": "T1059.001",
      "scenario_id": "AU-2",
      "scenario_name": "Event Logging",
      "relevance_score": 0.78,
      "rationale": "NIST AU-2 requires identifying which auditable events are relevant to security monitoring; enabling PowerShell Script Block Logging and Module Logging are the specific audit event configurations required to detect T1059.001 abuse.",
      "mapped_controls": ["T1059.001"],
      "attack_tactics": ["Execution"],
      "attack_platforms": ["Windows"],
      "loss_outcomes": ["Audit gaps", "Undetected execution"],
      "confidence": "high"
    },
    {
      "technique_id": "T1059.001",
      "scenario_id": "SI-3",
      "scenario_name": "Malicious Code Protection",
      "relevance_score": 0.78,
      "rationale": "Anti-malware tools may detect malicious PowerShell scripts by scanning script content and blocking known-bad patterns before execution completes.",
      "mapped_controls": ["T1059.001"],
      "attack_tactics": ["Execution"],
      "attack_platforms": ["Windows"],
      "loss_outcomes": ["Malware execution"],
      "confidence": "medium"
    },
    {
      "technique_id": "T1059.001",
      "scenario_id": "CM-7",
      "scenario_name": "Least Functionality",
      "relevance_score": 0.85,
      "rationale": "NIST CM-7 requires configuring systems to provide only essential capabilities; restricting or disabling PowerShell on endpoints where it is not operationally required directly implements this principle and eliminates the abuse surface.",
      "mapped_controls": ["T1059.001"],
      "attack_tactics": ["Execution"],
      "attack_platforms": ["Windows"],
      "loss_outcomes": [],
      "confidence": "high"
    }
  ],
  "validation_notes": "All three mappings retained after corrections. NIST 800-53 Rev 5 reviewers should note that PowerShell abuse has strong relevance across AU (audit), SI (system integrity), and CM (configuration management) control families. Consider also reviewing CM-11 (User-Installed Software) and AU-12 (Audit Record Generation) for completeness in a follow-on enrichment pass."
}
```

## Customization

> **How to adapt this prompt:**
> - `{framework_name}` is repeated in both the header and the final instruction. This double-anchoring ensures the validator applies the correct framework lens even when `{raw_mappings_json}` contains `scenario_id` values from a different framework (a common data pipeline bug). Always pass the exact same framework name used during mapping.
> - `{technique_summary}` should be a condensed 2–4 sentence synthesis of the technique — not the full ATT&CK description. Construct it by combining technique ID, name, primary tactics, and key adversary behaviors. Keeping it brief keeps the validator focused on cross-checking logic rather than re-reading source material.
> - `{raw_mappings_json}` must be the complete JSON array from the mapping stage output. Truncating or reformatting it will cause the validator to produce incomplete `corrected_mappings`.
> - To get more actionable validation output, instruct consumers to parse `issues` for programmatic quality scoring and surface `validation_notes` to human reviewers for framework-specific concerns that require judgment.
> - For high-throughput pipelines, this prompt can be batched: pass multiple techniques' mappings in a single call by wrapping `{raw_mappings_json}` in a keyed object (e.g., `{"T1059.001": [...], "T1190": [...]}`). Adjust the output schema accordingly in the system prompt.
