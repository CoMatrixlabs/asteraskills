---
id: CONTROL_MAPPING_USER
name: ATT&CK-to-Control Mapping User Prompt (with candidates)
stage: mapping
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  technique_id: MITRE ATT&CK technique identifier, e.g. T1059.001
  technique_name: Human-readable ATT&CK technique name, e.g. "PowerShell"
  tactics: Comma-separated list of ATT&CK tactic names
  platforms: Comma-separated list of targeted platforms
  description: Full ATT&CK technique description text
  mitigations: Newline-separated list of ATT&CK recommended mitigations for this technique
  data_sources: Comma-separated list of ATT&CK data sources that detect this technique
  framework_name: The target compliance or risk framework (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
  top_k: Number of candidate controls retrieved from the vector store, e.g. 10
  scenarios_json: JSON array of candidate control objects retrieved from the vector store
---

=== ATT&CK Technique ===
ID:           {technique_id}
Name:         {technique_name}
Tactics:      {tactics}
Platforms:    {platforms}
Description:  {description}
Mitigations:  {mitigations}
Data Sources: {data_sources}

=== Candidate {framework_name} Controls / Scenarios (top-{top_k} from vector store) ===
{scenarios_json}

Map the ATT&CK technique to the most relevant {framework_name} controls above.
Return a JSON array. If NO controls are relevant, return an empty array [].

<!-- DOCS_START -->
## Examples

### Example 1 — ISO 27001 mapping for PowerShell abuse

**Input variables:**
```
technique_id: T1059.001
technique_name: Command and Scripting Interpreter: PowerShell
tactics: Execution
platforms: Windows
description: Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
mitigations: Disable or remove PowerShell where not required. Use application control to restrict execution of PowerShell. Enable Script Block Logging and Module Logging in PowerShell.
data_sources: Command: Command Execution, Module: Module Load, Process: Process Creation, Script: Script Execution
framework_name: ISO 27001
top_k: 8
scenarios_json: [{"id": "A.8.15", "name": "Logging", "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed."}, {"id": "A.8.2", "name": "Privileged Access Rights", "description": "The allocation and use of privileged access rights shall be restricted and managed."}, {"id": "A.8.19", "name": "Installation of Software on Operational Systems", "description": "Procedures and measures shall be implemented to securely manage software installation on operational systems."}, {"id": "A.5.33", "name": "Protection of Records", "description": "Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release."}]
```

**Expected output:**
```json
[
  {
    "technique_id": "T1059.001",
    "scenario_id": "A.8.15",
    "scenario_name": "Logging",
    "relevance_score": 0.88,
    "rationale": "PowerShell Script Block Logging and Module Logging generate the audit trail required by ISO 27001 A.8.15; without this logging, malicious PowerShell execution goes undetected and the logging control objective is violated.",
    "mapped_controls": ["T1059.001"],
    "attack_tactics": ["Execution"],
    "attack_platforms": ["Windows"],
    "loss_outcomes": ["Undetected code execution", "Audit trail gaps"],
    "confidence": "high"
  },
  {
    "technique_id": "T1059.001",
    "scenario_id": "A.8.2",
    "scenario_name": "Privileged Access Rights",
    "relevance_score": 0.72,
    "rationale": "PowerShell abuse often relies on accounts with elevated privileges; ISO 27001 A.8.2 requires restricting and managing privileged access rights, which limits the blast radius of malicious script execution.",
    "mapped_controls": ["T1059.001"],
    "attack_tactics": ["Execution"],
    "attack_platforms": ["Windows"],
    "loss_outcomes": ["Privilege escalation", "Lateral movement"],
    "confidence": "medium"
  }
]
```

### Example 2 — SOC 2 mapping for a credential access technique

**Input variables:**
```
technique_id: T1078.004
technique_name: Valid Accounts: Cloud Accounts
tactics: Defense Evasion, Persistence, Privilege Escalation, Initial Access
platforms: IaaS, SaaS, Identity Provider
description: Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
mitigations: Enforce MFA for all cloud accounts. Implement least-privilege IAM policies. Monitor for anomalous login events and impossible travel.
data_sources: Logon Session: Logon Session Creation, User Account: User Account Authentication
framework_name: SOC 2
top_k: 6
scenarios_json: [{"id": "CC6.1", "name": "Logical and Physical Access Controls", "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events."}, {"id": "CC7.2", "name": "The entity monitors system components and the operation of those controls", "description": "The entity monitors system components and the operation of controls used to mitigate risk."}, {"id": "CC6.8", "name": "Prevent or Detect and Act Upon the Introduction of Unauthorized or Malicious Software", "description": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software."}]
```

**Expected output:**
```json
[
  {
    "technique_id": "T1078.004",
    "scenario_id": "CC6.1",
    "scenario_name": "Logical and Physical Access Controls",
    "relevance_score": 0.93,
    "rationale": "T1078.004 directly exploits gaps in logical access controls by using legitimate cloud credentials; SOC 2 CC6.1 requires controls over logical access to protected information assets, and weak IAM policies or absent MFA directly violate this criterion.",
    "mapped_controls": ["T1078.004"],
    "attack_tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "attack_platforms": ["IaaS", "SaaS", "Identity Provider"],
    "loss_outcomes": ["Unauthorized access", "Data exfiltration", "Privilege escalation"],
    "confidence": "high"
  },
  {
    "technique_id": "T1078.004",
    "scenario_id": "CC7.2",
    "scenario_name": "The entity monitors system components and the operation of those controls",
    "relevance_score": 0.75,
    "rationale": "Because the attacker uses valid credentials, detection depends entirely on behavioral monitoring; SOC 2 CC7.2 requires monitoring system components and controls, which must include anomalous login detection to catch this technique.",
    "mapped_controls": ["T1078.004"],
    "attack_tactics": ["Defense Evasion", "Persistence"],
    "attack_platforms": ["IaaS", "SaaS"],
    "loss_outcomes": ["Undetected persistence", "Compliance audit failure"],
    "confidence": "high"
  }
]
```

## Customization

> **How to adapt this prompt:**
> - `{framework_name}` is embedded in the candidate controls header label, signaling to the LLM which framework vocabulary to apply when writing rationales. Ensure the value matches the framework used to populate `{scenarios_json}`.
> - `{top_k}` is informational — it tells the LLM how many candidates were retrieved. Adjust `top_k` in the retrieval layer (not the prompt) to control coverage vs. precision; higher values increase recall but may introduce noise.
> - `{scenarios_json}` should be a compact JSON array. If controls have long descriptions, truncate each description field to 200 characters before injection to avoid exceeding context limits.
> - To force the LLM to explain why it excluded candidates, add an instruction: "For each candidate you exclude, append a brief rejection note in a separate 'excluded' array."
> - For frameworks where the same control may appear under multiple sub-IDs (e.g., NIST 800-53 enhancements), pre-expand the candidates in `{scenarios_json}` to include the relevant enhancements as separate entries.
> - `{mitigations}` and `{data_sources}` provide detection and remediation context that helps the LLM write richer rationales — populate them from the ATT&CK STIX data when available.
