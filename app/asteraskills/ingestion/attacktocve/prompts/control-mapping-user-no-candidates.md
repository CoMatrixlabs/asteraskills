---
id: CONTROL_MAPPING_USER_NO_CANDIDATES
name: ATT&CK-to-Control Mapping User Prompt (No Vector Candidates)
stage: mapping
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  technique_id: MITRE ATT&CK technique identifier, e.g. T1078.004
  technique_name: Human-readable ATT&CK technique name
  tactics: Comma-separated list of ATT&CK tactic names
  platforms: Comma-separated list of targeted platforms
  description: Full ATT&CK technique description text
  mitigations: Newline-separated list of ATT&CK recommended mitigations
  data_sources: Comma-separated list of ATT&CK data sources
  framework_name: The target compliance or risk framework (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
  control_id_label: The identifier format used by the framework, e.g. "CIS Safeguard ID", "NIST control number", "ISO clause reference", "SOC 2 criteria code"
  max_proposals: Maximum number of control mappings to propose, e.g. 5
---

=== ATT&CK Technique ===
ID:           {technique_id}
Name:         {technique_name}
Tactics:      {tactics}
Platforms:    {platforms}
Description:  {description}
Mitigations:  {mitigations}
Data Sources: {data_sources}

=== Candidate {framework_name} controls ===
None were retrieved (vector index + local YAML had no usable items for this framework/tactic).

Propose up to {max_proposals} relevant {framework_name} controls ({control_id_label}) that mitigate this technique for the active tactic context. Return a JSON array. If you cannot name specific valid IDs, return [].

<!-- DOCS_START -->
## Examples

### Example 1 — NIST 800-53 fallback proposals for a lateral movement technique

**Input variables:**
```
technique_id: T1021.001
technique_name: Remote Services: Remote Desktop Protocol
tactics: Lateral Movement
platforms: Windows
description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. Adversaries may use credentials from Valid Accounts to log into remote systems.
mitigations: Limit the accounts that are allowed to login via RDP. Enable Network Level Authentication. Use a VPN or jump server to limit RDP exposure to the internet.
data_sources: Logon Session: Logon Session Creation, Network Traffic: Network Connection Creation, Process: Process Creation
framework_name: NIST 800-53
control_id_label: NIST control number
max_proposals: 4
```

**Expected output:**
```json
[
  {
    "technique_id": "T1021.001",
    "scenario_id": "AC-17",
    "scenario_name": "Remote Access",
    "relevance_score": 0.92,
    "rationale": "RDP is a remote access mechanism; NIST AC-17 requires establishing and documenting usage restrictions, configuration and connection requirements, and implementation guidance for each type of remote access, directly governing RDP use.",
    "mapped_controls": ["T1021.001"],
    "attack_tactics": ["lateral-movement"],
    "attack_platforms": ["Windows"],
    "loss_outcomes": [],
    "confidence": "high"
  },
  {
    "technique_id": "T1021.001",
    "scenario_id": "AC-2",
    "scenario_name": "Account Management",
    "relevance_score": 0.80,
    "rationale": "Abuse of RDP relies on valid accounts; NIST AC-2 mandates managing information system accounts including restricting which accounts have RDP logon rights, limiting the pool of credentials an adversary can abuse.",
    "mapped_controls": ["T1021.001"],
    "attack_tactics": ["lateral-movement"],
    "attack_platforms": ["Windows"],
    "loss_outcomes": [],
    "confidence": "high"
  },
  {
    "technique_id": "T1021.001",
    "scenario_id": "SC-7",
    "scenario_name": "Boundary Protection",
    "relevance_score": 0.65,
    "rationale": "Exposing RDP directly to network segments enables lateral movement; SC-7 boundary protection controls restrict which systems can communicate over management ports, reducing the reachability of RDP endpoints.",
    "mapped_controls": ["T1021.001"],
    "attack_tactics": ["lateral-movement"],
    "attack_platforms": ["Windows"],
    "loss_outcomes": [],
    "confidence": "medium"
  }
]
```

### Example 2 — SOC 2 fallback proposals for a data exfiltration technique

**Input variables:**
```
technique_id: T1048.003
technique_name: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
tactics: Exfiltration
platforms: Linux, Windows, macOS
description: Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.
mitigations: Implement network traffic filtering and deep packet inspection to detect anomalous protocols. Enforce data loss prevention policies.
data_sources: Command: Command Execution, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow
framework_name: SOC 2
control_id_label: SOC 2 criteria code
max_proposals: 3
```

**Expected output:**
```json
[
  {
    "technique_id": "T1048.003",
    "scenario_id": "CC7.2",
    "scenario_name": "System Monitoring",
    "relevance_score": 0.87,
    "rationale": "Exfiltration over unencrypted alternative protocols requires network traffic monitoring to detect; SOC 2 CC7.2 requires monitoring system components to detect anomalies, which must include DLP and network traffic analysis capable of flagging this technique.",
    "mapped_controls": ["T1048.003"],
    "attack_tactics": ["exfiltration"],
    "attack_platforms": ["Linux", "Windows", "macOS"],
    "loss_outcomes": [],
    "confidence": "high"
  },
  {
    "technique_id": "T1048.003",
    "scenario_id": "CC6.7",
    "scenario_name": "Restrict Transmission of Confidential Information",
    "relevance_score": 0.83,
    "rationale": "SOC 2 CC6.7 restricts transmission of confidential information to authorized parties and requires encryption in transit; unencrypted exfiltration directly violates the encryption and authorization objectives of this criterion.",
    "mapped_controls": ["T1048.003"],
    "attack_tactics": ["exfiltration"],
    "attack_platforms": ["Linux", "Windows", "macOS"],
    "loss_outcomes": [],
    "confidence": "high"
  }
]
```

## Customization

> **How to adapt this prompt:**
> - `{max_proposals}` is the primary lever for controlling output volume on the no-candidate path. Set it lower (e.g., 3) for high-precision pipelines, or higher (e.g., 8) when broad coverage is preferred and downstream validation will filter results.
> - `{control_id_label}` is included in the user prompt instruction line to reinforce the expected ID format alongside the system prompt. This double-anchoring reduces hallucinated IDs — especially important since there is no vector-retrieved ground truth to guide the LLM.
> - `{framework_name}` appears both in the header and the instruction, providing maximum context. For frameworks with versioned editions (e.g., "ISO 27001:2022" vs "ISO 27001:2013"), always specify the version to avoid the LLM mixing clause numbers across editions.
> - If the technique has a long description, consider passing only the first 2 sentences of `{description}` plus the full `{mitigations}` field — mitigations are often the most direct signal for which controls apply.
> - To require tactic-specific mappings (e.g., only controls relevant to the Lateral Movement tactic rather than all tactics the technique appears under), filter `{tactics}` to a single tactic before injection and add a line: "Focus only on controls that address the {tactics} tactic context."
> - This prompt pairs with `control-mapping-system-no-candidates.md` as the system message. The `max_proposals` cap in this user prompt and the relevance threshold in the system prompt work together — there is no need to duplicate the threshold here.
