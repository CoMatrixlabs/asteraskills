---
id: ATTACK_QUERY_BUILDER
name: ATT&CK Technique Search Query Builder
stage: query
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  framework_name: The target compliance or risk framework (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
  technique_id: MITRE ATT&CK technique identifier, e.g. T1190 or T1059.001
  technique_name: Human-readable ATT&CK technique name, e.g. "Exploit Public-Facing Application"
  tactics: Comma-separated list of ATT&CK tactic names, e.g. "Initial Access, Execution"
  platforms: Comma-separated list of targeted platforms, e.g. "Windows, Linux, IaaS"
  description: Full ATT&CK technique description text
---

You are a cybersecurity analyst building a semantic search query to find relevant controls and risk scenarios inside a {framework_name} control library.

Given the ATT&CK technique details below, write a concise search query (2–4 sentences) that captures:
- What the attacker does (the core action)
- Which systems, data, or processes are targeted
- What the primary business or compliance impact would be
- Any {framework_name}-specific risk themes the technique is likely to trigger

Return ONLY the search query text — no preamble, no markdown.

Technique ID:    {technique_id}
Technique Name:  {technique_name}
Tactics:         {tactics}
Platforms:       {platforms}
Description:
{description}

<!-- DOCS_START -->
## Examples

### Example 1 — CIS Controls query for a web exploitation technique

**Input variables:**
```
framework_name: CIS Controls
technique_id: T1190
technique_name: Exploit Public-Facing Application
tactics: Initial Access
platforms: Windows, Linux, macOS, Network, IaaS
description: Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration. Webservers, web applications, databases (e.g., SQL), standard services (e.g., SMB or SSH), network device administration and management protocols (e.g., SNMP and Smart Install), and any other system with the Internet accessible open sockets that have not been patched or are improperly configured may be vulnerable.
```

**Expected output:**
An attacker exploits a vulnerability in an internet-facing web application or service to gain unauthorized initial access to the network. The targeted systems include web servers, databases, and exposed administrative interfaces that have unpatched software bugs or misconfigurations. The primary business impact is unauthorized network entry, data exfiltration, and potential lateral movement across critical infrastructure. CIS Controls risk themes include asset inventory gaps, patch management failures, and inadequate web application security testing.

### Example 2 — NIST 800-53 query for a credential abuse technique

**Input variables:**
```
framework_name: NIST 800-53
technique_id: T1078.004
technique_name: Valid Accounts: Cloud Accounts
tactics: Defense Evasion, Persistence, Privilege Escalation, Initial Access
platforms: IaaS, SaaS, Identity Provider
description: Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, integration/development, and administration. In scenarios with an Identity Provider, the adversary may be able to generate or modify federated tokens.
```

**Expected output:**
An attacker obtains and abuses legitimate cloud account credentials to gain persistent access to IaaS and SaaS environments while evading detection by blending in with normal user activity. The targeted resources include cloud-hosted data stores, administrative consoles, and identity federation services such as IdPs and SSO providers. Primary compliance impacts include unauthorized privileged access, audit trail manipulation, and violation of least-privilege access controls. NIST 800-53 risk themes include identity and access management controls (IA, AC families), audit and accountability gaps, and federated identity trust boundary failures.

## Customization

> **How to adapt this prompt:**
> - Changing `{framework_name}` directly shapes the final sentence — the LLM will tailor risk themes to the named framework's vocabulary (e.g., "Safeguards" for CIS, "control families" for NIST, "Annex A clauses" for ISO 27001, "Trust Service Criteria" for SOC 2). Always pass the full, canonical framework name.
> - To generate longer or more detailed queries, change "2–4 sentences" in the instruction to "3–6 sentences" or add a bullet requesting sub-technique context.
> - If your vector store uses keyword-based retrieval rather than dense embeddings, append an instruction to include specific control-family abbreviations (e.g., "include relevant control family codes like AC, SI, IA").
> - For highly verbose ATT&CK descriptions, consider truncating `{description}` to the first 300 characters before injecting to keep the prompt within token limits while retaining the technique's core action.
> - To target a specific tactic context (e.g., only Persistence mappings), filter `{tactics}` to the relevant tactic before injection rather than passing the full list.
