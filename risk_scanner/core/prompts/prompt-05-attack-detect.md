---
id: PROMPT-05
name: ATT&CK Technique Mapper
stage: detection
used_by: risk_scanner/core/detection/attack_detector.py
variables:
  matched_iocs: JSON list of matched indicators of compromise with type, value, and match context
  event_sequences: JSON list of correlated event sequences with timestamps and event details
  retrieved_attack_signals: Embedding-matched ATT&CK technique examples from the pack index
---

SYSTEM
You are a threat intelligence analyst specializing in MITRE ATT&CK.
You will receive IoC matches and temporally correlated event sequences.
Map each to the most precise ATT&CK Technique ID (including sub-technique
where applicable, e.g. T1059.001).

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "findings": [
    {{
      "technique_id": "<T-NNNN.NNN>",
      "technique_name": "<official name>",
      "tactic": "<tactic name>",
      "tactic_id": "<TA-NNNN>",
      "kill_chain_position": <1-N>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "severity_rationale": "<2 sentences>",
      "evidence_type": "<ioc_match|sequence_correlation|behavioral>",
      "confidence": <0.0-1.0>,
      "sequence_stage": "<initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact|null>"
    }}
  ],
  "kill_chain_coverage": {{
    "stages_detected": ["<stage>"],
    "is_complete_chain": <true|false>,
    "chain_summary": "<one sentence>"
  }}
}}

RULES
- Use sub-technique IDs (T1059.001) where evidence is specific enough.
- kill_chain_position is 1-indexed within the detected sequence.
- is_complete_chain=true only if at least Initial Access + one later stage detected.
- severity=CRITICAL for any exfiltration or impact stage finding.

MATCHED IOCs
{matched_iocs}

CORRELATED SEQUENCES
{event_sequences}

RETRIEVED ATT&CK PACK SIGNALS
{retrieved_attack_signals}

<!-- DOCS_START -->
## Examples

### Example 1 — HTTP/2 Rapid Reset DDoS followed by credential access attempts

**Input variables:**
```
matched_iocs: [
  {"type":"traffic_pattern","value":"HTTP/2 RST_STREAM flood 50000 req/s","source_ip":"198.51.100.42","matched_rule":"DETECT-HTTP2-RAPIDRESET"},
  {"type":"user_agent","value":"python-requests/2.28.0","endpoint":"/admin/login","count":847,"matched_rule":"DETECT-BRUTEFORCE"}
]
event_sequences: [
  {"sequence_id":"SEQ-001","events":[
    {"ts":"2024-10-15T03:12:00Z","type":"network","detail":"HTTP/2 flood from 198.51.100.42 targeting /api/"},
    {"ts":"2024-10-15T03:14:22Z","type":"auth","detail":"847 failed login attempts to /admin/login from 198.51.100.43"},
    {"ts":"2024-10-15T03:16:05Z","type":"auth","detail":"Successful login to admin account from 198.51.100.43"}
  ]}
]
retrieved_attack_signals: [{"technique_id":"T1498.002","name":"Network DoS: Reflection Amplification"},{"technique_id":"T1110.001","name":"Brute Force: Password Guessing"}]
```

**Expected output:**
```json
{
  "findings": [
    {
      "technique_id": "T1498.001",
      "technique_name": "Network Denial of Service: Direct Network Flood",
      "tactic": "Impact",
      "tactic_id": "TA0040",
      "kill_chain_position": 1,
      "severity": "CRITICAL",
      "severity_rationale": "HTTP/2 RST_STREAM flood at 50,000 req/s from 198.51.100.42 matches CVE-2023-44487 (HTTP/2 Rapid Reset) pattern used to overwhelm application servers. Impact-stage technique with confirmed service disruption evidence.",
      "evidence_type": "ioc_match",
      "confidence": 0.92,
      "sequence_stage": "impact"
    },
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "tactic_id": "TA0006",
      "kill_chain_position": 2,
      "severity": "HIGH",
      "severity_rationale": "847 failed login attempts from a related IP address immediately following the DoS flood suggests the flood was cover for a credential access operation. Subsequent successful admin login confirms the brute force succeeded.",
      "evidence_type": "sequence_correlation",
      "confidence": 0.88,
      "sequence_stage": "credential_access"
    },
    {
      "technique_id": "T1078.003",
      "technique_name": "Valid Accounts: Local Accounts",
      "tactic": "Initial Access",
      "tactic_id": "TA0001",
      "kill_chain_position": 3,
      "severity": "CRITICAL",
      "severity_rationale": "Successful admin login from the brute-force source IP completes initial access via compromised local account credentials. This is the gateway for all subsequent attacker activity.",
      "evidence_type": "sequence_correlation",
      "confidence": 0.85,
      "sequence_stage": "initial_access"
    }
  ],
  "kill_chain_coverage": {
    "stages_detected": ["impact", "credential_access", "initial_access"],
    "is_complete_chain": true,
    "chain_summary": "Attacker used HTTP/2 Rapid Reset DoS as cover for credential brute force, achieving admin account takeover via valid compromised credentials."
  }
}
```

### Example 2 — PowerShell execution with base64 encoded command followed by scheduled task creation

**Input variables:**
```
matched_iocs: [
  {"type":"process_event","value":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==","host":"WORKSTATION-14","matched_rule":"DETECT-PS-ENCODED"},
  {"type":"registry_event","value":"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks","host":"WORKSTATION-14","matched_rule":"DETECT-SCHTASK-CREATE"}
]
event_sequences: [
  {"sequence_id":"SEQ-002","events":[
    {"ts":"2024-11-03T09:44:01Z","type":"process","detail":"powershell.exe spawned by winword.exe with -enc argument"},
    {"ts":"2024-11-03T09:44:08Z","type":"process","detail":"schtasks.exe /create /tn SystemUpdate /tr C:\\Users\\Public\\updater.exe /sc daily"},
    {"ts":"2024-11-03T09:44:12Z","type":"file","detail":"C:\\Users\\Public\\updater.exe created by powershell.exe"}
  ]}
]
retrieved_attack_signals: [{"technique_id":"T1059.001","name":"Command and Scripting Interpreter: PowerShell"},{"technique_id":"T1053.005","name":"Scheduled Task/Job: Scheduled Task"}]
```

**Expected output:**
```json
{
  "findings": [
    {
      "technique_id": "T1566.001",
      "technique_name": "Phishing: Spearphishing Attachment",
      "tactic": "Initial Access",
      "tactic_id": "TA0001",
      "kill_chain_position": 1,
      "severity": "HIGH",
      "severity_rationale": "PowerShell spawned by winword.exe is a strong indicator of a malicious macro in a Word document, consistent with T1566.001 spearphishing attachment delivery. The parent-child process relationship is a high-confidence signal for document-based initial access.",
      "evidence_type": "sequence_correlation",
      "confidence": 0.87,
      "sequence_stage": "initial_access"
    },
    {
      "technique_id": "T1059.001",
      "technique_name": "Command and Scripting Interpreter: PowerShell",
      "tactic": "Execution",
      "tactic_id": "TA0002",
      "kill_chain_position": 2,
      "severity": "HIGH",
      "severity_rationale": "Base64-encoded PowerShell command executed on WORKSTATION-14 is a classic obfuscation technique to evade command-line logging and AV signatures. The encoded payload dropped a binary to a world-writable path.",
      "evidence_type": "ioc_match",
      "confidence": 0.96,
      "sequence_stage": "execution"
    },
    {
      "technique_id": "T1053.005",
      "technique_name": "Scheduled Task/Job: Scheduled Task",
      "tactic": "Persistence",
      "tactic_id": "TA0003",
      "kill_chain_position": 3,
      "severity": "HIGH",
      "severity_rationale": "schtasks.exe creating a daily 'SystemUpdate' task pointing to a PowerShell-dropped binary establishes persistence that survives reboots. The benign-sounding task name is consistent with defense evasion through masquerading.",
      "evidence_type": "ioc_match",
      "confidence": 0.94,
      "sequence_stage": "persistence"
    }
  ],
  "kill_chain_coverage": {
    "stages_detected": ["initial_access", "execution", "persistence"],
    "is_complete_chain": true,
    "chain_summary": "Malicious Word macro delivered via spearphishing executed obfuscated PowerShell that dropped and persisted a daily scheduled task on WORKSTATION-14."
  }
}
```

## Customization

> **How to adapt this prompt:**
> - To restrict detection to specific ATT&CK tactics, add a rule: "Only map to techniques in the following tactics: {allowed_tactics}." This is useful for scoped threat models (e.g. cloud-only or endpoint-only).
> - To increase sub-technique precision, enrich the `retrieved_attack_signals` with sub-technique-level examples in your pack index; the model will prefer them when they appear in retrieved context.
> - To add a `threat_actor` field to findings, extend the output schema and add a rule: "If the technique sequence matches a known group profile in retrieved signals, populate threat_actor with the group name."
> - To tune `is_complete_chain`, change the rule to require more stages (e.g. Initial Access + Execution + Persistence) for completeness classification.
> - The `kill_chain_position` field is 1-indexed within the detected sequence — if your downstream correlation engine uses 0-indexed positions, adjust accordingly in the consumer.
