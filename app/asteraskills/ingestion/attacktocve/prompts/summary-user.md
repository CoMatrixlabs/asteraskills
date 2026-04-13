---
id: SUMMARY_USER
name: ATT&CK Mapping Executive Summary User Prompt
stage: summary
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  framework_name: The target compliance or risk framework (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
  technique_id: MITRE ATT&CK technique identifier, e.g. T1190
  technique_name: Human-readable ATT&CK technique name, e.g. "Exploit Public-Facing Application"
  tactics: Comma-separated list of ATT&CK tactic names
  final_mappings_json: JSON array of validated and corrected mappings from the validation stage
---

Summarise the following ATT&CK → {framework_name} control mappings in 3–5 sentences.
Highlight: the attack technique, the primary controls or risk areas it maps to, and which {framework_name} domains or categories are most exposed.

Framework:  {framework_name}
Technique:  {technique_id} – {technique_name}
Tactics:    {tactics}

Final Mappings:
{final_mappings_json}

<!-- DOCS_START -->
## Examples

### Example 1 — NIST 800-53 summary for a network sniffing technique

**Input variables:**
```
framework_name: NIST 800-53 Rev 5
technique_id: T1040
technique_name: Network Sniffing
tactics: Credential Access, Discovery
final_mappings_json: [{"technique_id": "T1040", "scenario_id": "SC-8", "scenario_name": "Transmission Confidentiality and Integrity", "relevance_score": 0.95, "rationale": "T1040 captures data from unencrypted traffic; SC-8 mandates cryptographic protection in transit.", "mapped_controls": ["T1040"], "attack_tactics": ["Credential Access", "Discovery"], "attack_platforms": ["Linux", "Windows", "macOS", "Network"], "loss_outcomes": ["Credential theft", "Data exposure"], "confidence": "high"}, {"technique_id": "T1040", "scenario_id": "SI-4", "scenario_name": "System Monitoring", "relevance_score": 0.67, "rationale": "Passive sniffing goes undetected without traffic analysis; SI-4 requires anomalous traffic monitoring.", "mapped_controls": ["T1040"], "attack_tactics": ["Credential Access", "Discovery"], "attack_platforms": ["Linux", "Windows", "macOS", "Network"], "loss_outcomes": ["Undetected lateral movement"], "confidence": "medium"}, {"technique_id": "T1040", "scenario_id": "IA-5", "scenario_name": "Authenticator Management", "relevance_score": 0.72, "rationale": "Sniffing harvests authentication credentials; IA-5 governs credential storage and transmission security.", "mapped_controls": ["T1040"], "attack_tactics": ["Credential Access"], "attack_platforms": ["Network"], "loss_outcomes": ["Credential theft"], "confidence": "high"}]
```

**Expected output:**
T1040 (Network Sniffing) enables adversaries to passively capture credentials and sensitive data traversing unencrypted network segments, with validated mappings spanning the System and Communications Protection (SC), System and Information Integrity (SI), and Identification and Authentication (IA) control families in NIST 800-53 Rev 5. The highest-confidence mapping is SC-8 (Transmission Confidentiality and Integrity), which directly addresses the encryption gap that passive sniffing exploits — organizations without TLS enforcement across internal network segments are most exposed. IA-5 (Authenticator Management) is also strongly implicated, as credentials captured via this technique are often reused in subsequent lateral movement. The SI-4 (System Monitoring) mapping highlights a detection gap: passive packet capture generates minimal noise, requiring dedicated network traffic analysis tools to identify.

### Example 2 — SOC 2 summary for a PowerShell execution technique

**Input variables:**
```
framework_name: SOC 2 (Trust Services Criteria)
technique_id: T1059.001
technique_name: Command and Scripting Interpreter: PowerShell
tactics: Execution
final_mappings_json: [{"technique_id": "T1059.001", "scenario_id": "CC6.8", "scenario_name": "Prevent or Detect and Act Upon the Introduction of Unauthorized or Malicious Software", "relevance_score": 0.84, "rationale": "Malicious PowerShell scripts constitute unauthorized software execution; CC6.8 requires controls to detect and act on such activity.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": ["Malware execution"], "confidence": "high"}, {"technique_id": "T1059.001", "scenario_id": "CC7.2", "scenario_name": "System Monitoring", "relevance_score": 0.80, "rationale": "Detecting PowerShell abuse requires script block logging and SIEM alerting; CC7.2 mandates monitoring of system components.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": ["Undetected execution"], "confidence": "high"}, {"technique_id": "T1059.001", "scenario_id": "CC6.1", "scenario_name": "Logical and Physical Access Controls", "relevance_score": 0.61, "rationale": "Restricting which users can run PowerShell limits the technique's accessibility; CC6.1 logical access controls govern this.", "mapped_controls": ["T1059.001"], "attack_tactics": ["Execution"], "attack_platforms": ["Windows"], "loss_outcomes": ["Privilege escalation"], "confidence": "medium"}]
```

**Expected output:**
T1059.001 (PowerShell) maps to three SOC 2 Trust Service Criteria across the CC6 (Logical Access Controls) and CC7 (System Operations) categories, reflecting that PowerShell abuse is both an access control problem and a detection challenge. The most critical exposure lies in CC6.8 (preventing unauthorized software execution) and CC7.2 (system monitoring), where organizations without PowerShell Script Block Logging and SIEM-integrated alerting face a significant gap in their ability to detect and respond to this technique. CC6.1 is implicated at lower confidence, as restricting PowerShell execution rights to only those users who operationally require it narrows the available attack surface. For SOC 2 Type II audits, evidence of script execution monitoring and application allowlisting controls will be the key artifacts needed to demonstrate coverage against this technique.

## Customization

> **How to adapt this prompt:**
> - `{framework_name}` shapes the domain/category language used in the summary. The instruction "which {framework_name} domains or categories are most exposed" causes the LLM to name the framework's native organizational structure — CIS Control Groups, NIST control families, ISO Annex A domains, or SOC 2 Trust Service Criteria categories — making summaries immediately meaningful to practitioners in each framework.
> - `{final_mappings_json}` should always contain the validated output from the validation stage, not the raw mapping stage output. Passing pre-validation mappings risks including low-quality or removed entries in the summary.
> - To adjust summary length, change "3–5 sentences" in the instruction to your target. For executive dashboards, "2–3 sentences" keeps summaries scannable. For detailed compliance reports, "5–7 sentences with bullet points for each mapped control" provides more depth.
> - To include remediation recommendations in the summary, add a bullet: "Include one sentence of prioritized remediation advice based on the highest-confidence mappings."
> - `{technique_id}` and `{technique_name}` are both provided to allow the LLM to format the technique reference consistently (e.g., "T1040 (Network Sniffing)"). If your pipeline has already formatted the technique reference, you can consolidate these into a single `{technique_ref}` variable.
> - For multi-tactic techniques, `{tactics}` provides context that the LLM uses to select the most relevant tactic framing for the summary. If you want a tactic-specific summary (e.g., only the Persistence perspective), filter `{tactics}` to a single value before injection.
