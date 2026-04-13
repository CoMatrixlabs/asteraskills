---
id: PROMPT-06
name: Compliance Framework Control Assessor
stage: detection
used_by: risk_scanner/core/detection/framework_detector.py
variables:
  control_list: JSON list of framework controls to assess, each with control_id, control_name, and description
  evidence_summaries: JSON list of evidence artifacts, each with a reference ID and summary of the evidence content
---

SYSTEM
You are a compliance analyst. You will receive evidence artifacts (config exports,
audit logs, screenshots descriptions, CSV data) and a list of controls from the
requested framework. Classify each control as satisfied, partial, or missing based
on the evidence.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "framework": "<soc2|nist-800-53|cis-8|iso27001>",
  "framework_version": "<version>",
  "control_assessments": [
    {{
      "control_id": "<control id>",
      "control_name": "<official name>",
      "satisfaction": "<satisfied|partial|missing>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "evidence_ref": "<which evidence artifact supports this>",
      "gap_narrative": "<what is missing or incomplete, null if satisfied>",
      "confidence": <0.0-1.0>
    }}
  ],
  "coverage_summary": {{
    "satisfied": <count>,
    "partial": <count>,
    "missing": <count>,
    "total_assessed": <count>
  }}
}}

RULES
- satisfaction=satisfied requires positive evidence, not absence of negative evidence.
- partial means the control exists but coverage is incomplete or documentation insufficient.
- severity for missing controls: use control criticality from the framework's own risk tiers.
- Do not assess controls for which no relevant evidence was provided; omit them entirely.

FRAMEWORK CONTROLS TO ASSESS
{control_list}

EVIDENCE ARTIFACTS
{evidence_summaries}

<!-- DOCS_START -->
## Examples

### Example 1 — SOC 2 Type II assessment for a SaaS platform with partial MFA and logging gaps

**Input variables:**
```
control_list: [
  {"control_id":"CC6.1","control_name":"Logical and Physical Access Controls","description":"The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events."},
  {"control_id":"CC7.2","control_name":"The entity monitors system components for anomalies","description":"The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives."},
  {"control_id":"CC9.2","control_name":"The entity assesses and manages risks associated with vendors","description":"The entity assesses and manages risks associated with vendors and business partners."}
]
evidence_summaries: [
  {"ref":"EVID-001","summary":"AWS IAM export showing MFA enabled for 87% of IAM users; root account has MFA enabled; 3 service accounts lack MFA."},
  {"ref":"EVID-002","summary":"CloudWatch Logs export showing application and infrastructure logs retained for 90 days with no alerting rules configured."},
  {"ref":"EVID-003","summary":"No vendor risk assessment documentation provided."}
]
```

**Expected output:**
```json
{
  "framework": "soc2",
  "framework_version": "2017",
  "control_assessments": [
    {
      "control_id": "CC6.1",
      "control_name": "Logical and Physical Access Controls",
      "satisfaction": "partial",
      "severity": "HIGH",
      "evidence_ref": "EVID-001",
      "gap_narrative": "MFA is enabled for 87% of IAM users and root, but 3 service accounts lack MFA. CC6.1 requires comprehensive logical access controls; service account exceptions represent an incomplete implementation that could be exploited for unauthorized access.",
      "confidence": 0.91
    },
    {
      "control_id": "CC7.2",
      "control_name": "The entity monitors system components for anomalies",
      "satisfaction": "partial",
      "severity": "MEDIUM",
      "evidence_ref": "EVID-002",
      "gap_narrative": "Logs are retained for 90 days which satisfies the retention aspect, but no alerting rules are configured meaning anomalous activity is logged but not monitored in real-time. CC7.2 requires active monitoring, not just log collection.",
      "confidence": 0.88
    },
    {
      "control_id": "CC9.2",
      "control_name": "The entity assesses and manages risks associated with vendors",
      "satisfaction": "missing",
      "severity": "HIGH",
      "evidence_ref": "EVID-003",
      "gap_narrative": "No vendor risk assessment documentation was provided. CC9.2 requires documented assessment of vendor risks; absence of any documentation means this control cannot be assessed as satisfied.",
      "confidence": 0.95
    }
  ],
  "coverage_summary": {
    "satisfied": 0,
    "partial": 2,
    "missing": 1,
    "total_assessed": 3
  }
}
```

### Example 2 — CIS Controls v8 assessment for an on-premises environment

**Input variables:**
```
control_list: [
  {"control_id":"CIS-1.1","control_name":"Establish and Maintain Detailed Enterprise Asset Inventory","description":"Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data."},
  {"control_id":"CIS-4.1","control_name":"Establish and Maintain a Secure Configuration Process","description":"Establish and maintain a secure configuration process for enterprise assets and software."},
  {"control_id":"CIS-11.3","control_name":"Protect Recovery Data","description":"Protect recovery data with equivalent controls as the original data."}
]
evidence_summaries: [
  {"ref":"EVID-A","summary":"Nessus asset discovery scan CSV showing 342 assets discovered; CMDB export shows 289 assets registered. 53 assets present in scan not in CMDB."},
  {"ref":"EVID-B","summary":"CIS-CAT Pro benchmark report for Windows Server 2022 baseline: 74% pass rate, 26% failures in network configuration and service hardening sections."},
  {"ref":"EVID-C","summary":"Backup policy document stating daily backups to S3 with AES-256 encryption and 30-day retention; last successful backup verified 2024-11-01."}
]
```

**Expected output:**
```json
{
  "framework": "cis-8",
  "framework_version": "8.0",
  "control_assessments": [
    {
      "control_id": "CIS-1.1",
      "control_name": "Establish and Maintain Detailed Enterprise Asset Inventory",
      "satisfaction": "partial",
      "severity": "MEDIUM",
      "evidence_ref": "EVID-A",
      "gap_narrative": "53 of 342 discovered assets (15.5%) are not in the CMDB, representing unmanaged assets that cannot be patched, configured, or monitored. CIS-1.1 requires a complete and current inventory; this gap is material.",
      "confidence": 0.93
    },
    {
      "control_id": "CIS-4.1",
      "control_name": "Establish and Maintain a Secure Configuration Process",
      "satisfaction": "partial",
      "severity": "HIGH",
      "evidence_ref": "EVID-B",
      "gap_narrative": "CIS-CAT Pro shows 74% benchmark compliance against CIS Windows Server 2022; the 26% failure rate in network configuration and service hardening represents unacceptable residual exposure in critical areas. A secure configuration process exists but is not fully enforced.",
      "confidence": 0.89
    },
    {
      "control_id": "CIS-11.3",
      "control_name": "Protect Recovery Data",
      "satisfaction": "satisfied",
      "severity": "INFO",
      "evidence_ref": "EVID-C",
      "gap_narrative": null,
      "confidence": 0.94
    }
  ],
  "coverage_summary": {
    "satisfied": 1,
    "partial": 2,
    "missing": 0,
    "total_assessed": 3
  }
}
```

## Customization

> **How to adapt this prompt:**
> - To restrict assessment to a specific framework version (e.g. NIST 800-53 Rev 5 only), add to the RULES: "Only use control IDs and names from {framework} version {version}; reject control_list entries from other versions."
> - To improve evidence matching, add an `evidence_type` field to each evidence artifact (e.g. config_export, audit_log, policy_doc, screenshot) and add a rule mapping evidence types to the controls they can satisfy.
> - To handle multi-framework assessments in one call, repeat the control_list with controls from different frameworks and ensure the output schema's `framework` field is populated per assessment (you may need to change it to an array).
> - The `satisfaction=satisfied requires positive evidence` rule is the strictest setting — relax it to `partial` for controls where absence of negative evidence is industry-standard (e.g. penetration test showed no finding).
> - To customize severity mapping for missing controls, add a `CONTROL_RISK_TIERS` section listing the framework's own criticality classifications (e.g. CIS IG1/IG2/IG3, NIST High/Moderate/Low baselines).
