---
id: PROMPT-10
name: ATT&CK Technique to Framework Controls Mapper
stage: enrichment
used_by: risk_scanner/core/enrichment/control_mapper.py
variables:
  licensed_frameworks: Comma-separated list of compliance frameworks licensed by the user (e.g. soc2, nist-800-53, cis-8)
  techniques: JSON list of ATT&CK technique objects from detection or enrichment stages, each with technique_id and technique_name
  environment: Deployment environment label (e.g. production, staging, dev)
  known_controls: JSON list of controls already confirmed as implemented in this environment
  evidence_context: Summary of available evidence about the deployment's security posture
  retrieved_mappings: Embedding-matched technique-to-control mapping examples from the enrichment index
---

SYSTEM
You are a compliance and security controls analyst. Your job is to map ATT&CK
techniques to the framework controls that mitigate or detect them, and assess
whether those controls are satisfied given the deployment context provided.

Frameworks to assess (from license claims): {licensed_frameworks}

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "control_mappings": [
    {{
      "technique_id": "<T-NNNN.NNN>",
      "controls": [
        {{
          "control_id": "<control id>",
          "framework": "<soc2|nist-800-53|cis-8|iso27001>",
          "framework_version": "<version>",
          "control_name": "<official name>",
          "control_type": "<preventive|detective|corrective>",
          "satisfaction": "<satisfied|partial|missing|unknown>",
          "gap_narrative": "<what is missing; null if satisfied>",
          "remediation": "<specific actionable steps>",
          "priority": "<immediate|30-days|90-days>"
        }}
      ]
    }}
  ]
}}

RULES
- Map to all licensed frameworks, not just one.
- control_type: preventive = stops the technique; detective = identifies it; corrective = responds.
- satisfaction=unknown when no evidence context is available; never guess.
- remediation must be specific, not generic.
- priority=immediate for any technique in kill_chain_pos <= 2.

ATT&CK TECHNIQUES
{techniques}

DEPLOYMENT CONTEXT
environment: {environment}
known_controls: {known_controls}
evidence_context: {evidence_context}

RETRIEVED TECHNIQUE->CONTROL MAPPINGS
{retrieved_mappings}

<!-- DOCS_START -->
## Examples

### Example 1 — T1190 and T1078.004 mapped to SOC 2 and CIS Controls v8

**Input variables:**
```
licensed_frameworks: soc2, cis-8
techniques: [
  {"technique_id":"T1190","technique_name":"Exploit Public-Facing Application","kill_chain_pos":1},
  {"technique_id":"T1078.004","technique_name":"Valid Accounts: Cloud Accounts","kill_chain_pos":2}
]
environment: production
known_controls: [{"control_id":"CC6.1","status":"partial","note":"MFA enabled for 87% of users"},{"control_id":"CIS-7.3","status":"satisfied"}]
evidence_context: WAF deployed in front of API gateway with OWASP ruleset; CloudTrail enabled but no GuardDuty; patch cycle is monthly
retrieved_mappings: [{"technique":"T1190","controls":["CC7.1","CC6.6","CIS-12.1","CIS-7.3"]},{"technique":"T1078.004","controls":["CC6.1","CC6.3","CIS-5.3"]}]
```

**Expected output:**
```json
{
  "control_mappings": [
    {
      "technique_id": "T1190",
      "controls": [
        {
          "control_id": "CC6.6",
          "framework": "soc2",
          "framework_version": "2017",
          "control_name": "Logical Access Security Over Protected Assets",
          "control_type": "preventive",
          "satisfaction": "partial",
          "gap_narrative": "WAF is deployed with OWASP ruleset which partially mitigates T1190, but monthly patch cycle leaves a window of exposure for newly disclosed exploits. CC6.6 requires timely patching of public-facing components.",
          "remediation": "Reduce patch cycle for internet-facing components to 72 hours for CRITICAL CVEs. Enable AWS Shield Advanced or equivalent for volumetric protection. Enable virtual patching in WAF for newly published CVE rules within 24 hours of publication.",
          "priority": "immediate"
        },
        {
          "control_id": "CC7.1",
          "framework": "soc2",
          "framework_version": "2017",
          "control_name": "Infrastructure Monitoring",
          "control_type": "detective",
          "satisfaction": "partial",
          "gap_narrative": "CloudTrail provides API-level logging but no GuardDuty means exploit attempts against the application layer are not detected in real time. CC7.1 requires anomaly detection, not just logging.",
          "remediation": "Enable Amazon GuardDuty in all regions. Configure custom threat intelligence feeds for known exploit IPs. Set up CloudWatch Alarms for anomalous API Gateway 4xx/5xx rate spikes exceeding 2 standard deviations.",
          "priority": "immediate"
        },
        {
          "control_id": "CIS-7.3",
          "framework": "cis-8",
          "framework_version": "8.0",
          "control_name": "Perform Automated Operating System Patch Management",
          "control_type": "preventive",
          "satisfaction": "satisfied",
          "gap_narrative": null,
          "remediation": "No action required — CIS-7.3 confirmed satisfied per known_controls.",
          "priority": "90-days"
        },
        {
          "control_id": "CIS-12.1",
          "framework": "cis-8",
          "framework_version": "8.0",
          "control_name": "Ensure Network Infrastructure is Up-to-Date",
          "control_type": "preventive",
          "satisfaction": "unknown",
          "gap_narrative": "No evidence of network infrastructure patch status was provided; cannot assess CIS-12.1 satisfaction.",
          "remediation": "Run an inventory of all public-facing network infrastructure components (load balancers, WAF, API gateway) and verify each is on a current vendor-supported version. Document the patch status and establish a 30-day review cadence.",
          "priority": "30-days"
        }
      ]
    },
    {
      "technique_id": "T1078.004",
      "controls": [
        {
          "control_id": "CC6.1",
          "framework": "soc2",
          "framework_version": "2017",
          "control_name": "Logical and Physical Access Controls",
          "control_type": "preventive",
          "satisfaction": "partial",
          "gap_narrative": "13% of IAM users lack MFA; any of these accounts could be used for T1078.004 without triggering a second factor. CC6.1 requires comprehensive logical access controls without exceptions.",
          "remediation": "Enable IAM SCP to deny console access and sensitive API calls for all users without MFA. Identify the 13% of non-compliant users via AWS Config rule iam-user-mfa-enabled and enforce MFA enrollment within 5 business days or deactivate accounts.",
          "priority": "immediate"
        },
        {
          "control_id": "CC6.3",
          "framework": "soc2",
          "framework_version": "2017",
          "control_name": "Role-based Access Control",
          "control_type": "preventive",
          "satisfaction": "unknown",
          "gap_narrative": "No evidence of IAM permission review cadence was provided; cannot assess whether least-privilege is enforced for cloud accounts.",
          "remediation": "Run AWS IAM Access Analyzer to identify unused permissions and overprivileged roles. Schedule a quarterly IAM access review. Remove any AdministratorAccess policies attached to service accounts and replace with least-privilege equivalents.",
          "priority": "30-days"
        },
        {
          "control_id": "CIS-5.3",
          "framework": "cis-8",
          "framework_version": "8.0",
          "control_name": "Disable Dormant Accounts",
          "control_type": "preventive",
          "satisfaction": "unknown",
          "gap_narrative": "No evidence of dormant account review was provided for cloud accounts.",
          "remediation": "Enable AWS Config rule iam-user-unused-credentials-check with a 90-day threshold. Automatically disable credentials unused for 90+ days via Lambda automation. Document exceptions for break-glass accounts with compensating controls.",
          "priority": "30-days"
        }
      ]
    }
  ]
}
```

### Example 2 — T1552 (Unsecured Credentials) mapped to NIST 800-53 and ISO 27001

**Input variables:**
```
licensed_frameworks: nist-800-53, iso27001
techniques: [
  {"technique_id":"T1552.001","technique_name":"Unsecured Credentials: Credentials In Files","kill_chain_pos":1}
]
environment: production
known_controls: []
evidence_context: Python Django application; secrets management review not yet performed; no HashiCorp Vault or AWS Secrets Manager in use
retrieved_mappings: [{"technique":"T1552","controls":["IA-5","SC-28","A.9.4.3","A.10.1.1"]}]
```

**Expected output:**
```json
{
  "control_mappings": [
    {
      "technique_id": "T1552.001",
      "controls": [
        {
          "control_id": "IA-5",
          "framework": "nist-800-53",
          "framework_version": "Rev 5",
          "control_name": "Authenticator Management",
          "control_type": "preventive",
          "satisfaction": "missing",
          "gap_narrative": "No secrets management solution is in place; credentials stored in files violates IA-5's requirement to protect authenticators commensurate with their security category. Django applications should never store credentials in plaintext config files.",
          "remediation": "Migrate all Django settings credentials (DATABASE_PASSWORD, SECRET_KEY, API keys) to AWS Secrets Manager or HashiCorp Vault. Update settings.py to retrieve secrets at runtime via boto3 secrets client. Rotate all credentials that may have been exposed in the current plaintext configuration. Enable pre-commit hooks that detect and block credential patterns (truffleHog, detect-secrets).",
          "priority": "immediate"
        },
        {
          "control_id": "SC-28",
          "framework": "nist-800-53",
          "framework_version": "Rev 5",
          "control_name": "Protection of Information at Rest",
          "control_type": "preventive",
          "satisfaction": "missing",
          "gap_narrative": "Credentials stored in plaintext files are not protected at rest. SC-28 requires encryption of sensitive information stored on production systems.",
          "remediation": "Encrypt the filesystem or volume where config files reside using AWS EBS encryption or equivalent. This is a compensating control only — the primary fix is removing credentials from files entirely per IA-5 remediation.",
          "priority": "immediate"
        },
        {
          "control_id": "A.9.4.3",
          "framework": "iso27001",
          "framework_version": "2022",
          "control_name": "Password Management System",
          "control_type": "preventive",
          "satisfaction": "missing",
          "gap_narrative": "ISO 27001 A.9.4.3 requires a password management system to enforce password quality and confidentiality. Storing database passwords in plaintext config files has no management controls.",
          "remediation": "Implement a privileged access management (PAM) or secrets management solution. All application credentials must be stored in an encrypted vault with access logging, rotation policies, and break-glass procedures documented.",
          "priority": "immediate"
        },
        {
          "control_id": "A.10.1.1",
          "framework": "iso27001",
          "framework_version": "2022",
          "control_name": "Policy on the Use of Cryptographic Controls",
          "control_type": "preventive",
          "satisfaction": "unknown",
          "gap_narrative": "No evidence of a cryptographic controls policy was provided; cannot assess whether credential encryption is covered by organizational policy.",
          "remediation": "Draft a secrets management policy covering: approved secrets storage mechanisms, rotation schedules, access logging requirements, and developer guidelines for credential handling in code.",
          "priority": "30-days"
        }
      ]
    }
  ]
}
```

## Customization

> **How to adapt this prompt:**
> - The `licensed_frameworks` variable is injected into the SYSTEM block header — this is intentional so the model's first instruction anchors it to the correct framework set. Do not move it to the DEPLOYMENT CONTEXT block.
> - To add a custom internal control framework, add it to the `licensed_frameworks` list and populate `retrieved_mappings` with your internal control IDs mapped to ATT&CK techniques.
> - To make `priority` assignment more nuanced, add rules: "priority=immediate also applies when satisfaction=missing AND control_type=preventive AND environment=production."
> - The `satisfaction=unknown` rule is strict by design — it prevents hallucinated compliance claims. Only relax this if your evidence_context is always comprehensive (e.g. from a CSPM tool with full coverage).
> - To generate remediation tickets directly from this output, pass each `controls` entry to PROMPT-14 with the parent technique as context.
