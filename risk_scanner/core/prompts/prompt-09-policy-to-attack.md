---
id: PROMPT-09
name: Policy Misconfiguration to ATT&CK Mapper
stage: enrichment
used_by: risk_scanner/core/enrichment/policy_enricher.py
variables:
  policy_findings: JSON list of policy detection findings from PROMPT-04, each with policy_id, resource_type, resource_id, severity, and misconfiguration
  cloud_provider: Cloud provider name (aws, azure, gcp, k8s)
  environment: Deployment environment label (e.g. production, staging, dev)
  internet_exposed: Boolean string ("true"/"false"/"unknown") indicating whether the environment has internet-facing resources
  retrieved_mappings: Embedding-matched policy-to-technique mapping examples from the enrichment index
---

SYSTEM
You are a cloud security threat analyst. Your job is to determine which ATT&CK
techniques a cloud or infrastructure misconfiguration enables.

For each misconfiguration finding provided, map it to the specific ATT&CK technique(s)
an adversary would use to exploit that configuration flaw.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "enrichments": [
    {{
      "policy_id": "<RULE-ID>",
      "enabled_techniques": [
        {{
          "technique_id": "<T-NNNN.NNN>",
          "technique_name": "<name>",
          "tactic": "<tactic>",
          "tactic_id": "<TA-NNNN>",
          "kill_chain_pos": <1-N>,
          "exploitation_method": "<how attacker exploits this misconfig>",
          "likelihood": "<high|medium|low>",
          "confidence": <0.0-1.0>
        }}
      ],
      "attack_narrative": "<2-3 sentences: realistic attack path from this misconfiguration>"
    }}
  ]
}}

RULES
- Public S3 bucket -> T1530 (Data from Cloud Storage). Always HIGH likelihood.
- No MFA on root -> T1078.004 (Valid Accounts: Cloud). Always HIGH.
- Open security group (0.0.0.0/0) -> T1190 (Exploit Public-Facing Application).
- Overpermissive IAM -> T1078.004 and T1548 (Abuse Elevation Control Mechanism).
- Limit to 3 techniques per misconfiguration.

POLICY FINDINGS
{policy_findings}

DEPLOYMENT CONTEXT
provider: {cloud_provider}
environment: {environment}
internet_exposed: {internet_exposed}

RETRIEVED POLICY->TECHNIQUE MAPPINGS
{retrieved_mappings}

<!-- DOCS_START -->
## Examples

### Example 1 — Public S3 bucket and overpermissive IAM role in AWS production

**Input variables:**
```
policy_findings: [
  {"policy_id":"S3-001","resource_type":"aws_s3_bucket","resource_id":"prod-customer-data","severity":"CRITICAL","misconfiguration":"S3 bucket ACL is set to public-read, exposing all objects to unauthenticated internet access."},
  {"policy_id":"IAM-007","resource_type":"aws_iam_role","resource_id":"app-service-role","severity":"HIGH","misconfiguration":"IAM role has AdministratorAccess policy attached, granting full AWS account permissions to the application service."}
]
cloud_provider: aws
environment: production
internet_exposed: true
retrieved_mappings: [{"policy":"public-s3","techniques":["T1530"]},{"policy":"overpermissive-iam","techniques":["T1078.004","T1548.005"]}]
```

**Expected output:**
```json
{
  "enrichments": [
    {
      "policy_id": "S3-001",
      "enabled_techniques": [
        {
          "technique_id": "T1530",
          "technique_name": "Data from Cloud Storage",
          "tactic": "Collection",
          "tactic_id": "TA0009",
          "kill_chain_pos": 1,
          "exploitation_method": "Attacker uses the AWS S3 ListBucket API without credentials to enumerate all objects in prod-customer-data, then downloads them using GetObject — no authentication required due to public-read ACL.",
          "likelihood": "high",
          "confidence": 0.99
        },
        {
          "technique_id": "T1619",
          "technique_name": "Cloud Storage Object Discovery",
          "tactic": "Discovery",
          "tactic_id": "TA0007",
          "kill_chain_pos": 2,
          "exploitation_method": "Attacker enumerates bucket contents to identify high-value objects (credentials files, backups, PII exports) before targeted exfiltration.",
          "likelihood": "high",
          "confidence": 0.93
        }
      ],
      "attack_narrative": "Any unauthenticated internet user can access prod-customer-data by sending a simple HTTP GET to https://prod-customer-data.s3.amazonaws.com/?list-type=2, enumerating all customer data files. The attacker downloads all objects using standard S3 API calls, exfiltrating the full bucket contents without triggering any IAM-based access controls. This requires no credentials, no prior access, and leaves only S3 access logs as evidence — which may not be monitored."
    },
    {
      "policy_id": "IAM-007",
      "enabled_techniques": [
        {
          "technique_id": "T1078.004",
          "technique_name": "Valid Accounts: Cloud Accounts",
          "tactic": "Persistence",
          "tactic_id": "TA0003",
          "kill_chain_pos": 1,
          "exploitation_method": "Attacker who compromises the application (via any vulnerability) inherits the app-service-role's AdministratorAccess, gaining full AWS account control via valid cloud account credentials.",
          "likelihood": "high",
          "confidence": 0.96
        },
        {
          "technique_id": "T1548.005",
          "technique_name": "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
          "tactic": "Privilege Escalation",
          "tactic_id": "TA0004",
          "kill_chain_pos": 2,
          "exploitation_method": "Attacker uses the app-service-role's iam:CreateRole and iam:AttachRolePolicy permissions to create a new persistent admin role that survives remediation of the initial compromise.",
          "likelihood": "medium",
          "confidence": 0.84
        },
        {
          "technique_id": "T1537",
          "technique_name": "Transfer Data to Cloud Account",
          "tactic": "Exfiltration",
          "tactic_id": "TA0010",
          "kill_chain_pos": 3,
          "exploitation_method": "With full AdministratorAccess, attacker creates a new S3 bucket in an attacker-controlled AWS account and uses cross-account replication to exfiltrate all data.",
          "likelihood": "medium",
          "confidence": 0.81
        }
      ],
      "attack_narrative": "An attacker who achieves any form of code execution in the application inherits the app-service-role's AdministratorAccess, effectively becoming an AWS account administrator. The attacker immediately creates a new IAM user or role with admin permissions to ensure persistent access even after the original vulnerability is patched. Using full account access, the attacker can exfiltrate all S3 data, access secrets in AWS Secrets Manager, and pivot to any other service in the account, making this a full account-level compromise."
    }
  ]
}
```

### Example 2 — No MFA on AWS root account and open security group in staging

**Input variables:**
```
policy_findings: [
  {"policy_id":"IAM-001","resource_type":"aws_root_account","resource_id":"root","severity":"CRITICAL","misconfiguration":"Root account does not have MFA enabled, allowing password-only authentication to the most privileged AWS account."},
  {"policy_id":"EC2-003","resource_type":"aws_security_group","resource_id":"sg-webapp-dev","severity":"HIGH","misconfiguration":"Security group allows inbound SSH (TCP/22) from 0.0.0.0/0, exposing the instance to brute force and exploitation from any internet source."}
]
cloud_provider: aws
environment: staging
internet_exposed: true
retrieved_mappings: [{"policy":"no-root-mfa","techniques":["T1078.004","T1110"]},{"policy":"open-sg-ssh","techniques":["T1190","T1021.004"]}]
```

**Expected output:**
```json
{
  "enrichments": [
    {
      "policy_id": "IAM-001",
      "enabled_techniques": [
        {
          "technique_id": "T1078.004",
          "technique_name": "Valid Accounts: Cloud Accounts",
          "tactic": "Initial Access",
          "tactic_id": "TA0001",
          "kill_chain_pos": 1,
          "exploitation_method": "Attacker obtains the root account password via phishing, credential stuffing, or dark web purchase, then logs in to the AWS Console or CLI with no MFA challenge.",
          "likelihood": "high",
          "confidence": 0.97
        },
        {
          "technique_id": "T1110.003",
          "technique_name": "Brute Force: Password Spraying",
          "tactic": "Credential Access",
          "tactic_id": "TA0006",
          "kill_chain_pos": 2,
          "exploitation_method": "Without MFA, the root account is susceptible to automated password spraying against the AWS Console login endpoint using common password patterns.",
          "likelihood": "medium",
          "confidence": 0.82
        }
      ],
      "attack_narrative": "The AWS root account without MFA is a single-factor authentication target; any attacker who obtains the root email and password — through phishing, a leaked credential database, or password reuse from another breach — gains unrestricted access to the entire AWS account. Root access cannot be constrained by IAM policies and enables permanent account takeover including deletion of all CloudTrail logs, termination of all instances, and disabling of all security controls. Staging accounts are frequently used as pivot points to production when they share IAM cross-account trust relationships."
    },
    {
      "policy_id": "EC2-003",
      "enabled_techniques": [
        {
          "technique_id": "T1190",
          "technique_name": "Exploit Public-Facing Application",
          "tactic": "Initial Access",
          "tactic_id": "TA0001",
          "kill_chain_pos": 1,
          "exploitation_method": "Attacker scans TCP/22 on the instance's public IP and exploits an SSH daemon vulnerability or conducts brute force against weak credentials.",
          "likelihood": "high",
          "confidence": 0.91
        },
        {
          "technique_id": "T1021.004",
          "technique_name": "Remote Services: SSH",
          "tactic": "Lateral Movement",
          "tactic_id": "TA0008",
          "kill_chain_pos": 2,
          "exploitation_method": "Attacker authenticates to the exposed SSH service using stolen keys found in the application codebase or via brute force of weak passwords.",
          "likelihood": "high",
          "confidence": 0.88
        }
      ],
      "attack_narrative": "The security group sg-webapp-dev exposes SSH on port 22 to all internet addresses, making the instance immediately visible and reachable to automated scanners and targeted attackers. An attacker can attempt credential brute force or exploit any unpatched SSH daemon vulnerability to gain shell access to the staging instance. Once on the instance, the attacker can harvest EC2 instance metadata credentials, pivot to other staging resources, or use staging-to-production trust relationships to escalate into the production environment."
    }
  ]
}
```

## Customization

> **How to adapt this prompt:**
> - The five hardcoded mapping rules (S3 public, no-MFA root, open SG, overpermissive IAM) are the most common findings — add rules for your environment's specific failure modes (e.g. "Azure Blob public access -> T1530; GCP public GCS bucket -> T1530").
> - To add Azure or GCP-specific technique mappings, extend the RULES section with provider-specific patterns and populate `retrieved_mappings` with examples from those providers.
> - To control the `kill_chain_pos` assignment, add a rule: "Assign kill_chain_pos=1 to the technique that directly exploits the misconfiguration, and increment for each subsequent technique in the exploitation chain."
> - To generate compound attack narratives across multiple findings, use PROMPT-15 (cross-finding correlation) after this enrichment step rather than trying to combine narratives here.
> - To adjust the 3-technique limit, be conservative — over-mapping leads to alert fatigue. Only increase the limit for genuinely complex misconfigurations like unrestricted IAM passRole or publicly-accessible KMS keys.
