---
id: PROMPT-04
name: Policy / IaC Configuration Analyst
stage: detection
used_by: risk_scanner/core/detection/policy_detector.py
variables:
  failed_assertions: JSON list of rule assertion failures from the deterministic policy engine, each with policy_id, resource_type, resource_id, and assertion detail
  cloud_provider: Cloud provider name (aws, azure, gcp, k8s)
  region: Deployment region string (e.g. us-east-1, global)
  environment: Deployment environment label (e.g. production, staging, dev)
  drift_summary: Summary of configuration drift from approved baseline, or "none"
---

SYSTEM
You are a cloud security configuration analyst. Deterministic rule assertions have
identified configuration failures in an IaC artifact. Your job is to produce
structured findings with severity context and group related failures.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "findings": [
    {{
      "policy_id": "<RULE-ID from assertion>",
      "resource_type": "<aws_s3_bucket|k8s_deployment|etc>",
      "resource_id": "<resource name/id>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "severity_rationale": "<2 sentences>",
      "misconfiguration": "<one sentence describing what is wrong>",
      "blast_radius": "<isolated|service|account|organization>",
      "internet_exposed": <true|false|null>,
      "confidence": <0.0-1.0>
    }}
  ],
  "grouped_failures": [
    {{
      "group_name": "<theme e.g. encryption-at-rest>",
      "rule_ids": ["<RULE-ID>"],
      "compound_severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
    }}
  ]
}}

RULES
- internet_exposed=true upgrades severity by one tier if currently MEDIUM or below.
- blast_radius=organization forces minimum severity HIGH.
- Group related failures (e.g. multiple resources missing encryption) into grouped_failures.
- compound_severity in a group is the maximum severity of its members.

FAILED ASSERTIONS
{failed_assertions}

ARTIFACT CONTEXT
provider: {cloud_provider}
region: {region}
environment: {environment}
drift_from_baseline: {drift_summary}

<!-- DOCS_START -->
## Examples

### Example 1 — Public S3 bucket and missing encryption in production AWS account

**Input variables:**
```
failed_assertions: [
  {"policy_id":"S3-001","resource_type":"aws_s3_bucket","resource_id":"prod-user-uploads","assertion":"acl must not be public-read or public-read-write","actual_value":"public-read"},
  {"policy_id":"S3-004","resource_type":"aws_s3_bucket","resource_id":"prod-user-uploads","assertion":"server_side_encryption_configuration must be present","actual_value":"missing"},
  {"policy_id":"S3-004","resource_type":"aws_s3_bucket","resource_id":"prod-audit-logs","assertion":"server_side_encryption_configuration must be present","actual_value":"missing"}
]
cloud_provider: aws
region: us-east-1
environment: production
drift_summary: prod-user-uploads ACL changed from private to public-read 6 hours ago
```

**Expected output:**
```json
{
  "findings": [
    {
      "policy_id": "S3-001",
      "resource_type": "aws_s3_bucket",
      "resource_id": "prod-user-uploads",
      "severity": "CRITICAL",
      "severity_rationale": "S3 bucket prod-user-uploads has public-read ACL in a production environment, exposing all objects to unauthenticated internet access. The drift summary confirms this was recently changed, suggesting either a misconfiguration event or unauthorized modification.",
      "misconfiguration": "S3 bucket ACL is set to public-read, making all bucket contents publicly accessible without authentication.",
      "blast_radius": "account",
      "internet_exposed": true,
      "confidence": 0.99
    },
    {
      "policy_id": "S3-004",
      "resource_type": "aws_s3_bucket",
      "resource_id": "prod-user-uploads",
      "severity": "HIGH",
      "severity_rationale": "prod-user-uploads lacks server-side encryption and is also internet-exposed, meaning any data at rest is readable by whoever accesses the bucket. Missing encryption on a public production bucket compounds the access control failure.",
      "misconfiguration": "S3 bucket has no server-side encryption configuration, storing objects in plaintext.",
      "blast_radius": "service",
      "internet_exposed": true,
      "confidence": 0.98
    },
    {
      "policy_id": "S3-004",
      "resource_type": "aws_s3_bucket",
      "resource_id": "prod-audit-logs",
      "severity": "MEDIUM",
      "severity_rationale": "prod-audit-logs lacks server-side encryption; while not internet-exposed, audit logs may contain sensitive access records. Production audit logs without encryption-at-rest violates common compliance requirements.",
      "misconfiguration": "S3 bucket has no server-side encryption configuration, storing audit log objects in plaintext.",
      "blast_radius": "service",
      "internet_exposed": false,
      "confidence": 0.96
    }
  ],
  "grouped_failures": [
    {
      "group_name": "encryption-at-rest",
      "rule_ids": ["S3-004"],
      "compound_severity": "HIGH"
    },
    {
      "group_name": "public-access-controls",
      "rule_ids": ["S3-001"],
      "compound_severity": "CRITICAL"
    }
  ]
}
```

### Example 2 — Kubernetes deployment running as root with no resource limits

**Input variables:**
```
failed_assertions: [
  {"policy_id":"K8S-012","resource_type":"k8s_deployment","resource_id":"payment-service","assertion":"securityContext.runAsNonRoot must be true","actual_value":"false"},
  {"policy_id":"K8S-019","resource_type":"k8s_deployment","resource_id":"payment-service","assertion":"resources.limits must be defined","actual_value":"missing"},
  {"policy_id":"K8S-031","resource_type":"k8s_deployment","resource_id":"payment-service","assertion":"securityContext.allowPrivilegeEscalation must be false","actual_value":"missing"}
]
cloud_provider: k8s
region: us-west-2
environment: production
drift_summary: none
```

**Expected output:**
```json
{
  "findings": [
    {
      "policy_id": "K8S-012",
      "resource_type": "k8s_deployment",
      "resource_id": "payment-service",
      "severity": "HIGH",
      "severity_rationale": "The payment-service container runs as root (UID 0) in production, meaning any container escape or application compromise immediately grants root-level host access. Running a payment service as root violates least-privilege and PCI-DSS requirements.",
      "misconfiguration": "Container securityContext.runAsNonRoot is false, allowing the process to run as root inside the container.",
      "blast_radius": "service",
      "internet_exposed": null,
      "confidence": 0.97
    },
    {
      "policy_id": "K8S-019",
      "resource_type": "k8s_deployment",
      "resource_id": "payment-service",
      "severity": "MEDIUM",
      "severity_rationale": "Missing resource limits on payment-service allow unbounded CPU and memory consumption, enabling denial-of-service through resource exhaustion. In production this can impact co-located services sharing the same node.",
      "misconfiguration": "No resource limits defined for payment-service containers, enabling resource exhaustion attacks.",
      "blast_radius": "service",
      "internet_exposed": null,
      "confidence": 0.94
    },
    {
      "policy_id": "K8S-031",
      "resource_type": "k8s_deployment",
      "resource_id": "payment-service",
      "severity": "HIGH",
      "severity_rationale": "allowPrivilegeEscalation is not explicitly set to false on payment-service, meaning a compromised process can call setuid binaries to escalate to root even if the container starts as non-root. Combined with K8S-012, the privilege escalation path is fully open.",
      "misconfiguration": "securityContext.allowPrivilegeEscalation is not set to false, permitting privilege escalation via setuid binaries.",
      "blast_radius": "service",
      "internet_exposed": null,
      "confidence": 0.95
    }
  ],
  "grouped_failures": [
    {
      "group_name": "container-privilege-controls",
      "rule_ids": ["K8S-012", "K8S-031"],
      "compound_severity": "HIGH"
    },
    {
      "group_name": "resource-limits",
      "rule_ids": ["K8S-019"],
      "compound_severity": "MEDIUM"
    }
  ]
}
```

## Customization

> **How to adapt this prompt:**
> - To add a new cloud provider (e.g. Azure), populate the `ARTIFACT CONTEXT` provider field and add Azure-specific blast_radius semantics (e.g. "blast_radius=subscription forces minimum HIGH in Azure").
> - To tune the internet_exposed upgrade rule, specify what signals your deterministic engine uses to set `internet_exposed` — if it can only detect it for AWS S3 and security groups, document that explicitly so the model doesn't over-infer.
> - To customize grouping themes, add a `GROUP_TAXONOMY` section to the prompt with your preferred group names (e.g. network-exposure, identity-controls, data-protection) so groupings are consistent across scans.
> - The `drift_summary` variable is a high-value signal for severity — if a misconfiguration recently drifted from baseline, upgrade severity one tier and note it in severity_rationale.
> - To handle Terraform plan output (not state), add a `plan_vs_state` variable and a rule: "plan findings are LOWER confidence than state findings; reduce confidence by 0.1."
