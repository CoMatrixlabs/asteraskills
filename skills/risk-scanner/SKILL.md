---
name: risk-scanner
description: Use when the user wants to scan a security artifact for vulnerabilities, weaknesses, misconfigurations, or compliance gaps. Triggers on: "scan <path>", "scan my SBOM", "scan my Terraform", "check for CVEs in", "find vulnerabilities in", "analyze for security issues", "check compliance", "risk scan", "security scan". Each finding is enriched with MITRE ATT&CK techniques and framework control gaps (SOC2, NIST 800-53, CIS 8, ISO 27001).
---

# Risk Scanner

Multi-domain security artifact scanner. Scans SBOMs, source code, IaC templates,
SIEM logs, and compliance evidence. Every finding is enriched with ATT&CK techniques
and framework control gaps inside the scan itself.

## Prerequisites

```bash
cd /path/to/Lexy/asteraskills
pip install -e ".[runtime]"
risk-scanner --help
```

Optional: set `RISK_SCANNER_LICENSE_TOKEN` for richer intelligence server rule packs.

## Scan Commands

```bash
# Scan a SBOM for CVE findings with ATT&CK + NIST mapping
risk-scanner scan run /path/to/sbom.json --format markdown

# Scan Terraform for policy misconfigurations
risk-scanner scan run /path/to/main.tf --domain policy --format markdown

# Scan Python source for CWE weaknesses
risk-scanner scan run /path/to/app.py --domain cwe

# Scan with specific frameworks
risk-scanner scan run /path/to/sbom.json --frameworks cis-8,nist-800-53

# Export as SARIF (GitHub Actions compatible)
risk-scanner scan run /path/to/sbom.json --format sarif > results.sarif

# Scan all files in a directory
risk-scanner scan all /path/to/project/ --format markdown

# Severity threshold (only HIGH and above)
risk-scanner scan run /path/to/sbom.json --severity HIGH
```

## Programmatic (Python skill)

```python
from risk_scanner.agent.skill import (
    run_scan, explain_finding, remediate_finding,
    export_result, correlate_findings
)

# Scan and get conversational summary
summary = run_scan("/path/to/sbom.json", session_id="my-session")

# Deep explanation of a specific finding
detail = explain_finding("RS-A1B2C3D4", session_id="my-session")

# Generate a remediation ticket (Jira/GitHub Issues format)
ticket = remediate_finding("RS-A1B2C3D4", session_id="my-session")

# Export in any format
sarif = export_result("sarif", session_id="my-session")
markdown = export_result("markdown", session_id="my-session")

# Cross-finding correlation analysis
correlation = correlate_findings(session_id="my-session")
```

## Follow-up Turns

After a scan, Claude can answer follow-up questions using the stored scan context:
- "Why is finding RS-003 CRITICAL?"
- "Show me only ATT&CK findings"
- "What controls do I need for SOC2 compliance?"
- "Generate a Jira ticket for finding RS-001"
- "Which finding should I fix first?"
- "Export this as SARIF for my CI pipeline"
- "Explain the relationship between RS-001 and RS-003"

## Artifact Types

| Type | Format | Domain |
|------|--------|--------|
| SBOM | CycloneDX JSON/XML, SPDX, Syft | CVE |
| Source code | Python, JS/TS, Go, Bash, Rust | CWE |
| IaC | Terraform HCL, CloudFormation, Kubernetes YAML | POLICY |
| Logs/Alerts | SIEM JSON, CEF, JSONL | ATTACK |
| Evidence | PDF, CSV, XLSX | FRAMEWORK |

## Policy Presets

```bash
# Generate a pre-configured policy file
risk-scanner generate-policy --preset cve-only --output policy.yaml
risk-scanner generate-policy --preset cicd --output policy.yaml
risk-scanner generate-policy --preset soc2 --output policy.yaml

# Available presets: strict, cve-only, iac, cicd, soc2
```

## Exit Codes

- `0` — scan complete, no CRITICAL findings
- `1` — CRITICAL findings present (use in CI gates)
- `2` — scan error (file not found, parse failure)

## Domains

- **CVE** — component vulnerabilities from NVD/EPSS/KEV (via asteraskills)
- **CWE** — source code weaknesses via AST taint analysis
- **POLICY** — IaC misconfigurations (AWS, GCP, Azure, Kubernetes)
- **ATTACK** — MITRE ATT&CK TTPs from SIEM logs via IoC + sequence correlation
- **FRAMEWORK** — SOC2/NIST/CIS/ISO27001 control gap assessment
