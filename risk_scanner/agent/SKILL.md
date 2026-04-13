# Risk Scanner

Scans security artifacts for CVE, CWE, ATT&CK, Policy, and Framework risks.
Each finding is enriched with the ATT&CK techniques it enables and the
framework controls (SOC2, NIST, CIS, ISO27001) that are violated or missing.

## Triggers

- `scan <path|url>` — scan a single artifact or directory
- `scan <path> --domain <cve|cwe|attack|policy|framework>` — constrain domain
- `scan <path> --frameworks <soc2,nist,cis>` — constrain frameworks
- `explain finding <finding-id>` — deep explanation of a specific finding
- `remediate finding <finding-id>` — generate remediation ticket
- `export <sarif|json|markdown|csv|html>` — export last scan result
- `correlate` — explain relationships across findings from last scan

## Inputs

Accepted artifact types:
- SBOM: CycloneDX JSON/XML, SPDX tag-value/JSON, Syft output
- Source: Python, JavaScript/TypeScript, Go, Bash, Rust
- IaC: Terraform HCL, CloudFormation YAML/JSON, Kubernetes YAML
- Logs/Alerts: SIEM JSON, CEF, Splunk export, generic JSONL
- Evidence: PDF, CSV, XLSX, config exports (JSON/YAML)

## Outputs

Each finding includes:
- Taxonomy code (CVE ID / CWE ID / ATT&CK technique / policy rule / control ID)
- Severity with rationale
- ATT&CK techniques enabled by this finding
- Framework control gaps (SOC2 / NIST 800-53 / CIS 8 / ISO 27001)
- Specific remediation steps
- Cross-references to related findings

## Follow-up turns

The skill maintains scan context across turns in the same session.
Users can ask:
- "Why is finding X HIGH and not MEDIUM?"
- "Show me only the ATT&CK findings"
- "What controls do I need to fix for SOC2?"
- "Generate a Jira ticket for finding RS-003"
- "Which finding should I fix first?"
- "Export this as SARIF for GitHub Actions"

## Configuration

Set via environment or `risk-scanner configure`:
- `RISK_SCANNER_LICENSE_TOKEN` — connects to intelligence server for richer rule packs
- `RISK_SCANNER_SERVER_URL` — default: https://api.risk-scanner.io
- `RISK_SCANNER_FRAMEWORKS` — comma-separated, default: all licensed
- `RISK_SCANNER_SEVERITY_THRESHOLD` — default: LOW
- `RISK_SCANNER_LLM_ENRICHMENT` — default: true

## Entry point

```python
from risk_scanner.agent.skill import run_scan, explain_finding, remediate_finding, export_result, correlate_findings
```

## Session management

```python
# Scan and store context for session "my-project"
result_summary = run_scan("/path/to/sbom.json", session_id="my-project")

# Follow-up in same session
ticket = remediate_finding("RS-A1B2C3D4", session_id="my-project")
sarif = export_result("sarif", session_id="my-project")
correlation = correlate_findings(session_id="my-project")
```
