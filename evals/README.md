# Evals

The eval runner mechanism is open source. Ground-truth eval corpora require a license token.

## Running Evals

```bash
# Single assertion file
python -m evals.runner --assertion evals/assertions/my_sbom.yaml

# All assertion files in a directory
python -m evals.runner --assertions evals/assertions/

# JSON output for CI
python -m evals.runner --assertions evals/assertions/ --json
```

## Writing Assertion Files

Each assertion file is a YAML document:

```yaml
fixture_path: tests/fixtures/sbom-example.json
description: CycloneDX SBOM with CVE-2024-3400
domain_override: cve
assertions:
  - taxonomy_code: CVE-2024-3400
    domain: cve
    severity_min: HIGH
    has_technique: T1190
    control_framework: nist-800-53
```

### Assertion Fields

| Field | Description |
|-------|-------------|
| `taxonomy_code` | Required. CVE-YYYY-NNNNN, CWE-NNN, T-NNNN, policy rule ID |
| `domain` | Exact domain: cve/cwe/attack/policy/framework |
| `severity` | Exact severity: CRITICAL/HIGH/MEDIUM/LOW |
| `severity_min` | Minimum severity (>= this level) |
| `confidence_min` | Minimum confidence (0.0–1.0) |
| `has_technique` | ATT&CK technique ID that must be in the finding's attack_chain |
| `has_tactic` | ATT&CK tactic that must be in the finding's attack_chain |
| `control_framework` | Framework that must appear in control_gaps |
| `control_id` | Specific control ID that must appear in control_gaps |
| `not_suppressed` | Finding must not be in the suppressed list (default: true) |
| `min_analyzer_sources` | Minimum number of analyzer sources (default: 1) |

## Ground-Truth Corpus

A curated corpus of ~500 labeled fixtures (SBOMs, IaC templates, source files, log samples) with verified assertions is available on the licensed intelligence server. Contact us for access.
