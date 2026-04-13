---
name: sast-finding-analyzer
description: Use when the user provides a SAST finding (code snippet + CWE ID + scanner description) and wants to determine whether it is a true positive, false positive, or inconclusive. Triggers on phrases like "analyze this SAST finding", "is this a false positive", "triage this CWE finding", "should I ignore this Wiz finding", "review this security scan result", or when a Wiz/Semgrep/Checkmarx finding is pasted with a CWE reference.
---

# SAST Finding Analyzer

Triage SAST scanner findings by enriching with CWE/CAPEC/ATT&CK intelligence and applying LLM-powered code analysis. Produces a verdict (true positive, false positive, or inconclusive) with actionable output.

## Prerequisites

```bash
cd /path/to/Lexy/asteraskills
pip install -e ".[runtime]"
asteraskills doctor   # verify registry loads
```

Environment: Postgres connection vars for CWE/CAPEC tables (optional — enrichment degrades gracefully). LLM API key (required for verdict, enrichment works without it).

## Workflow

### Step 1 — Parse the SAST finding from user input

Extract these fields from what the user provides:

| Field | Required | Example |
|-------|----------|---------|
| `cwe_id` | Yes | `CWE-472` |
| `code_snippet` | Yes | The flagged code block |
| `file_path` | Yes | `app/tools/cve_attack_mapper.py` |
| `sast_description` | Yes | `Untrusted Data Poisoning Agent Memory` |
| `sast_tool_name` | No | `Wiz`, `Semgrep`, `Checkmarx` |
| `line_number` | No | `200` |

If the user also provides context about data sources, sanitization, deployment, or authentication, capture those too as optional fields (`data_source_trust`, `sanitization_present`, `deployment_context`, `authentication_required`, `additional_context`).

If any **required** field is missing, ask the user before proceeding.

### Step 2 — Initial analysis

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "<CWE-ID>",
  "code_snippet": "<the flagged code>",
  "file_path": "<path>",
  "sast_description": "<scanner finding title>",
  "sast_tool_name": "<tool name>"
}'
```

Include any optional context fields the user already provided.

### Step 3 — Handle missing context

Check the `missing_context` array in the tool result. If it contains items, **ask the user each question** before re-analyzing. Present them as a numbered list with explanations:

> To give you a more accurate verdict, I need a few more details:
>
> 1. **Data source trust**: Where does the data in this code come from? Is it an internal database, external API, or user input?
>    _This matters because data-flow vulnerabilities are only exploitable when the data source can be influenced by an attacker._
>
> 2. **Sanitization**: Is there any input validation or sanitization applied before this code runs?
>    _Upstream sanitization can neutralize the attack vector entirely._

Do not ask more than 4 questions at once. Prioritize `data_source_trust` and `sanitization_present` for data-flow CWEs.

### Step 4 — Re-analyze with context

Once the user answers, re-run the tool with the additional context fields populated:

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "<CWE-ID>",
  "code_snippet": "<code>",
  "file_path": "<path>",
  "sast_description": "<description>",
  "sast_tool_name": "<tool>",
  "data_source_trust": "<user answer>",
  "sanitization_present": <true|false>,
  "deployment_context": "<user answer>",
  "authentication_required": <true|false>,
  "additional_context": "<any extra notes from user>"
}'
```

### Step 5 — Present verdict

Format the final output based on the verdict field:

#### If TRUE POSITIVE

```
## Finding: TRUE POSITIVE (confidence: X.XX)

**CWE**: CWE-NNN — <name>
**File**: <path>:<line>
**Scanner**: <tool name>

### Analysis
<reasoning from the tool>

### Key Factors
| Factor | Assessment | Impact |
|--------|-----------|--------|
| ... | ... | ... |

### ATT&CK Mapping
<technique IDs and tactics from attack_mappings>

### Remediation
<remediation guidance from the tool>

### Risk If Ignored
<risk_if_wrong from the tool>
```

#### If FALSE POSITIVE

```
## Finding: FALSE POSITIVE (confidence: X.XX)

**CWE**: CWE-NNN — <name>
**File**: <path>:<line>
**Scanner**: <tool name>

### Analysis
<reasoning from the tool>

### Key Factors
| Factor | Assessment | Impact |
|--------|-----------|--------|
| ... | ... | ... |

### Recommended Action
Suppress this finding with:

`#wiz_ignore <wiz_ignore_comment from tool>`

### Justification for Audit Trail
<ignore_justification from tool>

### Residual Risk
<risk_if_wrong — what to monitor even after suppression>
```

#### If INCONCLUSIVE

```
## Finding: INCONCLUSIVE (confidence: X.XX)

**CWE**: CWE-NNN — <name>
**File**: <path>:<line>

### Analysis
<reasoning — what is known and what is not>

### What Would Change the Verdict
<specific information needed, and in which direction it would push the verdict>

### CWE/ATT&CK Context
<enrichment data for manual review>
```

## Fallback Handling

- If `sast_finding_analyzer` errors on LLM call, the enrichment data (CWE definition, CAPEC patterns, ATT&CK mappings) is still returned. Present the enrichment and reason through the analysis using the data directly.
- If `cwe_lookup` returns no data for the CWE ID (table missing or CWE not ingested), note the gap and proceed with whatever the SAST description provides.
- If the user provides more context after the initial verdict, re-run the analysis — the verdict may change.

## Rules

- Never declare a finding as false positive without examining the actual code pattern against the CWE definition.
- Always disclose confidence level and what could change the verdict.
- When data comes from a database, always note that database poisoning is a theoretical risk even for internal DBs.
- Prefer tool outputs over speculation. Label any inference clearly.
- If the user pastes a Wiz finding, extract the CWE ID from the finding metadata and the code from the "Code examples" section.
- For `#wiz_ignore` comments, always include the CWE ID and a concise reason.
