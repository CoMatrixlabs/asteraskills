# SAST Finding Analyzer — Walkthrough & Example Outcomes

## Overview

The SAST Finding Analyzer skill triages findings from scanners like Wiz, Semgrep, and Checkmarx. It enriches each finding with CWE/CAPEC/ATT&CK intelligence, identifies missing context, asks targeted follow-up questions, and produces a verdict with actionable output.

### Files

| File | Purpose |
|------|---------|
| `app/asteraskills/tools/sast_finding_analyzer.py` | Core tool — enrichment, missing context detection, LLM analysis |
| `risk_scanner/core/prompts/prompt-18-sast-finding-analysis.md` | LLM prompt template with analysis framework and examples |
| `skills/sast-finding-analyzer/SKILL.md` | Skill orchestration — parsing, follow-up flow, verdict formatting |
| `app/asteraskills/tools/__init__.py` | Tool registry entry (`sast_finding_analyzer`) |
| `risk_scanner/core/prompts/__init__.py` | Prompt registry entry (`PROMPT-18`) |

### How It Works

```
User pastes SAST finding
        |
        v
Skill parses: CWE ID, code snippet, file path, description
        |
        v
Tool runs enrichment:
  1. CWE lookup (definition + linked CAPECs)
  2. CWE -> ATT&CK technique mappings
  3. CAPEC pattern details (up to 3)
        |
        v
Missing context detection (deterministic):
  - Data-flow CWEs -> need data_source_trust, sanitization_present
  - Access-control CWEs -> need authentication_required
  - All CWEs -> benefit from deployment_context
        |
        v
LLM analysis via PROMPT-18:
  - Applies 6-step analysis framework
  - Checks against common FP patterns
  - Returns verdict + confidence + reasoning
        |
        v
If missing_context present:
  Claude asks follow-up questions with "why it matters"
  User answers -> tool re-runs with context -> updated verdict
        |
        v
Final output: remediation (TP) or #wiz_ignore comment (FP)
```

---

## Example 1: CWE-472 — False Positive (Wiz)

### The Finding

**Source**: Wiz SAST scanner
**Rule**: WS-PYTHON-00333
**File**: `leen_kb/app/tools/cve_attack_mapper.py`
**Severity**: High
**CWE**: CWE-472 (Untrusted Data Poisoning Agent Memory)

**Flagged code:**
```python
rows = session.execute(
    text(f"""
        SELECT technique_id, tactic, confidence, mapping_source
        FROM cwe_technique_mappings
        WHERE cwe_id IN ({placeholders})
        ORDER BY confidence DESC
    """),
    params,
).fetchall()
seen: set = set()
results: List[Dict[str, Any]] = []
for r in rows:
    tid = (r[0] or "").strip().upper()
    tactic = (r[1] or "").strip().lower().replace(" ", "-")
    if not tid or not tactic:
        continue
    key = (tid, tactic)
    if key in seen:
        continue
    seen.add(key)
```

**Scanner description**: "This rule detects instances where untrusted data from external sources is directly stored in an AI agent's memory or context."

### Step 1: Initial Analysis (no context provided)

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "CWE-472",
  "code_snippet": "rows = session.execute(\n    text(f\"\"\"\n        SELECT technique_id, tactic, confidence, mapping_source\n        FROM cwe_technique_mappings\n        WHERE cwe_id IN ({placeholders})\n        ORDER BY confidence DESC\n    \"\"\"),\n    params,\n).fetchall()\nseen: set = set()\nresults: List[Dict[str, Any]] = []\nfor r in rows:\n    tid = (r[0] or \"\").strip().upper()\n    tactic = (r[1] or \"\").strip().lower().replace(\" \", \"-\")",
  "file_path": "leen_kb/app/tools/cve_attack_mapper.py",
  "sast_description": "Untrusted Data Poisoning Agent Memory",
  "sast_tool_name": "Wiz"
}'
```

**Expected result**: Verdict `inconclusive` because `data_source_trust` and `sanitization_present` are missing.

**Missing context questions returned:**

1. **Data source trust**: Where does the data in this code originate? Is it an internal database, external API, or user input?
   _This matters because data-flow vulnerabilities like CWE-472 are only exploitable when the data source can be influenced by an attacker._

2. **Sanitization**: Is there any input validation, sanitization, or parameterization applied to the data before it reaches this code?
   _Upstream sanitization can neutralize the attack vector entirely._

3. **Deployment context**: Is this code deployed in an internet-facing service, internal-only service, or air-gapped environment?

### Step 2: Re-analysis with User Context

User answers:
- Data source: Internal PostgreSQL database populated by MITRE ingestion pipelines
- Sanitization: Yes, SQL uses parameterized placeholders (`:c0`, `:c1`)
- Deployment: Internal service

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "CWE-472",
  "code_snippet": "...",
  "file_path": "leen_kb/app/tools/cve_attack_mapper.py",
  "sast_description": "Untrusted Data Poisoning Agent Memory",
  "sast_tool_name": "Wiz",
  "data_source_trust": "internal_db",
  "sanitization_present": true,
  "deployment_context": "internal_only",
  "additional_context": "The cwe_technique_mappings table is populated by trusted MITRE CWE/CAPEC/ATT&CK ingestion pipelines. Results are returned as structured tool output, not stored in LLM agent memory."
}'
```

### Expected Outcome

```
## Finding: FALSE POSITIVE (confidence: 0.88)

**CWE**: CWE-472 — External Control of Assumed-Immutable Web Parameter
**File**: leen_kb/app/tools/cve_attack_mapper.py
**Scanner**: Wiz

### Analysis

The code reads from cwe_technique_mappings, an internal PostgreSQL table
populated by trusted MITRE ingestion pipelines. The SQL uses parameterized
placeholders (:c0, :c1) preventing injection. Output values are normalized
(.strip().upper()) and deduplicated via a seen set before being returned as
a structured list. This data is returned as a tool result, not stored in
LLM agent memory or context.

CWE-472 requires externally controllable input influencing assumed-immutable
parameters, which does not apply here since the data source is a controlled
internal database.

### Key Factors

| Factor | Assessment | Impact |
|--------|-----------|--------|
| Data source | Internal PostgreSQL table populated by trusted MITRE data pipelines | positive_for_fp |
| SQL parameterization | Uses named placeholders (:c0, :c1) via SQLAlchemy text() | positive_for_fp |
| Output handling | Values stripped, normalized, deduplicated before return | positive_for_fp |
| Agent memory | Results returned as structured tool output, not persisted in agent memory | positive_for_fp |
| DB poisoning risk | Theoretical risk if ingestion pipeline is compromised, outside CWE-472 scope | neutral |

### Recommended Action

Suppress this finding with:

`#wiz_ignore CWE-472: internal DB read with parameterized SQL, not untrusted external input`

### Justification for Audit Trail

Data sourced from controlled internal cwe_technique_mappings table populated
by trusted MITRE ingestion pipelines, not untrusted external input. SQL is
parameterized. Output is structured tool data returned to caller, not stored
in agent memory.

### Residual Risk

If the ingestion pipeline were compromised, poisoned ATT&CK mappings could
propagate incorrect technique associations. Mitigated by pipeline integrity
checks and data validation at ingestion time.
```

---

## Example 2: CWE-89 — True Positive (Semgrep)

### The Finding

**Source**: Semgrep
**File**: `app/api/users.py`
**Severity**: Critical
**CWE**: CWE-89 (SQL Injection)

**Flagged code:**
```python
query = f"SELECT * FROM users WHERE name = '{request.args.get('name')}'"
cursor.execute(query)
```

**Scanner description**: "SQL Injection via string formatting"

### Analysis (with context)

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "CWE-89",
  "code_snippet": "query = f\"SELECT * FROM users WHERE name = '\''{request.args.get('\''name'\'')}'\''\"\ncursor.execute(query)",
  "file_path": "app/api/users.py",
  "sast_description": "SQL Injection via string formatting",
  "sast_tool_name": "Semgrep",
  "data_source_trust": "user_input",
  "deployment_context": "internet_facing"
}'
```

### Expected Outcome

```
## Finding: TRUE POSITIVE (confidence: 0.96)

**CWE**: CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
**File**: app/api/users.py
**Scanner**: Semgrep

### Analysis

The code constructs a SQL query using f-string interpolation with
request.args.get('name'), which is direct user input from HTTP query
parameters. No parameterization, escaping, or input validation is present.
The deployment context is internet-facing, making this directly exploitable
by any HTTP client.

### Key Factors

| Factor | Assessment | Impact |
|--------|-----------|--------|
| Data source | Direct HTTP query parameter (request.args) | positive_for_tp |
| SQL construction | f-string interpolation, no parameterization | positive_for_tp |
| Input validation | None present | positive_for_tp |
| Deployment | Internet-facing endpoint | positive_for_tp |

### ATT&CK Mapping

| Technique | Tactic |
|-----------|--------|
| T1190 — Exploit Public-Facing Application | initial-access |
| T1059 — Command and Scripting Interpreter | execution |

### Remediation

Replace f-string SQL with parameterized query:

```python
cursor.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
```

Or use an ORM query builder to avoid raw SQL entirely.

### Risk If Ignored

Direct SQL injection on an internet-facing endpoint. Attacker can extract,
modify, or delete database contents, potentially escalating to OS command
execution depending on DB privileges.
```

---

## Example 3: CWE-502 — Inconclusive (Checkmarx)

### The Finding

**Source**: Checkmarx
**File**: `app/workers/task_handler.py`
**Severity**: High
**CWE**: CWE-502 (Deserialization of Untrusted Data)

**Flagged code:**
```python
data = pickle.loads(payload)
process_result(data)
```

**Scanner description**: "Deserialization of untrusted data"

### Analysis (no context)

```bash
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "CWE-502",
  "code_snippet": "data = pickle.loads(payload)\nprocess_result(data)",
  "file_path": "app/workers/task_handler.py",
  "sast_description": "Deserialization of untrusted data",
  "sast_tool_name": "Checkmarx"
}'
```

### Expected Outcome

```
## Finding: INCONCLUSIVE (confidence: 0.35)

**CWE**: CWE-502 — Deserialization of Untrusted Data
**File**: app/workers/task_handler.py

### Analysis

pickle.loads() is inherently dangerous as it can execute arbitrary code
during deserialization. However, without knowing the source of 'payload',
we cannot determine if this is exploitable. If payload comes from a trusted
internal message queue with authenticated producers, the risk is lower. If
it comes from user-uploaded files or external APIs, this is a critical
vulnerability.

### What Would Change the Verdict

- **If payload comes from user input or external API** -> TRUE POSITIVE
  (confidence ~0.95). pickle.loads with attacker-controlled data is RCE.
- **If payload comes from an internal message queue with authenticated,
  trusted producers** -> still recommend replacing pickle with a safer
  format (JSON, msgpack), but lower urgency.
- **If payload comes from a signed/encrypted internal cache** -> FALSE
  POSITIVE, but consider defense in depth.

### CWE/ATT&CK Context

| Technique | Tactic |
|-----------|--------|
| T1059 — Command and Scripting Interpreter | execution |
| T1203 — Exploitation for Client Execution | execution |

### CAPEC Patterns

- CAPEC-586: Object Injection — attacker supplies crafted serialized object
  to achieve arbitrary code execution during deserialization.
```

### Follow-up

After the user confirms "payload comes from an internal Redis queue, producers are authenticated microservices", re-running with `data_source_trust: "internal_db"` and `authentication_required: true` would shift the verdict toward **false positive** with a recommendation to still migrate away from pickle for defense in depth.

---

## Running the Skill

### Via CLI

```bash
# Single tool run
asteraskills run sast_finding_analyzer --args '{
  "cwe_id": "CWE-472",
  "code_snippet": "<code>",
  "file_path": "<path>",
  "sast_description": "<description>"
}'

# Verify tool is registered
asteraskills list | grep sast
asteraskills doctor
```

### Via Claude Code Skill

Paste a SAST finding into Claude Code and it will automatically trigger the `sast-finding-analyzer` skill. The skill handles:

1. Parsing the finding from natural language or structured paste
2. Running the initial analysis
3. Asking follow-up questions if context is missing
4. Re-running with context and formatting the final verdict
