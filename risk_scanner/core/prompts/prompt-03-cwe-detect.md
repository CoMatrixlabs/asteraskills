---
id: PROMPT-03
name: CWE Taxonomy Resolver
stage: detection
used_by: risk_scanner/core/detection/cwe_detector.py
variables:
  source_file: Relative path to the file where tainted data originates
  source_line: Line number of the taint source
  source_type: Category of taint source (http_param, env_var, file_read, db_read, user_input)
  sink_file: Relative path to the file containing the dangerous sink
  sink_line: Line number of the sink expression
  sink_expression: The actual code expression at the sink (e.g. cursor.execute(query))
  intermediate_vars: Comma-separated list of variable names carrying the taint between source and sink
  cross_file: Boolean string ("true"/"false") indicating whether taint crosses file boundaries
  retrieved_cwe_signals: Embedding-matched CWE examples retrieved from the pack index
---

SYSTEM
You are a CWE taxonomy resolver. You will receive a source-sink taint chain
extracted from static AST dataflow analysis. Your job is to assign the most
precise CWE ID from the CWE-1000 Research View.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "cwe_id": "<CWE-NNN>",
  "cwe_name": "<official CWE name>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "severity_rationale": "<2 sentences referencing the specific taint chain>",
  "sink_type": "<network|filesystem|subprocess|eval|database|reflection>",
  "source_type": "<http_param|env_var|file_read|db_read|user_input>",
  "exploitability": "<local|network|adjacent>",
  "confidence": <0.0-1.0>,
  "alternative_cwes": ["<CWE-NNN>"]
}}

RULES
- Prefer the most specific CWE child over a parent pillar (e.g. CWE-89 over CWE-74).
- alternative_cwes: include up to 2 alternatives if confidence < 0.85.
- Do not assign CWE-other or CWE-noinfo.
- severity must be consistent with CVSS exploitability and impact of this sink type.

TAINT CHAIN
source_file: {source_file}
source_line: {source_line}
source_type: {source_type}
sink_file: {sink_file}
sink_line: {sink_line}
sink_expression: {sink_expression}
intermediate_vars: {intermediate_vars}
cross_file: {cross_file}

RETRIEVED CWE PACK SIGNALS
{retrieved_cwe_signals}

<!-- DOCS_START -->
## Examples

### Example 1 — HTTP parameter flows unsanitized into SQL query

**Input variables:**
```
source_file: app/routes/users.py
source_line: 23
source_type: http_param
sink_file: app/db/queries.py
sink_line: 87
sink_expression: cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
intermediate_vars: username, query_str
cross_file: true
retrieved_cwe_signals: [{"cwe_id":"CWE-89","name":"SQL Injection","example":"Flask route param concatenated into raw SQL"},{"cwe_id":"CWE-74","name":"Improper Neutralization of Special Elements in Output Used by a Downstream Component"}]
```

**Expected output:**
```json
{
  "cwe_id": "CWE-89",
  "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "severity": "CRITICAL",
  "severity_rationale": "HTTP parameter `username` from users.py:23 flows across two files into a raw string-concatenated SQL query at queries.py:87 with no parameterization or sanitization. Network-exploitable SQL injection against a user table enables authentication bypass, data exfiltration, and potentially stacked queries for persistence.",
  "sink_type": "database",
  "source_type": "http_param",
  "exploitability": "network",
  "confidence": 0.97,
  "alternative_cwes": []
}
```

### Example 2 — Environment variable flows into subprocess shell call

**Input variables:**
```
source_file: scripts/deploy.py
source_line: 14
source_type: env_var
sink_file: scripts/deploy.py
sink_line: 41
sink_expression: subprocess.call("deploy.sh " + os.environ['TARGET_HOST'], shell=True)
intermediate_vars: target_host, cmd
cross_file: false
retrieved_cwe_signals: [{"cwe_id":"CWE-78","name":"OS Command Injection","example":"env var passed to shell=True subprocess"},{"cwe_id":"CWE-88","name":"Argument Injection or Modification"}]
```

**Expected output:**
```json
{
  "cwe_id": "CWE-78",
  "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  "severity": "HIGH",
  "severity_rationale": "Environment variable TARGET_HOST flows directly into a shell=True subprocess call at deploy.py:41 without sanitization, enabling OS command injection if an attacker can control environment variables at runtime. While typically requiring local access to set environment variables, CI/CD pipeline injection or container escape scenarios make this HIGH severity in a deployment context.",
  "sink_type": "subprocess",
  "source_type": "env_var",
  "exploitability": "local",
  "confidence": 0.93,
  "alternative_cwes": ["CWE-88"]
}
```

### Example 3 — User-supplied path flows into file read (path traversal)

**Input variables:**
```
source_file: api/files.py
source_line: 9
source_type: http_param
sink_file: api/files.py
sink_line: 22
sink_expression: open(base_dir + "/" + request.args.get('filename'), 'r')
intermediate_vars: filename, filepath
cross_file: false
retrieved_cwe_signals: [{"cwe_id":"CWE-22","name":"Path Traversal","example":"filename param used in open() without normalization"},{"cwe_id":"CWE-73","name":"External Control of File Name or Path"}]
```

**Expected output:**
```json
{
  "cwe_id": "CWE-22",
  "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  "severity": "HIGH",
  "severity_rationale": "HTTP parameter `filename` is directly concatenated with a base directory and passed to open() at files.py:22 with no path normalization or containment check, enabling traversal to arbitrary files (e.g. ../../etc/passwd). Network-exploitable without authentication in a typical API context.",
  "sink_type": "filesystem",
  "source_type": "http_param",
  "exploitability": "network",
  "confidence": 0.95,
  "alternative_cwes": ["CWE-73"]
}
```

## Customization

> **How to adapt this prompt:**
> - To add language-specific sink patterns, extend the `TAINT CHAIN` block with a `language` field and add language-aware rules (e.g. "For Python, `eval()` with http_param is always CWE-95 with HIGH confidence").
> - To tune specificity vs. breadth, adjust the `confidence < 0.85` threshold for `alternative_cwes` — lower it to always include alternatives, raise it to only include them for truly ambiguous cases.
> - To integrate with a custom CWE profile (e.g. OWASP Top 10 subset), add a rule: "If the CWE is not in the following list {allowed_cwes}, map to the nearest parent in that list."
> - The `retrieved_cwe_signals` variable is the primary quality lever — richer pack examples with diverse language/framework coverage directly improve precision.
> - To handle framework-specific injection sinks (e.g. Django ORM, SQLAlchemy), add a `framework` variable and rule: "Django ORM `.raw()` with user input is CWE-89; `.filter()` with user input is LOW confidence CWE-89."
