---
id: PROMPT-08
name: CWE to ATT&CK Technique Mapper
stage: enrichment
used_by: risk_scanner/core/enrichment/cwe_enricher.py
variables:
  cwe_id: CWE identifier string (e.g. CWE-89)
  cwe_name: Official CWE name (e.g. Improper Neutralization of Special Elements used in an SQL Command)
  source_type: Category of taint source (http_param, env_var, file_read, db_read, user_input)
  sink_type: Category of dangerous sink (network, filesystem, subprocess, eval, database, reflection)
  sink_expression: The actual code expression at the sink
  cross_file: Boolean string indicating whether taint crosses file boundaries
  retrieved_mappings: Embedding-matched CWE-to-technique mapping examples from the enrichment index
---

SYSTEM
You are a threat intelligence enrichment analyst specializing in mapping software
weaknesses to adversary techniques. Your job is to determine which ATT&CK
techniques a CWE weakness enables in the specific taint chain context provided.

Return ONLY valid JSON matching the output schema.

OUTPUT SCHEMA
{{
  "enabled_techniques": [
    {{
      "technique_id": "<T-NNNN.NNN>",
      "technique_name": "<name>",
      "tactic": "<tactic>",
      "tactic_id": "<TA-NNNN>",
      "kill_chain_pos": <1-N>,
      "likelihood": "<high|medium|low>",
      "exploit_path": "<one sentence: how attacker reaches this sink>",
      "confidence": <0.0-1.0>,
      "rationale": "<2 sentences>"
    }}
  ],
  "attack_narrative": "<3-4 sentences describing exploitation of this weakness>"
}}

RULES
- CWE-89 (SQLi) maps primarily to T1190 and T1005. Do not add speculative techniques.
- CWE-78 (OS Command Injection) maps to T1059 and likely privilege escalation.
- CWE-312 (Cleartext Storage) maps to T1552 and T1078.
- Use sub-technique IDs where the taint chain provides sufficient specificity.
- Limit to 4 techniques maximum.

CWE FINDING
cwe_id: {cwe_id}
cwe_name: {cwe_name}
source_type: {source_type}
sink_type: {sink_type}
sink_expression: {sink_expression}
cross_file: {cross_file}

RETRIEVED CWE->TECHNIQUE MAPPINGS
{retrieved_mappings}

<!-- DOCS_START -->
## Examples

### Example 1 — CWE-89 SQL Injection from HTTP parameter into database query

**Input variables:**
```
cwe_id: CWE-89
cwe_name: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
source_type: http_param
sink_type: database
sink_expression: cursor.execute("SELECT * FROM orders WHERE user_id = '" + user_id + "' AND status = '" + status + "'")
cross_file: true
retrieved_mappings: [{"cwe":"CWE-89","techniques":["T1190","T1005","T1565.001"]},{"cwe":"CWE-564","techniques":["T1190","T1005"]}]
```

**Expected output:**
```json
{
  "enabled_techniques": [
    {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "tactic_id": "TA0001",
      "kill_chain_pos": 1,
      "likelihood": "high",
      "exploit_path": "Attacker sends an HTTP request with a crafted user_id parameter containing SQL metacharacters (e.g. ' OR '1'='1) that are interpolated directly into the query string.",
      "confidence": 0.97,
      "rationale": "The HTTP parameter source with no sanitization flowing into string-concatenated SQL is the canonical SQL injection exploit path for web applications. Cross-file taint propagation increases the likelihood this bypasses any input validation at the route layer."
    },
    {
      "technique_id": "T1005",
      "technique_name": "Data from Local System",
      "tactic": "Collection",
      "tactic_id": "TA0009",
      "kill_chain_pos": 2,
      "likelihood": "high",
      "exploit_path": "Attacker uses UNION SELECT or batched queries to enumerate and dump table contents beyond the orders table, including users, credentials, and PII.",
      "confidence": 0.93,
      "rationale": "SQL injection in an orders query with two injectable parameters enables UNION-based data extraction from any table accessible to the database user. The multi-parameter injection surface provides flexibility for blind and error-based enumeration."
    },
    {
      "technique_id": "T1565.001",
      "technique_name": "Data Manipulation: Stored Data Manipulation",
      "tactic": "Impact",
      "tactic_id": "TA0040",
      "kill_chain_pos": 3,
      "likelihood": "medium",
      "exploit_path": "Attacker uses stacked queries or UPDATE injection to modify order records, user account data, or application configuration stored in the database.",
      "confidence": 0.78,
      "rationale": "If the database user has INSERT/UPDATE permissions (common for application service accounts), SQL injection can be escalated from read-only exfiltration to data manipulation. Impact on order integrity could have direct business consequences."
    }
  ],
  "attack_narrative": "An attacker targeting the orders API submits a crafted user_id parameter containing SQL injection syntax that bypasses the application's query logic and executes attacker-controlled SQL against the database. Using UNION-based injection, the attacker enumerates the full database schema and extracts all records from the users and payment_methods tables across file boundaries. If the application database account has write permissions, the attacker can modify order records or user credentials, potentially escalating to full application compromise. The cross-file taint path means any input validation at the API route layer does not reach the query execution site."
}
```

### Example 2 — CWE-312 Cleartext Storage of credentials in config file

**Input variables:**
```
cwe_id: CWE-312
cwe_name: Cleartext Storage of Sensitive Information
source_type: db_read
sink_type: filesystem
sink_expression: open('config/database.yml', 'w').write('password: ' + db_password)
cross_file: false
retrieved_mappings: [{"cwe":"CWE-312","techniques":["T1552.001","T1078"]},{"cwe":"CWE-256","techniques":["T1552","T1078.002"]}]
```

**Expected output:**
```json
{
  "enabled_techniques": [
    {
      "technique_id": "T1552.001",
      "technique_name": "Unsecured Credentials: Credentials In Files",
      "tactic": "Credential Access",
      "tactic_id": "TA0006",
      "kill_chain_pos": 1,
      "likelihood": "high",
      "exploit_path": "Attacker with filesystem read access (via path traversal, SSRF to file:// URIs, or compromised account) reads config/database.yml to obtain cleartext database credentials.",
      "confidence": 0.96,
      "rationale": "The sink expression writes a database password in plaintext to a YAML config file, making credential theft trivially easy for any actor with filesystem access. YAML config files are frequently included in version control or backup archives, widening the exposure surface."
    },
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "tactic": "Persistence",
      "tactic_id": "TA0003",
      "kill_chain_pos": 2,
      "likelihood": "high",
      "exploit_path": "Attacker uses stolen plaintext database credentials to authenticate directly to the database server, bypassing application-layer controls.",
      "confidence": 0.89,
      "rationale": "Cleartext database credentials enable direct database login using valid account credentials, providing persistent access independent of application session management. Direct database access exposes all data and potentially enables stacked queries or administrative commands."
    }
  ],
  "attack_narrative": "A database password is written in plaintext to config/database.yml during application initialization, persisting the credential in a human-readable file on the filesystem. Any attacker who achieves filesystem read access — via a separate path traversal vulnerability, an exposed backup, or accidental version control commit — immediately obtains valid database credentials without needing to crack a hash. The attacker authenticates directly to the database server using these valid credentials, gaining persistent access to all application data. This credential exposure also makes incident response difficult, as the attacker can re-authenticate even after application-layer sessions are revoked."
}
```

## Customization

> **How to adapt this prompt:**
> - The three hardcoded CWE mapping rules (CWE-89, CWE-78, CWE-312) are anchor examples — add similar rules for your most common CWEs (e.g. "CWE-22 (Path Traversal) maps to T1083 and T1005").
> - To add programming-language-specific sub-technique mapping (e.g. CWE-78 in Python maps to T1059.006 rather than T1059), add a `language` variable to the CWE FINDING block and a corresponding rule.
> - To use the `cross_file` flag for confidence adjustments, add a rule: "cross_file=true increases confidence by 0.05 for T1190 since it suggests the injection bypasses route-level input validation."
> - To generate remediation-linked output, extend the output schema with a `remediation_hint` field per technique and populate it with framework-specific fix guidance (e.g. parameterized queries for CWE-89).
> - The 4-technique maximum is intentional to prevent over-speculation — increase it only for complex multi-stage weaknesses like CWE-502 (Deserialization) where the technique chain is genuinely long.
