---
id: PROMPT-14
name: Remediation Ticket Generator
stage: agent
used_by: risk_scanner/core/agent/ticket_generator.py
variables:
  severity: Final severity string (CRITICAL, HIGH, MEDIUM, LOW)
  severity_rationale: The severity_rationale from PROMPT-11 severity contextualization
  taxonomy_code: The taxonomy identifier for the finding (e.g. CVE-2021-44228, CWE-89, T1190, S3-001)
  evidence_location: File path and line number, or cloud resource identifier where the finding was detected
  techniques: Comma-separated list of ATT&CK technique IDs enabled by this finding
  control_ids: Comma-separated list of framework control IDs that are missing or partial
  finding_json: Complete JSON object for this finding including all enrichments
---

SYSTEM
You are a security remediation assistant. Generate a well-structured remediation
ticket for the finding provided. The ticket must be directly actionable by an
engineer with no prior context.

OUTPUT FORMAT: Markdown ticket body

SECTIONS REQUIRED
## Summary
One sentence: what is wrong and where.

## Severity
{severity} — {severity_rationale}

## Finding Detail
- Taxonomy code: {taxonomy_code}
- File / resource: {evidence_location}
- ATT&CK techniques enabled: {techniques}
- Control gaps: {control_ids}

## Reproduction
Step-by-step how to reproduce or observe the issue.

## Remediation Steps
Numbered, specific, testable steps. Include code snippets where applicable.

## Acceptance Criteria
Bullet list of what must be true for this ticket to be closed.
Include: re-scan command that should return no findings for this rule.

## References
- Taxonomy link
- ATT&CK technique links
- Framework control links

FINDING
{finding_json}

<!-- DOCS_START -->
## Examples

### Example 1 — CVE-2021-44228 Log4Shell remediation ticket

**Input variables:**
```
severity: CRITICAL
severity_rationale: Log4Shell is a CVSS 10.0 RCE in log4j-core@2.14.1 exposed via HTTP in production; ATT&CK mapping confirms T1190 (Initial Access) and T1059.007 (Execution) are enabled with no preventive control satisfied for the execution stage.
taxonomy_code: CVE-2021-44228
evidence_location: pom.xml:18 (dependency declaration), runtime: com.example.api.RequestProcessor:47
techniques: T1190, T1059.007, T1105, T1078.004
control_ids: CC6.6, CIS-7.3
finding_json: {"finding_id":"F-001","taxonomy_code":"CVE-2021-44228","component":"log4j-core@2.14.1","final_severity":"CRITICAL","risk_score":95,"reachable":true,"reachability_note":"User-controlled X-Forwarded-For header reaches Logger.getLogger() at RequestProcessor:47"}
```

**Expected output (Markdown):**

---

## Summary

`log4j-core@2.14.1` is affected by Log4Shell (CVE-2021-44228), a CVSS 10.0 unauthenticated remote code execution vulnerability reachable via the X-Forwarded-For header logged at `RequestProcessor.java:47`.

## Severity

**CRITICAL** — Log4Shell is a CVSS 10.0 RCE in log4j-core@2.14.1 exposed via HTTP in production; ATT&CK mapping confirms T1190 (Initial Access) and T1059.007 (Execution) are enabled with no preventive control satisfied for the execution stage.

## Finding Detail

- **Taxonomy code:** CVE-2021-44228
- **File / resource:** `pom.xml:18` (dependency), `com/example/api/RequestProcessor.java:47` (reachable sink)
- **ATT&CK techniques enabled:** T1190 (Exploit Public-Facing Application), T1059.007 (JavaScript/JScript), T1105 (Ingress Tool Transfer), T1078.004 (Valid Accounts: Cloud Accounts)
- **Control gaps:** CC6.6 (patch management SLA not met), CIS-7.3 (patch automation — partially satisfied)

## Reproduction

1. Start the application locally: `./gradlew bootRun`
2. Send a request with a JNDI lookup string in the X-Forwarded-For header:
   ```
   curl -H 'X-Forwarded-For: ${jndi:ldap://127.0.0.1:1389/a}' http://localhost:8080/api/users
   ```
3. Observe the application attempting an outbound LDAP connection (visible in network logs or a local netcat listener on port 1389).
4. Confirm the application version: `grep log4j pom.xml` should show `2.14.1`.

## Remediation Steps

1. **Upgrade log4j-core** in `pom.xml` from `2.14.1` to `2.17.1` (minimum safe version):
   ```xml
   <dependency>
     <groupId>org.apache.logging.log4j</groupId>
     <artifactId>log4j-core</artifactId>
     <version>2.17.1</version>
   </dependency>
   ```
2. **Apply interim JVM mitigation** (add to application startup flags until upgrade is deployed):
   ```
   -Dlog4j2.formatMsgNoLookups=true
   ```
3. **Update all log4j transitive dependencies**: run `./gradlew dependencyInsight --dependency log4j-core` to find all paths and update any that pin an older version.
4. **WAF rule**: add the following WAF rule to block JNDI injection patterns at the edge: `${jndi:`, `${${lower:j}ndi:`, `%24%7Bjndi%3A`.
5. **Rebuild and redeploy** the application after step 1 and verify the new version in the startup log: `grep -i "log4j" application.log | grep version`.

## Acceptance Criteria

- [ ] `pom.xml` contains `log4j-core` version `2.17.1` or later
- [ ] No `log4j-core` version below `2.17.0` appears in `./gradlew dependencies --configuration runtimeClasspath`
- [ ] Re-scan returns no CVE-2021-44228 finding: `risk-scanner scan --artifact pom.xml --rule CVE-2021-44228`
- [ ] WAF blocks the reproduction curl command in step 2 with HTTP 403
- [ ] Patch deployment is documented in the change management system

## References

- [CVE-2021-44228 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1059.007 — Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [CC6.6 — SOC 2 Logical Access Security](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservices)
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)

---

### Example 2 — CWE-89 SQL Injection remediation ticket

**Input variables:**
```
severity: HIGH
severity_rationale: Network-exploitable SQL injection at queries.py:87 enables customer data exfiltration via T1005; missing CIS-16.1 preventive control means no framework-level input validation exists.
taxonomy_code: CWE-89
evidence_location: app/db/queries.py:87
techniques: T1190, T1005, T1565.001
control_ids: CIS-16.1, A.14.2.5
finding_json: {"finding_id":"F-003","taxonomy_code":"CWE-89","file_path":"app/db/queries.py","line_start":85,"line_end":89,"sink_expression":"cursor.execute(\"SELECT * FROM orders WHERE user_id = '\" + user_id + \"'\")", "source_type":"http_param","final_severity":"HIGH","risk_score":72}
```

**Expected output (Markdown):**

---

## Summary

HTTP parameter `user_id` flows unsanitized into a raw SQL string concatenation at `app/db/queries.py:87`, enabling unauthenticated SQL injection against the orders database.

## Severity

**HIGH** — Network-exploitable SQL injection at `queries.py:87` enables customer data exfiltration via T1005; missing CIS-16.1 preventive control means no framework-level input validation exists.

## Finding Detail

- **Taxonomy code:** CWE-89 (SQL Injection)
- **File / resource:** `app/db/queries.py:87`
- **ATT&CK techniques enabled:** T1190 (Exploit Public-Facing Application), T1005 (Data from Local System), T1565.001 (Stored Data Manipulation)
- **Control gaps:** CIS-16.1 (no input validation framework), A.14.2.5 (no secure coding standard requiring parameterized queries)

## Reproduction

1. Identify the vulnerable endpoint: `grep -r "user_id" app/routes/` to find the route calling `queries.py`.
2. Send a request with a SQL injection payload in the `user_id` parameter:
   ```
   curl "http://localhost:8000/api/orders?user_id=' OR '1'='1"
   ```
3. Observe that the response returns orders for all users, not just the specified user_id.
4. Confirm exfiltration potential with a UNION probe:
   ```
   curl "http://localhost:8000/api/orders?user_id=' UNION SELECT table_name,null,null FROM information_schema.tables--"
   ```

## Remediation Steps

1. **Replace string concatenation with parameterized queries** at `queries.py:87`:
   ```python
   # BEFORE (vulnerable)
   cursor.execute("SELECT * FROM orders WHERE user_id = '" + user_id + "' AND status = '" + status + "'")

   # AFTER (safe)
   cursor.execute(
       "SELECT * FROM orders WHERE user_id = %s AND status = %s",
       (user_id, status)
   )
   ```
2. **Audit all other query construction** in `app/db/`: run `grep -n "execute(" app/db/*.py` and verify no other raw string concatenation exists.
3. **Add a linting rule** to prevent future regressions: install `bandit` and add `bandit -r app/ -t B608` to your CI pipeline. B608 detects hardcoded SQL injection patterns.
4. **Apply principle of least privilege** to the database user: ensure the application database account cannot execute DDL statements (`CREATE`, `DROP`, `ALTER`) and cannot access tables outside the application schema.

## Acceptance Criteria

- [ ] `queries.py:87` uses parameterized queries (no string concatenation with user input)
- [ ] `bandit -r app/ -t B608` returns exit code 0 with no B608 findings
- [ ] Re-scan returns no CWE-89 finding for this file: `risk-scanner scan --artifact app/ --rule CWE-89`
- [ ] The reproduction curl command in step 2 returns a 400 error or empty result set, not all orders

## References

- [CWE-89 — SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [CIS Control 16.1 — Establish Secure Coding Practices](https://www.cisecurity.org/controls/application-software-security)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

---

## Customization

> **How to adapt this prompt:**
> - To integrate with Jira, wrap the generated Markdown in a Jira API call and add a `jira_project_key` variable that populates the ticket's project and assignee fields.
> - To add SLA due dates, inject the current date as a variable and add a rule: "Add a 'Due Date' field after Severity: CRITICAL = today + 1 business day, HIGH = today + 5 business days, MEDIUM = today + 30 days."
> - To customize the re-scan command in Acceptance Criteria, replace the generic `risk-scanner scan` command with your actual CLI invocation pattern.
> - To generate tickets in a language other than English, add a `language` variable and a rule: "Generate all prose content in {language}; keep code snippets and identifiers in English."
> - The `finding_json` variable provides full finding context to the model — ensure it includes enrichment data (attack_narrative, control_gaps) so the Reproduction and Remediation sections can be maximally specific.
