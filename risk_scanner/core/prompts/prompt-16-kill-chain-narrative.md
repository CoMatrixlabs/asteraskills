---
id: PROMPT-16
name: Kill Chain Narrative — Threat Intelligence Prose
stage: agent
used_by: risk_scanner/core/agent/kill_chain_narrator.py
variables:
  kill_chain_findings: JSON array of ATT&CK technique findings in chronological order, each with technique_id, technique_name, tactic, kill_chain_position, evidence_type, sequence_stage, and evidence_detail
  stages: Comma-separated list of detected kill chain stages in chronological order
  window: Time window string describing the detection period (e.g. "2024-11-03T09:44:01Z to 2024-11-03T11:22:15Z (98 minutes)")
  is_complete: Boolean string ("true"/"false") indicating whether a complete kill chain was detected
---

SYSTEM
You are a threat intelligence analyst. A sequence correlator has detected an event
pattern spanning multiple ATT&CK kill chain stages. Produce a threat actor narrative
describing the observed or suspected intrusion activity.

This narrative will appear in the finding summary and may be shared with an
incident response team.

OUTPUT FORMAT: 4-6 paragraphs of professional threat intelligence prose.

SECTIONS
1. Executive summary (2 sentences): what happened, how far it progressed.
2. Initial access: how the attacker likely entered.
3. Progression: each detected stage in chronological order.
4. Current state: where the attacker is in the kill chain based on last observed event.
5. Immediate actions: 3 specific containment steps ranked by urgency.

RULES
- Distinguish observed evidence from inferred stages.
- Do not speculate about threat actor attribution without supporting evidence.
- Keep technical references (technique IDs) in parentheses, not inline.

KILL CHAIN DETECTION
{kill_chain_findings}
detected_stages: {stages}
timeline_window: {window}
is_complete_chain: {is_complete}

<!-- DOCS_START -->
## Examples

### Example 1 — Complete kill chain: spearphishing to persistence over 98 minutes on an endpoint

**Input variables:**
```
kill_chain_findings: [
  {"technique_id":"T1566.001","technique_name":"Spearphishing Attachment","tactic":"Initial Access","kill_chain_position":1,"evidence_type":"sequence_correlation","sequence_stage":"initial_access","evidence_detail":"winword.exe spawned powershell.exe at 09:44:01 on WORKSTATION-14"},
  {"technique_id":"T1059.001","technique_name":"PowerShell","tactic":"Execution","kill_chain_position":2,"evidence_type":"ioc_match","sequence_stage":"execution","evidence_detail":"powershell.exe executed base64-encoded command at 09:44:08"},
  {"technique_id":"T1105","technique_name":"Ingress Tool Transfer","tactic":"Command and Control","kill_chain_position":3,"evidence_type":"behavioral","sequence_stage":"execution","evidence_detail":"powershell.exe created C:\\Users\\Public\\updater.exe at 09:44:12"},
  {"technique_id":"T1053.005","technique_name":"Scheduled Task","tactic":"Persistence","kill_chain_position":4,"evidence_type":"ioc_match","sequence_stage":"persistence","evidence_detail":"schtasks.exe created task SystemUpdate pointing to updater.exe at 09:44:18"},
  {"technique_id":"T1083","technique_name":"File and Directory Discovery","tactic":"Discovery","kill_chain_position":5,"evidence_type":"behavioral","sequence_stage":"discovery","evidence_detail":"cmd.exe executed dir /s C:\\Users\\ and dir /s C:\\Program Files\\ at 10:15:44"},
  {"technique_id":"T1552.001","technique_name":"Credentials In Files","tactic":"Credential Access","kill_chain_position":6,"evidence_type":"behavioral","sequence_stage":"credential_access","evidence_detail":"powershell.exe read .aws/credentials and %APPDATA%\\Code\\User\\settings.json at 11:20:33"}
]
stages: initial_access, execution, persistence, discovery, credential_access
window: 2024-11-03T09:44:01Z to 2024-11-03T11:22:15Z (98 minutes)
is_complete: false
```

**Expected output (prose):**

An intrusion was detected on WORKSTATION-14 spanning five kill chain stages over a 98-minute window, progressing from initial access through credential harvesting; the attacker has established persistence and is actively conducting pre-exfiltration reconnaissance as of the last observed event.

Initial access was achieved at 09:44:01 through a malicious document that executed PowerShell when opened in Microsoft Word (T1566.001). The parent-child relationship between winword.exe and powershell.exe is a high-confidence indicator of a macro-enabled document delivered via email, consistent with a spearphishing attachment lure. The document was likely opened by a user on WORKSTATION-14 in response to a targeted email; the precise delivery vector is inferred from process telemetry rather than email gateway logs.

Within seven seconds of initial access, the attacker executed a base64-encoded PowerShell command (T1059.001) that downloaded and wrote a second-stage executable to `C:\Users\Public\updater.exe` (T1105). This rapid execution-to-implant timeline is consistent with an automated post-exploitation framework. At 09:44:18, a scheduled task named "SystemUpdate" was created to execute `updater.exe` daily (T1053.005), establishing persistence that survives system reboots and is designed to blend in with legitimate Windows update task names.

After a 31-minute quiet period — likely the implant checking in to command and control infrastructure — automated discovery commands were executed at 10:15:44, recursively enumerating the filesystem under `C:\Users\` and `C:\Program Files\` (T1083). The most recent observed activity at 11:20:33 shows the attacker reading `C:\Users\[user]\.aws\credentials` and VS Code settings files, suggesting credential harvesting (T1552.001) targeting cloud access keys and potentially stored API tokens. As of the last observed event, the attacker holds AWS credentials and has established persistent access via the scheduled task.

**Immediate containment actions (ranked by urgency):** (1) Isolate WORKSTATION-14 from the network immediately to prevent lateral movement and cut the implant's command-and-control channel — this is the highest priority. (2) Revoke and rotate all AWS credentials associated with the user account on WORKSTATION-14, specifically the IAM user whose `.aws/credentials` file was read, and audit CloudTrail for any API calls made in the last 98 minutes using those credentials. (3) Search for `updater.exe` in `C:\Users\Public\` and the "SystemUpdate" scheduled task across all endpoints in the environment to assess whether lateral movement has already occurred to other workstations.

### Example 2 — Incomplete kill chain: cloud initial access via compromised credentials, no lateral movement yet detected

**Input variables:**
```
kill_chain_findings: [
  {"technique_id":"T1078.004","technique_name":"Valid Accounts: Cloud Accounts","tactic":"Initial Access","kill_chain_position":1,"evidence_type":"sequence_correlation","sequence_stage":"initial_access","evidence_detail":"Successful AWS console login from IP 203.0.113.77 (Romania) for user sarah.chen@company.com at 2024-10-22T02:14:33Z, outside normal business hours"},
  {"technique_id":"T1619","technique_name":"Cloud Storage Object Discovery","tactic":"Discovery","kill_chain_position":2,"evidence_type":"behavioral","sequence_stage":"discovery","evidence_detail":"ListBucket API calls to 14 S3 buckets across 3 regions within 4 minutes at 02:15:01Z"},
  {"technique_id":"T1530","technique_name":"Data from Cloud Storage","tactic":"Collection","kill_chain_position":3,"evidence_type":"ioc_match","sequence_stage":"collection","evidence_detail":"GetObject API calls downloaded 2,847 objects totaling 4.2GB from prod-customer-data and prod-backups buckets at 02:16:44Z to 02:31:19Z"}
]
stages: initial_access, discovery, collection
window: 2024-10-22T02:14:33Z to 2024-10-22T02:31:19Z (16 minutes)
is_complete: false
```

**Expected output (prose):**

A cloud intrusion was detected in which an attacker authenticated using compromised employee credentials and exfiltrated approximately 4.2GB of data from production S3 buckets within a 16-minute window; the collection stage has completed and the attacker may have already exited the environment.

Initial access was achieved at 02:14:33Z via valid cloud account credentials belonging to sarah.chen@company.com, authenticated from IP address 203.0.113.77 geolocating to Romania (T1078.004). The authentication occurred outside normal business hours and from an IP not previously associated with this user, suggesting credential compromise rather than authorized access. The method by which these credentials were obtained is not established from available evidence — possibilities include phishing, credential stuffing from a prior breach, or theft from a developer machine — but the authentication was successful against the AWS console, indicating valid username and password were used.

Immediately following authentication, the attacker executed rapid S3 discovery operations (T1619), issuing ListBucket API calls against 14 buckets across three regions within four minutes. This systematic enumeration pattern is consistent with automated tooling designed to quickly identify high-value data stores. The discovery phase identified two production buckets — `prod-customer-data` and `prod-backups` — as targets.

Data exfiltration (T1530) began at 02:16:44Z and ran for 14 minutes, downloading 2,847 objects totaling 4.2GB from the two identified buckets. The volume and duration suggest automated bulk download rather than selective manual access. As of 02:31:19Z, the last observed API call, the download appears complete. No lateral movement, privilege escalation, or infrastructure modification was observed in the detection window, but the absence of these stages in telemetry does not rule out activity that may have occurred outside monitored services.

**Immediate containment actions (ranked by urgency):** (1) Revoke all active AWS sessions for sarah.chen@company.com immediately using `aws iam delete-login-profile` and `aws iam delete-access-key` for all associated credentials, and force a password reset through the identity provider — this stops any ongoing access if the session has not yet expired. (2) Determine the full scope of exfiltrated data by reviewing S3 server access logs and CloudTrail GetObject events for the 02:14Z to 02:32Z window, and assess whether the downloaded data includes personally identifiable information subject to breach notification obligations. (3) Investigate how sarah.chen's credentials were compromised: review her endpoint for malware, check whether her email address appears in public breach databases, and audit all other IAM users for anomalous login patterns from the same IP range or similar off-hours activity.

## Customization

> **How to adapt this prompt:**
> - To adjust the narrative length, change "4-6 paragraphs" to your preferred range. For automated alert digests, "2-3 paragraphs" is more appropriate; for formal incident reports, allow "6-8 paragraphs."
> - To add threat actor attribution when supporting evidence exists, change the attribution rule to: "Include threat actor attribution only when the retrieved ATT&CK signals contain a named group match with confidence >= 0.8; prefix with 'This activity is consistent with TTPs attributed to [group], though attribution cannot be confirmed.'"
> - To generate structured output alongside prose, add a JSON schema to the OUTPUT FORMAT with fields: `incident_severity`, `estimated_attacker_position`, `containment_urgency`, and `requires_breach_notification`.
> - To localize the "Immediate actions" section for your IR playbook, replace the generic recommendations with references to your runbook steps (e.g. "Follow IR-PLAYBOOK-03 Step 4 for credential revocation").
> - The `is_complete` variable gates the narrative tone — when true, the model should treat this as a confirmed intrusion requiring IR; when false, it should hedge with "observed activity is consistent with" language rather than definitive assertions.
