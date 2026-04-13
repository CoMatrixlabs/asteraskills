# Detection Engineering Playbooks — By Data Source

Each playbook contains natural language investigation questions. These questions are
platform-agnostic: the same question works whether your stack is KQL, Splunk SPL,
Elastic EQL, or standard SQL. The agent generates the actual query from the question
once you select a target platform.

---

## Data Source: Windows Security Events
**source_id:** windows_security_events
**platform_hints:** Microsoft Sentinel, Splunk, Elastic, QRadar
**primary_tables:** SecurityEvent, WinEventLog:Security
**schema_notes:** Key fields — EventID, Account, TargetUserName, LogonType, IpAddress, SubjectUserName, ProcessName, AuthenticationPackageName

---

### Playbook: Suspicious Logon Pattern Detection
**investigation_type:** initial_access
**trigger:** Unusual logon activity flagged by SIEM or user report of unexpected access
**att&ck:** T1078, T1110

**Investigation Questions:**
1. How many successful and failed logons did this account have in the last 24 hours, broken down by source IP?
2. Which logon types (interactive, network, remote interactive) does this account normally use, and does today's activity match that pattern?
3. Did the same account log on from more than one country within a two-hour window?
4. How many distinct accounts failed logon from the same source IP in the last hour?
5. Were there any successful logons immediately following a burst of failures from the same IP, suggesting a successful brute force?
6. Did any logons happen outside the account's normal working hours in the last seven days?

---

### Playbook: Privilege Escalation via Token Manipulation
**investigation_type:** privilege_escalation
**trigger:** Process running with unexpected elevated privilege, alert on special privilege assignment
**att&ck:** T1134, T1068

**Investigation Questions:**
1. Which non-service accounts triggered special privilege assignment events in the last 24 hours?
2. Did any of those accounts access LSASS memory or perform credential-related operations in the same time window?
3. What is the parent process tree for the process that triggered the privilege event?
4. How many times did this account use elevated privileges compared to its 30-day baseline?
5. Were any new scheduled tasks or services created immediately after the privilege assignment?

---

### Playbook: Lateral Movement via Pass-the-Hash
**investigation_type:** lateral_movement
**trigger:** NTLM network logon from anomalous source, or Kerberos ticket anomaly
**att&ck:** T1550.002, T1021

**Investigation Questions:**
1. How many distinct machines did this account authenticate to via NTLM network logon in the last two hours?
2. Is the ratio of NTLM to Kerberos authentications for this account higher than usual today?
3. Which source host originated the most network logons in the last 30 minutes, and how many destination hosts did it reach?
4. Did the same account authenticate to more than five machines within a 10-minute window?
5. Are any of the destination machines high-value assets such as domain controllers, file servers, or crown-jewel application servers?

---

## Data Source: Sysmon
**source_id:** sysmon
**platform_hints:** Microsoft Sentinel, Splunk, Elastic
**primary_tables:** Sysmon (Sentinel), index=sysmon (Splunk), logs-endpoint (Elastic)
**schema_notes:** Key fields — EventID, Image, CommandLine, ParentImage, OriginalFileName, DestinationIp, DestinationPort, Hashes, TargetFilename

---

### Playbook: Process Injection Detection
**investigation_type:** execution
**trigger:** Suspicious CreateRemoteThread or cross-process memory write detected
**att&ck:** T1055

**Investigation Questions:**
1. Which processes created remote threads into other processes in the last hour, excluding known-good system and security software?
2. What is the full parent-child process chain for the injecting process?
3. Did the injected target process open any outbound network connections within five minutes of being injected?
4. Does the injecting process have any known-bad hash matches in threat intelligence?
5. Has this injection pattern appeared on other machines in the environment in the last 24 hours?

---

### Playbook: Renamed Executable / Living-off-the-Land Binary
**investigation_type:** defense_evasion
**trigger:** OriginalFileName in process metadata does not match the actual executable filename
**att&ck:** T1036.003, T1218

**Investigation Questions:**
1. Which processes running in the last 24 hours have an OriginalFileName that differs from their actual image filename?
2. Of those renamed processes, which ones are known LOLBins such as powershell, cmd, mshta, certutil, or rundll32?
3. Did any renamed LOLBin execute with encoded, obfuscated, or unusually long command-line arguments?
4. Did the renamed process make any outbound network connections or write files to disk after execution?
5. What user account and parent process spawned the renamed binary?

---

### Playbook: Suspicious Network Connection from Script Host
**investigation_type:** command_and_control
**trigger:** Script interpreter making outbound connection to non-internal IP
**att&ck:** T1059, T1071

**Investigation Questions:**
1. Which script hosts such as PowerShell, wscript, cscript, or mshta made outbound connections to public IP addresses in the last 24 hours?
2. For each such connection, how many times did the same source process connect to the same destination IP, and at what intervals?
3. Does the connection interval show low variance suggesting automated beaconing rather than interactive use?
4. Do any of the destination IPs appear in CISA KEV, threat intelligence feeds, or known Tor exit node lists?
5. What command-line arguments were passed to the script host process that initiated the connection?

---

## Data Source: Azure Activity Logs
**source_id:** azure_activity
**platform_hints:** Microsoft Sentinel
**primary_tables:** AzureActivity
**schema_notes:** Key fields — OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, ResourceGroup, ResourceId, Properties

---

### Playbook: Privilege Escalation via Role Assignment
**investigation_type:** privilege_escalation
**trigger:** Unexpected IAM role assignment; Write/roleAssignments operation by non-admin caller
**att&ck:** T1078.004, T1098

**Investigation Questions:**
1. Which callers performed role assignment write operations in the last seven days, and are any of those callers outside the known IAM admin list?
2. What role was assigned, and does it grant Owner, Contributor, or any wildcard permission over resources?
3. What did the caller do in the 30 minutes immediately before the role assignment — was this a new or dormant identity?
4. How many resource modifications did the same caller make within a 10-minute window after gaining the new role?
5. Did the caller IP address appear in any threat intelligence or show anomalous geography?

---

### Playbook: Impossible Travel / Credential Compromise
**investigation_type:** initial_access
**trigger:** Same identity active from two geographically distant locations within one hour
**att&ck:** T1078, T1110.003

**Investigation Questions:**
1. Which identities authenticated from more than one country within a two-hour window in the last 24 hours?
2. For the flagged identity, what resources did they access immediately after the anomalous sign-in?
3. Does the anomalous source IP belong to a VPN provider, Tor exit node, or hosting provider that would explain the geography mismatch?
4. Was multi-factor authentication satisfied for the anomalous sign-in, or was it a legacy protocol bypass?
5. How does the volume and type of operations after the anomalous sign-in compare to this identity's baseline behaviour?

---

## Data Source: AWS CloudTrail
**source_id:** aws_cloudtrail
**platform_hints:** Splunk, Athena, Microsoft Sentinel (via connector), Elastic
**primary_tables:** AWSCloudTrail (Sentinel), index=aws sourcetype=aws:cloudtrail (Splunk)
**schema_notes:** Key fields — EventName, EventSource, UserIdentityArn, SourceIpAddress, RequestParameters, ErrorCode, UserAgent

---

### Playbook: IAM Privilege Escalation
**investigation_type:** privilege_escalation
**trigger:** Unexpected IAM policy attachment or inline policy creation by non-service caller
**att&ck:** T1078.004, T1098.003

**Investigation Questions:**
1. Which IAM principals performed policy creation, attachment, or inline-policy write operations in the last 24 hours that are not known automation service accounts?
2. Did any of those operations attach AdministratorAccess or a policy with wildcard Action and Resource fields?
3. Was the acting principal itself created recently, suggesting a newly created backdoor account?
4. Did the same principal create any new access keys or console passwords in the same session?
5. What API calls did this principal make in the five minutes following the privilege escalation, and which resources did they touch?

---

### Playbook: S3 Data Exfiltration
**investigation_type:** exfiltration
**trigger:** Unusually high GetObject volume, or bucket ACL/policy change making data public
**att&ck:** T1530

**Investigation Questions:**
1. Which principals retrieved the most objects from S3 in the last 24 hours, and how does that compare to their 7-day average?
2. Were any S3 bucket ACLs or bucket policies changed to allow public or cross-account access in the last seven days?
3. Did the high-volume requester access buckets they had not accessed in the prior 30 days?
4. What is the total data volume transferred out by the top requesters, and does any single session exceed a threshold that suggests bulk exfiltration?
5. Were any new IAM roles or cross-account trusts created that could facilitate exfiltration to an external account?

---

## Data Source: Kubernetes Audit Logs
**source_id:** kubernetes_audit
**platform_hints:** Microsoft Sentinel, Splunk, Elastic, Loki
**primary_tables:** AzureDiagnostics (AKS), KubeAuditAdmin_CL, k8s_audit (Elastic)
**schema_notes:** Key fields — verb, objectRef.resource, user.username, sourceIPs, responseStatus.code, requestObject, objectRef.namespace

---

### Playbook: Container Escape via Privileged Pod
**investigation_type:** privilege_escalation
**trigger:** Pod created with privileged security context or sensitive hostPath mount
**att&ck:** T1611, T1068

**Investigation Questions:**
1. Which pods were created or updated with a privileged security context, hostPID, or hostNetwork flag in the last 24 hours?
2. Did any of those pods mount host filesystem paths such as /etc, /var/run/docker.sock, /proc, or /host?
3. Who or what service account created the privileged pod, and is that the expected actor for that namespace?
4. Was an exec session opened into any of the flagged pods after creation, suggesting active exploitation?
5. Did the node running the flagged pod subsequently make unusual outbound network connections or spawn unexpected processes?

---

### Playbook: RBAC Privilege Escalation via ClusterRoleBinding
**investigation_type:** privilege_escalation
**trigger:** New ClusterRoleBinding granting cluster-admin or wildcard verbs to unexpected subject
**att&ck:** T1078, T1548

**Investigation Questions:**
1. Which ClusterRoleBindings or RoleBindings were created or modified in the last seven days that reference cluster-admin or roles with wildcard verb permissions?
2. Who created the binding and did that user normally have permission to create ClusterRoleBindings?
3. What subject was granted the elevated role — a human user, a ServiceAccount, or a group — and is that subject otherwise legitimate?
4. Did the newly privileged subject perform any cluster-wide operations such as listing secrets, accessing other namespaces, or modifying RBAC immediately after the binding was created?
5. Is there a corresponding deployment or application that legitimately requires this level of access, or was this binding created outside of a normal change management process?

---

## Data Source: Network Flows
**source_id:** network_flows
**platform_hints:** Microsoft Sentinel, Splunk, Elastic, Zeek/Corelight
**primary_tables:** AzureNetworkAnalytics_CL, CommonSecurityLog, zeek_conn
**schema_notes:** Key fields — SrcIP, DestIP, DestPort, Protocol, FlowStatus, InboundBytes, OutboundBytes, VM, Subnet, FlowDirection

---

### Playbook: C2 Beacon Detection
**investigation_type:** command_and_control
**trigger:** Regular low-volume outbound connections at consistent intervals from internal host
**att&ck:** T1071, T1132

**Investigation Questions:**
1. Which internal hosts made more than 20 outbound connections to the same external IP in the last six hours?
2. For those connection pairs, what is the average interval between connections and how low is the jitter — is the pattern more consistent than human-driven traffic would produce?
3. Is the outbound data volume per connection suspiciously uniform, suggesting fixed-size C2 check-ins rather than variable user traffic?
4. Do any of the destination IPs appear in CISA KEV, Tor exit node lists, or known malware C2 threat intelligence feeds?
5. What process on the source host initiated the connections, and is it a process expected to make outbound internet connections?

---

### Playbook: Port Scan and Reconnaissance Detection
**investigation_type:** reconnaissance
**trigger:** Single source connecting to many distinct ports or hosts in a short window
**att&ck:** T1046, T1595

**Investigation Questions:**
1. Which source IPs connected to or were denied to more than 20 distinct destination ports on the same host within a five-minute window?
2. Which source IPs reached out to more than 15 distinct internal hosts within a five-minute window, suggesting horizontal scanning?
3. Are any of the scanning sources known authorized scanners such as Tenable or Nessus, and if so should they be excluded?
4. Did any of the scanned ports subsequently receive a successful connection from the same source, indicating the scanner found an open service?
5. Has this source IP conducted scanning activity previously, or is this the first time it has appeared in network flow data?

---

## Data Source: Linux Auditd
**source_id:** linux_auditd
**platform_hints:** Microsoft Sentinel (Syslog), Splunk, Elastic
**primary_tables:** Syslog, auditd (Elastic)
**schema_notes:** Key fields — type (SYSCALL/PATH/EXECVE), auid, uid, syscall, exe, comm, key, name

---

### Playbook: Kernel Exploit and Local Privilege Escalation
**investigation_type:** privilege_escalation
**trigger:** CVE with AV:L (local attack vector) — attacker needs existing shell, escalates to root
**att&ck:** T1068, T1548.001

**Investigation Questions:**
1. Did any non-root process execute a binary associated with known exploit paths such as downloaded files, /tmp, or world-writable directories in the last 24 hours?
2. Was the setuid or setgid bit added to any binary by a non-root user in the last 24 hours?
3. Were the files /etc/passwd, /etc/shadow, /etc/sudoers, or any cron table modified outside a change window?
4. Did any process spawn a shell with a different effective UID than the initiating user, indicating successful privilege escalation?
5. Were any new persistence mechanisms such as cron jobs, systemd services, or authorized_keys entries created within minutes of a suspicious execve event?

---

### Playbook: Reverse Shell and Interactive Shell Spawn
**investigation_type:** execution
**trigger:** Interactive shell spawned by web server process, or outbound shell pipe detected
**att&ck:** T1059.004, T1071

**Investigation Questions:**
1. Did any web server or application process such as apache, nginx, java, or php-fpm spawn an interactive shell process in the last six hours?
2. Were any network tools such as netcat, socat, or ncat executed with arguments indicating a reverse shell or port forwarding setup?
3. Did a bash or sh process receive its stdin from a network socket rather than a terminal, suggesting a piped remote shell?
4. What commands were executed in the suspicious shell session, and did they include reconnaissance, download, or persistence activities?
5. Did the source host make any new outbound connections within seconds of the shell spawn event?

---

## Data Source: Microsoft Defender for Endpoint
**source_id:** mde
**platform_hints:** Microsoft Defender Portal, Microsoft Sentinel
**primary_tables:** DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents
**schema_notes:** Key fields — Timestamp, DeviceName, ActionType, FileName, SHA256, ProcessCommandLine, InitiatingProcessFileName, RemoteIP, AccountName, ReportId

---

### Playbook: Ransomware Precursor Activity
**investigation_type:** impact
**trigger:** Mass file rename, shadow copy deletion, or backup disruption commands detected
**att&ck:** T1486, T1490

**Investigation Questions:**
1. Which devices renamed more than 20 files within a one-hour window, and what process was responsible?
2. Were any commands executed to delete volume shadow copies, disable recovery mode, or wipe backup catalogs?
3. Did the device make any outbound connections to external IPs in the hour before the file rename activity began?
4. Is the file rename pattern consistent with a specific ransomware family — for example, a consistent new extension being appended to all renamed files?
5. Did the same device show lateral movement indicators in the 24 hours before the ransomware precursor events, suggesting network propagation is underway?

---

## Data Source: Web Application Logs
**source_id:** web_application_logs
**platform_hints:** Microsoft Sentinel, Splunk, Elastic
**primary_tables:** W3CIISLog, CustomLog_CL, nginx_access (Elastic)
**schema_notes:** Key fields — csMethod, csUriStem, csUriQuery, cIp, scStatus, csUserAgent, scBytes, TimeTaken

---

### Playbook: Web Application Exploitation
**investigation_type:** initial_access
**trigger:** WAF alert, 500 error spike, or suspicious URI pattern in access logs
**att&ck:** T1190, T1059

**Investigation Questions:**
1. Which source IPs submitted requests containing SQL injection keywords such as UNION, SELECT, OR 1=1, or time-delay functions in query parameters in the last 24 hours?
2. Which source IPs attempted path traversal patterns such as ../ sequences or URL-encoded equivalents against file-serving endpoints?
3. Did any source IP receive HTTP 500 responses after submitting unusual input, then subsequently receive a 200 response with a large response body, suggesting a successful exploit?
4. Which requests contained command injection indicators such as semicolons followed by system commands, backticks, or shell expansion syntax in query parameters?
5. Did any IP that triggered WAF blocks or error responses later make successful authenticated requests, suggesting they probed until they found a working payload?

---

## Data Source Catalog

| source_id | Description | Typical Platform | Primary Use Cases |
|---|---|---|---|
| windows_security_events | Windows Event Log (Security channel) | Sentinel, Splunk, Elastic | Logon anomalies, lateral movement, privilege use |
| sysmon | Microsoft Sysinternals System Monitor | Sentinel, Splunk, Elastic | Process injection, LOLBin, C2 beaconing |
| azure_activity | Azure control-plane activity | Microsoft Sentinel | Cloud IAM escalation, impossible travel |
| aws_cloudtrail | AWS API activity | Splunk, Athena, Sentinel | AWS IAM escalation, S3 exfiltration |
| kubernetes_audit | Kubernetes API server audit | Sentinel, Splunk, Elastic, Loki | Container escape, RBAC escalation |
| network_flows | NetFlow, NSG flow logs, Zeek conn | Sentinel, Splunk, Elastic | C2 beaconing, reconnaissance, exfiltration |
| linux_auditd | Linux kernel audit daemon | Sentinel (Syslog), Splunk | Kernel exploits, reverse shell, privilege escalation |
| mde | Microsoft Defender for Endpoint | Defender Portal, Sentinel | Ransomware precursor, endpoint IOCs |
| web_application_logs | IIS / Nginx / Apache access logs | Sentinel, Splunk, Elastic | SQLi, path traversal, RCE via web |
