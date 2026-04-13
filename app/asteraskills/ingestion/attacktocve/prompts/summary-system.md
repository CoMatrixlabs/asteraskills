---
id: SUMMARY_SYSTEM
name: ATT&CK Mapping Executive Summary System Prompt
stage: summary
used_by: app/asteraskills/tools/attack_control_mapping.py
variables:
  framework_name: The target compliance or risk framework (e.g., "CIS Controls", "NIST 800-53", "ISO 27001", "SOC 2")
---

You are a cybersecurity analyst writing executive summaries of ATT&CK technique mappings to {framework_name} controls. Be concise, use plain language, reference {framework_name} terminology, and highlight the key risk themes.

<!-- DOCS_START -->
## Examples

### Example 1 — CIS Controls summary system prompt in action

**Input variables:**
```
framework_name: CIS Controls v8
```

**What the LLM's output style will reflect:**
The summary will use CIS Controls terminology such as "Safeguards", "Implementation Groups (IG1/IG2/IG3)", and "Control Groups". It will be concise (3–5 sentences), written for a non-technical executive audience, and will name specific CIS Control Group numbers where relevant (e.g., "CIS Control 7 – Continuous Vulnerability Management").

**Sample output produced by this system prompt when paired with a user prompt:**
T1190 (Exploit Public-Facing Application) maps most strongly to CIS Controls in the vulnerability management and network monitoring domains. The three highest-relevance Safeguards fall within CIS Control 7 (Continuous Vulnerability Management) and CIS Control 13 (Network Monitoring and Defense), reflecting that unpatched public-facing applications are the primary attack surface and that detection depends on centralized log analysis. Organizations operating at IG1 maturity are most exposed, as basic patch management and asset inventory Safeguards must be in place before the more advanced application security testing Safeguards become achievable. Prioritizing CIS Safeguards 7.2 (remediate detected vulnerabilities) and 13.1 (centralize security alerting) provides the highest risk reduction return for this technique.

### Example 2 — ISO 27001 summary system prompt in action

**Input variables:**
```
framework_name: ISO 27001:2022
```

**What the LLM's output style will reflect:**
The summary will use ISO 27001 terminology such as "Annex A controls", "clauses", "information security objectives", and "ISMS". It will reference control domains (e.g., "Technological Controls (Annex A 8.x)") and frame the risk in terms of confidentiality, integrity, and availability (CIA triad). Language will remain accessible while staying technically grounded.

**Sample output produced by this system prompt when paired with a user prompt:**
T1566.001 (Spearphishing Attachment) triggers controls primarily within the Technological Controls domain of ISO 27001:2022 Annex A, with significant exposure in the People Controls domain as well. The validated mappings highlight A.8.23 (Web Filtering) and A.8.4 (Access to Source Code) as the most directly mitigating controls, addressing the delivery mechanism and post-exploitation code execution respectively. People-oriented controls — particularly A.6.3 (Information Security Awareness, Education and Training) — represent the second risk domain given that phishing fundamentally relies on human interaction. Organizations should treat this technique as a signal to review their phishing simulation program maturity and email gateway configuration against the A.8.x Technological Controls baseline.

## Customization

> **How to adapt this prompt:**
> - `{framework_name}` is the sole variable in this system prompt but has outsized impact: it dictates the entire vocabulary, structural references, and framing of the summary. Passing "NIST 800-53 Rev 5" produces summaries that reference control families (AC, AU, SI), impact levels (LOW/MODERATE/HIGH), and FedRAMP context; passing "SOC 2" produces summaries referencing Trust Service Criteria codes (CC, A, PI, etc.) and audit opinion framing.
> - To produce longer, more detailed summaries (e.g., for technical briefings rather than executive dashboards), add an instruction to the system prompt: "Write 5–8 sentences and include specific control IDs in parentheses."
> - To produce shorter summaries suitable for inline tooltips or SIEM rule descriptions, add: "Write exactly 2 sentences. Be direct and action-oriented."
> - For multi-framework outputs (e.g., an organization using both NIST 800-53 and ISO 27001), invoke this prompt twice with different `{framework_name}` values and concatenate the outputs under distinct headers in the final report.
> - If the downstream consumer is a non-security executive audience, add: "Avoid acronyms and technical jargon. Explain all framework terms in plain English on first use." If the audience is a security engineer, add: "Include specific control IDs and tactic slugs where relevant."
