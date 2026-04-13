# CVE Investigation — CVE-2024-26855

⚪ **MINIMAL** &nbsp;|&nbsp; P(exploitation) = 0.000 &nbsp;|&nbsp; Environment: k8s &nbsp;|&nbsp; Criticality: crown_jewel

> This report walks through the in-memory causal graph built from the CVE
> enrichment result. Each step introduces one ontology node, explains which
> domain score it drives, and shows how it contributes to the structural
> equation.

**Graph summary:** 4 nodes · 3 edges


---

## Step 1 — 🔍 Vulnerability Profile

> **What we know about CVE-2024-26855**

No description available.


```
[vulnerability] CVE-2024-26855
  ├── severity: medium
  ├── exploitability: none
```

**Causal role of this node**

| Signal | Value | Domain score driven |
|--------|-------|---------------------|
| CVSS base score | 0.0 | `vuln_exposure` ← primary driver |
| EPSS probability | 0.000 (0.0% of CVEs scored higher) | `vuln_exposure` amplifier |
| CISA KEV | ❌ Not in KEV | `vuln_exposure` override when True |

**`p_vuln_exposure` = 0.000** (⚪ Minimal)
This score feeds `P(exploit | access)` in the structural equation.


---

## Step 2 — 🏗️ Target Environment

> **Ontology node type: `k8s_cluster`**

The affected asset lives in a **k8s** environment with criticality **crown_jewel**.

```
[k8s_cluster] Target system (k8s)
  ├── network_exposure: public_internet
  ├── business_criticality: crown_jewel
  ├── hardening_level: hardened
  ├── p_asset_exposure: 0.54
```

**How this node's properties map to domain scores**

| Property | Value | Domain score |
|----------|-------|--------------|
| `network_exposure` | `public_internet` (reachability = 1.00) | `p_asset_exposure` = 0.540 |
| `business_criticality` | `crown_jewel` | Crown-jewel amplifier ×1.25 if `crown_jewel` |
| `hardening_level` | `hardened` | `p_attack_surface` = 0.550 |

**Edge created:** `CVE-2024-26855` —[**exploits** conf=0.1]→ `Target system`

`p_asset_exposure` and `p_attack_surface` together determine **P(access)** — the probability
the attacker can reach and interact with this asset.


---

## Step 3 — ⚔️ Attack Path (ATT&CK Mapping)

> No ATT&CK techniques were mapped during enrichment.

**Causal role:** These nodes determine which tactic family dominates the
structural equation. Execution-phase techniques amplify `p_vuln_exposure`;
lateral-movement techniques amplify `p_attack_surface`.


---

## Step 4 — 🛡️ Controls in Place

> **2 control(s) detected in your environment**

Each control node is connected via `protected_by_security_group` edge from the asset.

| Control | Ontology type | Hardening level | Domain score impact |
|---------|--------------|-----------------|---------------------|
| Network Policy | `network_policy_control` | hardened | Reduces `p_misconfiguration` and `p_attack_surface` |
| Apparmor | `pod_security_control` | hardened | Reduces `p_misconfiguration` and `p_attack_surface` |

| Domain | Score | Interpretation |
|--------|-------|----------------|
| `p_misconfiguration` | 0.750 | 🟠 High — drives P(blocked) |
| `p_patch_risk`       | 0.300 | 🟢 Low — drives P(blocked) |

**`P(blocked)` = (1 − patch_risk) × (1 − 0.3 × misconfiguration) = 0.542**


---

## Step 5 — 📊 Causal Domain Scores

> **All six domain scores derived from the graph**

These scores are computed from the ontology node properties using the
enum-to-score mappings in `enums_v1.json`.

| Domain | Score | Tier | Primary source |
|--------|-------|------|----------------|
| `p_asset_exposure`  | 0.540  | 🟡 Medium  | `network_exposure` enum on asset node |
| `p_attack_surface`  | 0.550  | 🟡 Medium  | CVSS S-field + environment type |
| `p_vuln_exposure`   | 0.000   | ⚪ Minimal   | CVSS base + EPSS + KEV override |
| `p_misconfiguration`| 0.750 | 🟠 High | CVSS PR-field + controls present |
| `p_patch_risk`      | 0.300      | 🟢 Low      | KEV status + EPSS |
| `p_asset_exposure` (crown jewel?) | Yes ×1.25 | — | `business_criticality` == `crown_jewel` |


---

## Step 6 — 🎯 Structural Equation — P(exploitation)

> **Pearl's Ladder of Causation — Rung 1 (observational)**

The causal structural equation over the graph:

```
P(exploitation) = P(access) × P(exploit | access) × (1 − P(blocked))
```

**Walking through each factor:**

**P(access)** — can the attacker reach the asset?
```
P(access) = asset_exposure × reachability + 0.2 × attack_surface × reachability
          = 0.540 × 1.00 + 0.2 × 0.550 × 1.00
          = 0.650
```

**P(exploit | access)** — if they reach it, can they exploit it?
```
P(exploit|access) = vuln_exposure + 0.15 × misconfiguration × vuln_exposure
                  = 0.000 + 0.15 × 0.750 × 0.000
                  = 0.000
```

**P(blocked)** — will existing controls stop the attempt?
```
P(blocked) = (1 − patch_risk) × (1 − 0.3 × misconfiguration)
           = (1 − 0.300) × (1 − 0.3 × 0.750)
           = 0.542
```

**Result:**
```
P(exploitation) = 0.650 × 0.000 × (1 − 0.542)
                = 0.000
```

⚪ **Risk tier: MINIMAL** (P = 0.000)
> ⚠️ Crown-jewel amplification (×1.25) applied.


---

## Step 7 — 🔧 Counterfactual Interventions — What-If

> **Rung 2 of Pearl's Ladder — do-calculus**

Each row shows what happens to P(exploitation) if you apply one intervention.
Use these to prioritise remediation actions.

| Intervention | do-expression | P before | P after | Δ drop | Tier after |
|---|---|---|---|---|---|
| Apply patch | `do(patch_risk=0)` | 0.000 | 0.000 | −0.000 (0%) | MINIMAL |
| Network isolation | `do(reachability=0.15)` | 0.000 | 0.000 | −0.000 (0%) | MINIMAL |
| Harden config | `do(misconfiguration=0.1)` | 0.000 | 0.000 | −0.000 (0%) | MINIMAL |
| Reduce attack surface | `do(attack_surface=0.1)` | 0.000 | 0.000 | −0.000 (0%) | MINIMAL |
| Patch + isolate | `do(patch_risk=0, rch=0.15)` | 0.000 | 0.000 | −0.000 (0%) | MINIMAL |


---

## Step 8 — 🔎 Detection Engineering Playbook

## Causal Investigation Playbook — CVE-2024-26855

### Causal Risk Assessment

| Component | Value |
|---|---|
| **P(exploitation)** | `0.0000` — **MINIMAL** |
| P(access) | `0.1950` |
| P(exploit\|access) | `0.0000` |
| P(blocked) | `0.6975` |
| Environment | `k8s` |
| Asset criticality | `crown_jewel` |

### Domain Scores (Ontology → Causal Input)

| Domain | Score | Interpretation |
|---|---|---|
| Asset Exposure | `0.540` █████░░░░░ | How exposed is the asset to attack |
| Vuln Exploitability | `0.000` ░░░░░░░░░░ | Probability attacker can exploit the CVE |
| Patch Gap Risk | `0.100` █░░░░░░░░░ | Probability the patch is NOT in place |
| Attack Surface | `0.550` █████░░░░░ | Breadth of the exploitable surface |
| Misconfiguration | `0.750` ███████░░░ | IAM/config weaknesses enabling the attack |

### Enabled ATT&CK Tactics

Enabled by domain scores: `TA0001`, `TA0003`, `TA0004`, `TA0008`  
Primary: `TA0004` → technique `T1078`

### Counterfactual Analysis (do-calculus — Rung 2)

What reduces exploitation probability most:

| Intervention | Δ P(exploitation) |
|---|---|
| do(patch_risk=0): fully patched | `+0.0000` ↑ |
| do(reachability=cluster_internal): isolate from internet | `+0.0000` ↑ |
| do(misconfiguration=0): fix all IAM misconfigs | `+0.0000` ↑ |
| do(attack_surface=0.1): harden service exposure | `+0.0000` ↑ |
| do(patch_risk=0, reachability=vpc_internal): patch+isolate | `+0.0000` ↑ |

### Investigation Playbooks by Data Source

#### Source: `kubernetes_audit`
*P(misconfiguration)=0.75 — RBAC or privileged container misconfigs are the risk driver*  
Driving tactics: `TA0004`


#### Source: `windows_security_events`
*P(access)=0.54 — logon anomalies and lateral movement are primary risk paths*  
Driving tactics: `TA0001`, `TA0003`, `TA0004`, `TA0008`


#### Source: `azure_activity`
*P(misconfiguration)=0.75 — cloud IAM privilege escalation path is active*  
Driving tactics: `TA0001`, `TA0004`

