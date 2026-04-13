"""
entity_investigation.py
────────────────────────────
Enriches a CVE finding, discovers related entities (affected assets, attack
techniques, controls, threat signals), computes exploitation probability, and
renders a step-by-step deeper analysis — one step per entity type.

Each step explains:
  • what the related entity is and what its properties mean
  • which risk domain that entity drives
  • how that domain score affects the overall exploitation probability
  • what the analyst can observe or change to reduce risk

No LLM is required — all narrative text is template-driven so the module
works offline, identical to PlaybookSynthesizer.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Try to import the shared ontology store models ────────────────────────────
# These live in the causalgraphs repo; fall back to inline equivalents so this
# module is usable in the asteraskills environment even without causalgraphs on
# sys.path.
try:
    _cg_path = str(
        Path(__file__).parents[5]
        / "Nexcraft"
        / "causalgraphs"
        / "expertsystem"
        / "backend"
        / "app"
        / "security_graph"
    )
    if _cg_path not in sys.path:
        sys.path.insert(0, _cg_path)
    from store_models import SecurityGraphNode, SecurityGraphEdge, GraphDocumentBundle  # type: ignore
    _HAS_STORE_MODELS = True
except Exception:
    _HAS_STORE_MODELS = False

    @dataclass
    class SecurityGraphNode:  # type: ignore[no-redef]
        node_id: str
        node_type: str
        name: str
        properties: Dict[str, Any] = field(default_factory=dict)
        labels: List[str] = field(default_factory=list)
        tags: Dict[str, str] = field(default_factory=dict)
        evidence_refs: List[str] = field(default_factory=list)
        status: str = "confirmed"
        source_system: str = "cve_investigation"

    @dataclass
    class SecurityGraphEdge:  # type: ignore[no-redef]
        edge_id: str
        edge_type: str
        source_node_id: str
        target_node_id: str
        confidence: float = 1.0
        properties: Dict[str, Any] = field(default_factory=dict)
        evidence_refs: List[str] = field(default_factory=list)

    @dataclass
    class GraphDocumentBundle:  # type: ignore[no-redef]
        nodes: List[SecurityGraphNode] = field(default_factory=list)
        edges: List[SecurityGraphEdge] = field(default_factory=list)
        ontology_version: str = "v1"


# ── Try to import the exploitation probability model ────────────────────────
try:
    _af_path = str(Path(__file__).parents[5] / "Nexcraft" / "causalgraphs" / "app_f")
    if _af_path not in sys.path:
        sys.path.insert(0, _af_path)
    from exploitation_risk_model import ExploitationRiskModel  # type: ignore
    _HAS_RISK_MODEL = True
except Exception:
    _HAS_RISK_MODEL = False

# ── Enums and mappings (from enums_v1.json + exploitation_risk_model.py) ─────

# network_exposure enum → reachability weight (from enums_v1 + risk model)
_EXPOSURE_TO_REACHABILITY: Dict[str, float] = {
    "none":             0.00,
    "cluster_internal": 0.15,
    "vpc_internal":     0.30,
    "corp_internal":    0.50,
    "partner_exposed":  0.75,
    "public_internet":  1.00,
}

# business_criticality enum → numeric weight
_CRITICALITY_WEIGHTS: Dict[str, float] = {
    "low":         0.20,
    "medium":      0.40,
    "high":        0.60,
    "critical":    0.70,
    "crown_jewel": 0.80,
    "unknown":     0.50,
}

# CVSS AV field → network_exposure label
_AV_TO_EXPOSURE: Dict[str, str] = {
    "N": "public_internet",
    "A": "partner_exposed",
    "L": "vpc_internal",
    "P": "cluster_internal",
}

# CVSS PR field → permission_risk label
_PR_TO_PERMISSION: Dict[str, str] = {
    "N": "minimal",
    "L": "broad",
    "H": "excessive",
}

# CVSS S field → attack_surface label
_SCOPE_TO_SURFACE: Dict[str, str] = {
    "C": "service_attack_surface",
    "U": "service_attack_surface_limited",
}

# Environment string → ontology node type
_ENV_TO_NODE_TYPE: Dict[str, str] = {
    "k8s":        "k8s_cluster",
    "kubernetes": "k8s_cluster",
    "container":  "k8s_pod",
    "cloud_vm":   "vm_instance",
    "cloud":      "vm_instance",
    "bare_metal": "host",
    "mixed":      "host",
    "serverless": "serverless_function",
}

# Controls → ontology node types
_CONTROL_TO_NODE_TYPE: Dict[str, str] = {
    "network_policy":   "network_policy_control",
    "apparmor":         "pod_security_control",
    "selinux":          "pod_security_control",
    "edr":              "runtime_policy_control",
    "waf":              "waf_control",
    "admission":        "admission_control",
    "rbac":             "rbac_control",
    "kms":              "kms_control",
    "logging":          "logging_control",
    "image_signing":    "image_signing_control",
}

# Tactic explanations for the conversation
_TACTIC_NARRATIVE: Dict[str, str] = {
    "initial-access":       "gaining a first foothold into the environment",
    "execution":            "running attacker-controlled code on the target",
    "persistence":          "maintaining access after restarts or credential rotation",
    "privilege-escalation": "obtaining higher permissions than initially granted",
    "defense-evasion":      "hiding activity from detection and monitoring tools",
    "credential-access":    "harvesting credentials for lateral movement",
    "discovery":            "mapping the internal network and adjacent assets",
    "lateral-movement":     "pivoting from this asset to other systems",
    "collection":           "aggregating sensitive data for exfiltration",
    "exfiltration":         "sending data out of the environment",
    "impact":               "disrupting or destroying data and services",
    "command-and-control":  "maintaining a backchannel to attacker infrastructure",
}

# Domain score interpretation thresholds
_SCORE_LABEL = [
    (0.80, "🔴 Critical"),
    (0.60, "🟠 High"),
    (0.40, "🟡 Medium"),
    (0.20, "🟢 Low"),
    (0.00, "⚪ Minimal"),
]


def _score_label(score: float) -> str:
    for threshold, label in _SCORE_LABEL:
        if score >= threshold:
            return label
    return "⚪ Minimal"


# ── Main graph dataclass ──────────────────────────────────────────────────────

@dataclass
class InvestigationGraph:
    """Related-entity graph built from a CVE enrichment result."""
    nodes: List[SecurityGraphNode] = field(default_factory=list)
    edges: List[SecurityGraphEdge] = field(default_factory=list)
    domain_scores: Dict[str, float] = field(default_factory=dict)
    p_exploitation: float = 0.0
    risk_tier: str = "UNKNOWN"
    p_access: float = 0.0
    p_exploit_given_access: float = 0.0
    p_blocked: float = 0.0
    counterfactuals: List[Dict[str, Any]] = field(default_factory=list)
    reachability_label: str = "unknown"

    def node(self, node_id: str) -> Optional[SecurityGraphNode]:
        return next((n for n in self.nodes if n.node_id == node_id), None)

    def edges_from(self, node_id: str) -> List[SecurityGraphEdge]:
        return [e for e in self.edges if e.source_node_id == node_id]

    def to_bundle(self) -> GraphDocumentBundle:
        return GraphDocumentBundle(nodes=self.nodes, edges=self.edges)


# ── Conversation turn dataclass ───────────────────────────────────────────────

@dataclass
class ConversationTurn:
    step: int
    icon: str
    title: str
    node_id: Optional[str]       # which graph node this turn focuses on
    narrative: str                # explanation paragraph
    graph_lines: List[str]        # ascii node/edge rendering
    causal_note: str              # how this node affects P(exploitation)


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_graph(
    cve_id: str,
    cve_detail: Dict[str, Any],
    attack_chain: List[Any],          # List[AttackEnrichment]
    kev_entry: Optional[Any],         # KevEntry | None
    environment: str,
    criticality: str,
    controls_csv: str,
) -> InvestigationGraph:
    """
    Discover related entities from the enriched CVE finding and compute
    exploitation probability across those entities.
    """
    from asteraskills.agents.playbook_synthesizer import cvss_to_domain_scores  # local import

    graph = InvestigationGraph()
    controls_list = [c.strip().lower() for c in (controls_csv or "").split(",") if c.strip()]

    # ── Parse CVSS fields (used to derive entity risk properties) ────────────
    cvss_vector: str = cve_detail.get("cvss_vector", "")
    cvss_score:  float = float(cve_detail.get("cvss_score", 0.0))
    epss_score:  float = float(cve_detail.get("epss_score", 0.0))
    description: str = cve_detail.get("description", "")

    av_field = "N"
    scope_field = "U"
    pr_field = "N"
    if cvss_vector:
        for part in cvss_vector.split("/"):
            if part.startswith("AV:"):
                av_field = part[3:]
            elif part.startswith("S:"):
                scope_field = part[2:]
            elif part.startswith("PR:"):
                pr_field = part[3:]

    in_kev         = bool(kev_entry and kev_entry.in_kev)
    kev_ransomware = bool(kev_entry and kev_entry.ransomware_campaign_use)

    exposure_label = _AV_TO_EXPOSURE.get(av_field, "vpc_internal")
    reachability   = _EXPOSURE_TO_REACHABILITY.get(exposure_label, 0.30)

    # ── Domain scores (from playbook_synthesizer / CVSS mapping) ────────────
    domain_scores = cvss_to_domain_scores(
        cvss_vector=cvss_vector,
        cvss_base=cvss_score,
        epss_score=epss_score,
        in_kev=in_kev,
        environment_type=environment,
        asset_criticality=criticality,
    )
    graph.domain_scores = domain_scores

    # ── Run exploitation probability model ──────────────────────────────────
    asset_exp  = domain_scores.get("p_asset_exposure", 0.5)
    attack_srf = domain_scores.get("p_attack_surface", 0.5)
    vuln_exp   = domain_scores.get("p_vuln_exposure", 0.5)
    misconfig  = domain_scores.get("p_misconfiguration", 0.3)
    patch_risk = domain_scores.get("p_patch_risk", 0.5)
    is_crown   = domain_scores.get("is_crown_jewel", False)

    if _HAS_RISK_MODEL:
        try:
            rm = ExploitationRiskModel()
            p, tier, factors = rm.score(
                asset_exposure=asset_exp,
                attack_surface=attack_srf,
                vuln_exposure=vuln_exp,
                misconfiguration=misconfig,
                patch_risk=patch_risk,
                reachability=reachability,
                is_crown_jewel=is_crown,
            )
            graph.p_exploitation = p
            graph.risk_tier = tier
            graph.p_access = factors.get("p_access", 0.0)
            graph.p_exploit_given_access = factors.get("p_exploit_given_access", 0.0)
            graph.p_blocked = factors.get("p_blocked", 0.0)
        except Exception:
            _inline_equation(graph, asset_exp, attack_srf, vuln_exp, misconfig, patch_risk, reachability, is_crown)
    else:
        _inline_equation(graph, asset_exp, attack_srf, vuln_exp, misconfig, patch_risk, reachability, is_crown)

    graph.reachability_label = exposure_label

    # ── Remediation scenarios (what-if analysis) ─────────────────────────────
    graph.counterfactuals = _compute_counterfactuals(graph, domain_scores, is_crown, reachability)

    # ═══════════════════════════════════════════════════════════════════════
    # Build ontology-typed nodes + edges
    # ═══════════════════════════════════════════════════════════════════════

    # Node 1: vulnerability
    sev_label = "critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0 else "medium"
    exploit_label = "weaponised" if in_kev else ("poc" if epss_score > 0.5 else "none")
    vuln_node = SecurityGraphNode(
        node_id=f"vuln:{cve_id}",
        node_type="vulnerability",
        name=cve_id,
        properties={
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "in_kev": in_kev,
            "kev_ransomware": kev_ransomware,
            "severity": sev_label,
            "exploitability": exploit_label,
            "description": description[:200] + "…" if len(description) > 200 else description,
        },
    )
    graph.nodes.append(vuln_node)

    # Node 2: target asset (environment-typed)
    asset_node_type = _ENV_TO_NODE_TYPE.get(environment.lower() if environment else "", "host")
    asset_node = SecurityGraphNode(
        node_id="asset:target",
        node_type=asset_node_type,
        name=f"Target system ({environment or 'bare_metal'})",
        properties={
            "network_exposure": exposure_label,
            "business_criticality": criticality or "medium",
            "hardening_level": "hardened" if controls_list else "minimal",
            "p_asset_exposure": round(asset_exp, 3),
        },
    )
    graph.nodes.append(asset_node)

    # Edge: vulnerability → exploits → asset
    graph.edges.append(SecurityGraphEdge(
        edge_id=f"e:exploit:{cve_id}:target",
        edge_type="exploits",
        source_node_id=vuln_node.node_id,
        target_node_id=asset_node.node_id,
        confidence=round(min(epss_score * 2 + 0.1, 1.0), 3),
        properties={"p_exploitation": round(graph.p_exploitation, 3)},
    ))

    # Nodes 3+: attack technique nodes (one per ATT&CK entry)
    prev_tech_id = None
    for attack in (attack_chain or []):
        tid = getattr(attack, "technique_id", "?")
        tname = getattr(attack, "technique_name", "Unknown")
        tactic = getattr(attack, "tactic", "unknown")
        kc_pos = getattr(attack, "kill_chain_pos", 0)
        conf = getattr(attack, "confidence", 0.5)

        tech_node = SecurityGraphNode(
            node_id=f"technique:{tid}",
            node_type="attack_path",
            name=f"{tid}: {tname}",
            properties={
                "tactic": tactic,
                "tactic_narrative": _TACTIC_NARRATIVE.get(tactic, tactic),
                "kill_chain_pos": kc_pos,
                "confidence": round(conf, 3),
            },
        )
        graph.nodes.append(tech_node)

        # vulnerability → enables → technique
        graph.edges.append(SecurityGraphEdge(
            edge_id=f"e:enables:{cve_id}:{tid}",
            edge_type="enables",
            source_node_id=vuln_node.node_id,
            target_node_id=tech_node.node_id,
            confidence=round(conf, 3),
        ))

        # technique → targets → asset
        graph.edges.append(SecurityGraphEdge(
            edge_id=f"e:targets:{tid}:target",
            edge_type="targets",
            source_node_id=tech_node.node_id,
            target_node_id=asset_node.node_id,
            confidence=round(conf, 3),
        ))

        # Chain: previous technique → precedes → this technique (by kill chain pos)
        if prev_tech_id:
            graph.edges.append(SecurityGraphEdge(
                edge_id=f"e:precedes:{prev_tech_id}:{tid}",
                edge_type="triggered_by",
                source_node_id=tech_node.node_id,
                target_node_id=prev_tech_id,
                confidence=0.7,
            ))
        prev_tech_id = tech_node.node_id

    # Control nodes
    for ctrl in controls_list:
        ctrl_node_type = _CONTROL_TO_NODE_TYPE.get(ctrl, "control")
        ctrl_node = SecurityGraphNode(
            node_id=f"control:{ctrl}",
            node_type=ctrl_node_type,
            name=ctrl.replace("_", " ").title(),
            properties={
                "hardening_level": "hardened",
                "status": "active",
            },
        )
        graph.nodes.append(ctrl_node)
        # asset → protected_by → control
        graph.edges.append(SecurityGraphEdge(
            edge_id=f"e:control:{ctrl}:target",
            edge_type="protected_by_security_group",
            source_node_id=asset_node.node_id,
            target_node_id=ctrl_node.node_id,
            confidence=0.9,
        ))

    # KEV node (if applicable)
    if in_kev and kev_entry:
        kev_node = SecurityGraphNode(
            node_id="kev:signal",
            node_type="risk_signal",
            name="CISA KEV Entry",
            properties={
                "in_kev": True,
                "ransomware_campaign": kev_ransomware,
                "ransomware_group": getattr(kev_entry, "ransomware_group", None),
                "days_until_due": getattr(kev_entry, "days_until_due", None),
                "required_action": (getattr(kev_entry, "required_action", "") or "")[:120],
            },
        )
        graph.nodes.append(kev_node)
        graph.edges.append(SecurityGraphEdge(
            edge_id=f"e:kev:{cve_id}",
            edge_type="triggers",
            source_node_id=kev_node.node_id,
            target_node_id=vuln_node.node_id,
            confidence=1.0,
        ))

    return graph


def _inline_equation(
    graph: InvestigationGraph,
    asset_exp: float, attack_srf: float, vuln_exp: float,
    misconfig: float, patch_risk: float, reachability: float,
    is_crown: bool,
) -> None:
    p_access = asset_exp * reachability + 0.2 * attack_srf * reachability
    p_exploit = vuln_exp + 0.15 * misconfig * vuln_exp
    p_blocked = (1.0 - patch_risk) * (1.0 - 0.3 * misconfig)
    p = p_access * p_exploit * (1.0 - p_blocked)
    if is_crown:
        p = min(p * 1.25, 1.0)

    graph.p_access = round(min(p_access, 1.0), 3)
    graph.p_exploit_given_access = round(min(p_exploit, 1.0), 3)
    graph.p_blocked = round(min(p_blocked, 1.0), 3)
    graph.p_exploitation = round(min(p, 1.0), 3)
    graph.risk_tier = (
        "CRITICAL" if p >= 0.70 else
        "HIGH"     if p >= 0.45 else
        "MEDIUM"   if p >= 0.25 else
        "LOW"      if p >= 0.10 else
        "MINIMAL"
    )


def _compute_counterfactuals(
    graph: InvestigationGraph,
    ds: Dict[str, float],
    is_crown: bool,
    reachability: float,
) -> List[Dict[str, Any]]:
    results = []

    def _score(patch_risk=None, reachability_=None, misconfig=None, attack_srf=None) -> float:
        ae   = ds.get("p_asset_exposure", 0.5)
        asrf = attack_srf if attack_srf is not None else ds.get("p_attack_surface", 0.5)
        ve   = ds.get("p_vuln_exposure", 0.5)
        mc   = misconfig   if misconfig   is not None else ds.get("p_misconfiguration", 0.3)
        pr   = patch_risk  if patch_risk  is not None else ds.get("p_patch_risk", 0.5)
        rch  = reachability_ if reachability_ is not None else reachability
        p_access   = ae * rch + 0.2 * asrf * rch
        p_exploit  = ve + 0.15 * mc * ve
        p_blocked  = (1.0 - pr) * (1.0 - 0.3 * mc)
        p = p_access * p_exploit * (1.0 - p_blocked)
        if is_crown:
            p = min(p * 1.25, 1.0)
        return round(min(p, 1.0), 3)

    base = graph.p_exploitation

    interventions = [
        ("Apply patch",        "patch_risk=0",           _score(patch_risk=0.0)),
        ("Network isolation",  "reachability=0.15",       _score(reachability_=0.15)),
        ("Harden config",      "misconfiguration=0.1",    _score(misconfig=0.1)),
        ("Reduce attack surface", "attack_surface=0.1",   _score(attack_srf=0.1)),
        ("Patch + isolate",    "patch_risk=0, rch=0.15", _score(patch_risk=0.0, reachability_=0.15)),
    ]

    for label, do_expr, new_p in interventions:
        delta = round(base - new_p, 3)
        pct = round(100 * delta / base, 1) if base > 0 else 0
        results.append({
            "intervention": label,
            "do_expression": f"do({do_expr})",
            "p_before": base,
            "p_after": new_p,
            "delta": delta,
            "reduction_pct": pct,
            "tier_after": (
                "CRITICAL" if new_p >= 0.70 else
                "HIGH"     if new_p >= 0.45 else
                "MEDIUM"   if new_p >= 0.25 else
                "LOW"      if new_p >= 0.10 else
                "MINIMAL"
            ),
        })

    return results


# ── Conversation renderer ─────────────────────────────────────────────────────

def render_conversation(
    graph: InvestigationGraph,
    cve_id: str,
    cve_detail: Dict[str, Any],
    attack_chain: List[Any],
    kev_entry: Optional[Any],
    environment: str,
    criticality: str,
    controls_csv: str,
    playbook_md: str = "",
) -> str:
    """
    Render the related-entity analysis as a multi-step deeper analysis in
    Markdown. Each step introduces one entity, explains its properties in
    terms of the risk domain it drives, and shows how it affects exploitation
    probability.
    """
    turns: List[str] = []
    ds = graph.domain_scores
    controls_list = [c.strip().lower() for c in (controls_csv or "").split(",") if c.strip()]

    # ── Helper ────────────────────────────────────────────────────────────────
    def divider(step: int, icon: str, title: str) -> str:
        return f"\n\n---\n\n## Step {step} — {icon} {title}\n"

    def node_box(node: SecurityGraphNode) -> str:
        lines = [f"```\n[{node.node_type}] {node.name}"]
        for k, v in node.properties.items():
            if v not in (None, "", False, []):
                lines.append(f"  ├── {k}: {v}")
        lines.append("```")
        return "\n".join(lines)

    def edge_line(e: SecurityGraphEdge, src_name: str, tgt_name: str) -> str:
        return f"`{src_name}` —[**{e.edge_type}** conf={e.confidence}]→ `{tgt_name}`"

    # ── Step 1: CVE Profile ───────────────────────────────────────────────────
    vuln_node = graph.node(f"vuln:{cve_id}")
    cvss_score = float(cve_detail.get("cvss_score", 0.0))
    epss_score = float(cve_detail.get("epss_score", 0.0))
    description = cve_detail.get("description", "No description available.")
    in_kev = bool(kev_entry and kev_entry.in_kev)
    kev_ransomware = bool(kev_entry and kev_entry.ransomware_campaign_use)
    vuln_exp = ds.get("p_vuln_exposure", 0.5)

    kev_note = ""
    if in_kev:
        ransomware_group = getattr(kev_entry, "ransomware_group", None)
        days = getattr(kev_entry, "days_until_due", None)
        kev_note = (
            f"\n\n> ⚠️ **CISA KEV** — This CVE has confirmed exploitation in the wild."
            + (f" Ransomware group: **{ransomware_group}**." if ransomware_group else "")
            + (f" Remediation {'**OVERDUE**' if days is not None and days < 0 else f'due in {days} days'}." if days is not None else "")
        )

    s1 = divider(1, "🔍", "Vulnerability Profile")
    s1 += f"""
> **What we know about {cve_id}**

{description}
{kev_note}

{node_box(vuln_node) if vuln_node else ""}

**How this finding drives risk**

| Signal | Value | Domain score driven |
|--------|-------|---------------------|
| CVSS base score | {cvss_score} | `vuln_exposure` ← primary driver |
| EPSS probability | {epss_score:.3f} ({epss_score*100:.1f}% of CVEs scored higher) | `vuln_exposure` amplifier |
| CISA KEV | {'✅ Yes — confirmed exploitation' if in_kev else '❌ Not in KEV'} | `vuln_exposure` override when True |

**`p_vuln_exposure` = {vuln_exp:.3f}** ({_score_label(vuln_exp)})
This score feeds directly into the exploitation probability calculation.
"""
    turns.append(s1)

    # ── Step 2: Target Environment ────────────────────────────────────────────
    asset_node = graph.node("asset:target")
    asset_exp  = ds.get("p_asset_exposure", 0.5)
    attack_srf = ds.get("p_attack_surface", 0.5)
    reachability_label = graph.reachability_label

    env_label = environment or "bare_metal"
    node_type_label = _ENV_TO_NODE_TYPE.get(env_label.lower(), "host")

    s2 = divider(2, "🏗️", "Target Environment")
    s2 += f"""
> **Ontology node type: `{node_type_label}`**

The affected asset lives in a **{env_label}** environment with criticality **{criticality or 'medium'}**.

{node_box(asset_node) if asset_node else ""}

**How this node's properties map to domain scores**

| Property | Value | Domain score |
|----------|-------|--------------|
| `network_exposure` | `{reachability_label}` (reachability = {_EXPOSURE_TO_REACHABILITY.get(reachability_label, 0):.2f}) | `p_asset_exposure` = {asset_exp:.3f} |
| `business_criticality` | `{criticality or 'medium'}` | Crown-jewel amplifier ×1.25 if `crown_jewel` |
| `hardening_level` | `{'hardened' if controls_list else 'minimal'}` | `p_attack_surface` = {attack_srf:.3f} |

**Edge created:** {edge_line(graph.edges[0], cve_id, "Target system") if graph.edges else ""}

`p_asset_exposure` and `p_attack_surface` together determine **P(access)** — the probability
the attacker can reach and interact with this asset.
"""
    turns.append(s2)

    # ── Step 3: Attack Path ───────────────────────────────────────────────────
    tech_nodes = [n for n in graph.nodes if n.node_type == "attack_path"]
    s3 = divider(3, "⚔️", "Attack Path (ATT&CK Mapping)")

    if tech_nodes:
        s3 += f"""
> **{len(tech_nodes)} technique(s) mapped from {cve_id}**

The vulnerability enables the following kill chain. Each node is typed as
`attack_path` in the ontology and connected via `enables` → `targets` edges.

| Kill Chain Pos | Technique | Tactic | Tactic Meaning | Confidence |
|---|---|---|---|---|
"""
        sorted_techs = sorted(
            tech_nodes,
            key=lambda n: n.properties.get("kill_chain_pos", 99),
        )
        for t in sorted_techs:
            p = t.properties
            kc = p.get("kill_chain_pos", "?")
            tactic = p.get("tactic", "unknown")
            meaning = p.get("tactic_narrative", _TACTIC_NARRATIVE.get(tactic, tactic))
            conf = p.get("confidence", 0)
            s3 += f"| {kc} | `{t.name}` | {tactic} | {meaning} | {conf:.2f} |\n"

        # Show graph edges for first technique
        if sorted_techs:
            first = sorted_techs[0]
            enables_edge = next(
                (e for e in graph.edges if e.edge_type == "enables" and e.target_node_id == first.node_id),
                None,
            )
            if enables_edge:
                s3 += f"\n**Example edge:** {edge_line(enables_edge, cve_id, first.name)}\n"
    else:
        s3 += "\n> No ATT&CK techniques were mapped during enrichment.\n"

    s3 += f"""
**Why this matters:** These nodes determine which tactic family dominates the
risk calculation. Execution-phase techniques amplify `p_vuln_exposure`;
lateral-movement techniques amplify `p_attack_surface`.
"""
    turns.append(s3)

    # ── Step 4: Controls ──────────────────────────────────────────────────────
    ctrl_nodes = [n for n in graph.nodes if "control" in n.node_type.lower()]
    misconfig  = ds.get("p_misconfiguration", 0.3)
    patch_risk = ds.get("p_patch_risk", 0.5)
    s4 = divider(4, "🛡️", "Controls in Place")

    if ctrl_nodes:
        s4 += f"""
> **{len(ctrl_nodes)} control(s) detected in your environment**

Each control node is connected via `protected_by_security_group` edge from the asset.

| Control | Ontology type | Hardening level | Domain score impact |
|---------|--------------|-----------------|---------------------|
"""
        for c in ctrl_nodes:
            s4 += (
                f"| {c.name} | `{c.node_type}` | "
                f"{c.properties.get('hardening_level', '?')} | "
                f"Reduces `p_misconfiguration` and `p_attack_surface` |\n"
            )
    else:
        s4 += "\n> No controls were provided. Assuming baseline hardening.\n"

    s4 += f"""
| Domain | Score | Interpretation |
|--------|-------|----------------|
| `p_misconfiguration` | {misconfig:.3f} | {_score_label(misconfig)} — drives P(blocked) |
| `p_patch_risk`       | {patch_risk:.3f} | {_score_label(patch_risk)} — drives P(blocked) |

**`P(blocked)` = (1 − patch_risk) × (1 − 0.3 × misconfiguration) = {graph.p_blocked:.3f}**
"""
    turns.append(s4)

    # ── Step 5: Domain Score Summary ─────────────────────────────────────────
    s5 = divider(5, "📊", "Risk Domain Scores")
    s5 += f"""
> **Risk scores derived from related entities**

These scores are computed from the properties of each related entity
discovered during enrichment.

| Domain | Score | Tier | Primary source |
|--------|-------|------|----------------|
| `p_asset_exposure`  | {ds.get('p_asset_exposure', 0):.3f}  | {_score_label(ds.get('p_asset_exposure', 0))}  | `network_exposure` enum on asset node |
| `p_attack_surface`  | {ds.get('p_attack_surface', 0):.3f}  | {_score_label(ds.get('p_attack_surface', 0))}  | CVSS S-field + environment type |
| `p_vuln_exposure`   | {ds.get('p_vuln_exposure', 0):.3f}   | {_score_label(ds.get('p_vuln_exposure', 0))}   | CVSS base + EPSS + KEV override |
| `p_misconfiguration`| {ds.get('p_misconfiguration', 0):.3f} | {_score_label(ds.get('p_misconfiguration', 0))} | CVSS PR-field + controls present |
| `p_patch_risk`      | {ds.get('p_patch_risk', 0):.3f}      | {_score_label(ds.get('p_patch_risk', 0))}      | KEV status + EPSS |
| `p_asset_exposure` (crown jewel?) | {'Yes ×1.25' if ds.get('is_crown_jewel') else 'No'} | — | `business_criticality` == `crown_jewel` |
"""
    turns.append(s5)

    # ── Step 6: Structural Equation Walk-through ──────────────────────────────
    tier_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "MINIMAL": "⚪"}.get(
        graph.risk_tier, "❓"
    )
    s6 = divider(6, "🎯", "Exploitation Probability — Deeper Analysis")
    s6 += f"""
> **How the risk model combines the related entities**

Exploitation probability is calculated by multiplying three factors derived
from the entities found above:

```
P(exploitation) = P(access) × P(exploit | access) × (1 − P(blocked))
```

**Walking through each factor:**

**P(access)** — can the attacker reach the asset?
```
P(access) = asset_exposure × reachability + 0.2 × attack_surface × reachability
          = {ds.get('p_asset_exposure',0):.3f} × {_EXPOSURE_TO_REACHABILITY.get(graph.reachability_label, 0):.2f} + 0.2 × {ds.get('p_attack_surface',0):.3f} × {_EXPOSURE_TO_REACHABILITY.get(graph.reachability_label, 0):.2f}
          = {graph.p_access:.3f}
```

**P(exploit | access)** — if they reach it, can they exploit it?
```
P(exploit|access) = vuln_exposure + 0.15 × misconfiguration × vuln_exposure
                  = {ds.get('p_vuln_exposure',0):.3f} + 0.15 × {ds.get('p_misconfiguration',0):.3f} × {ds.get('p_vuln_exposure',0):.3f}
                  = {graph.p_exploit_given_access:.3f}
```

**P(blocked)** — will existing controls stop the attempt?
```
P(blocked) = (1 − patch_risk) × (1 − 0.3 × misconfiguration)
           = (1 − {ds.get('p_patch_risk',0):.3f}) × (1 − 0.3 × {ds.get('p_misconfiguration',0):.3f})
           = {graph.p_blocked:.3f}
```

**Result:**
```
P(exploitation) = {graph.p_access:.3f} × {graph.p_exploit_given_access:.3f} × (1 − {graph.p_blocked:.3f})
                = {graph.p_exploitation:.3f}
```

{tier_emoji} **Risk tier: {graph.risk_tier}** (P = {graph.p_exploitation:.3f})
{'> ⚠️ Crown-jewel amplification (×1.25) applied.' if ds.get('is_crown_jewel') else ''}
"""
    turns.append(s6)

    # ── Step 7: Remediation scenarios ────────────────────────────────────────
    s7 = divider(7, "🔧", "Remediation Scenarios — What-If Analysis")
    s7 += f"""
> **What changes if you take action on a related entity?**

Each row shows how exploitation probability changes if you act on one of the
entities identified above. Use this to prioritise your remediation steps.

| Action | Targets entity | P before | P after | Risk drop | Tier after |
|---|---|---|---|---|---|
"""
    for cf in graph.counterfactuals:
        # Show the entity being acted on in plain language, not do-expression syntax
        entity_label = cf['do_expression'].replace("do(", "").replace(")", "")
        s7 += (
            f"| {cf['intervention']} "
            f"| `{entity_label}` "
            f"| {cf['p_before']:.3f} "
            f"| {cf['p_after']:.3f} "
            f"| −{cf['delta']:.3f} ({cf['reduction_pct']}%) "
            f"| {cf['tier_after']} |\n"
        )
    turns.append(s7)

    # ── Step 8: Detection Playbook ────────────────────────────────────────────
    s8 = divider(8, "🔎", "Detection Engineering Playbook")
    if playbook_md:
        s8 += "\n" + playbook_md
    else:
        s8 += "\n> Run with `--source <data_source_id>` to get NL investigation questions.\n"
    turns.append(s8)

    # ── Assemble header + turns ───────────────────────────────────────────────
    tier_badge = f"{tier_emoji} **{graph.risk_tier}**"
    header = f"""# CVE Investigation — {cve_id}

{tier_badge} &nbsp;|&nbsp; P(exploitation) = {graph.p_exploitation:.3f} &nbsp;|&nbsp; Environment: {env_label} &nbsp;|&nbsp; Criticality: {criticality or 'medium'}

> This report finds the entities related to {cve_id} — the affected asset,
> mapped attack techniques, active controls, and threat signals — then
> performs a deeper analysis to show how each entity contributes to the
> overall exploitation probability and where to focus detection.

**Related entities found:** {len(graph.nodes)} &nbsp;|&nbsp; **Relationships:** {len(graph.edges)}
"""

    return header + "".join(turns)
