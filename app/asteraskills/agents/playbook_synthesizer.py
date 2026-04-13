"""
playbook_synthesizer.py — Causal + Knowledge-Base Grounded Playbook Synthesis
==============================================================================

Bridges three knowledge layers to produce investigation playbooks that are
grounded in causal reasoning rather than static templates:

  Layer 1 — Causal structural equation (exploitation_risk_model.py)
            P(exploitation) = P(access) × P(exploit|access) × (1 - P(blocked))
            Synthesises domain scores directly from CVE enrichment data + environment
            context when a full security graph is unavailable.

  Layer 2 — Ontology domain scores (CVSS → domain score mapping)
            Maps CVSS vector fields to the seven risk domains used by the causal model:
            asset_exposure, vuln_exposure, patch_risk, attack_surface, misconfiguration,
            network_exposure, blast_radius. Uses Pearl's Ladder of Causation:
              Rung 1 — P(exploitation | environment)       [observational]
              Rung 2 — P(exploitation | do(patch=applied)) [interventional / counterfactual]
              Rung 3 — P(exploitation | had we isolated)   [counterfactual planning]

  Layer 3 — Knowledge base (Qdrant vector store)
            Retrieves matching investigation questions from detection_playbooks collection,
            ATT&CK technique details from attack_techniques collection, and CWE/CAPEC
            context from the cwe_capec collection.
            Questions are ranked by causal relevance: the domain with the highest score
            in the structural equation drives which playbook questions surface first.

Output: PlaybookSynthesisResult
  - P(exploitation), risk tier, all structural equation components
  - Enabled ATT&CK tactics with causal explanation (which domain drives each)
  - Counterfactual interventions (do-calculus: what reduces risk most)
  - Ranked data sources (mapped from enabled tactics + domain scores)
  - Investigation questions per source, annotated with causal framing
  - Compensating controls derived from highest-delta counterfactuals

Usage::

    from asteraskills.agents.playbook_synthesizer import PlaybookSynthesizer

    synth = PlaybookSynthesizer()
    result = synth.synthesize(
        cve_id="CVE-2024-26855",
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        cvss_base=5.5,
        epss_score=0.0001,
        in_kev=False,
        environment_type="k8s",
        asset_criticality="crown_jewel",
        internet_facing=True,
        source_id="kubernetes_audit",    # user-selected; None = auto-recommend
    )
    print(result.to_markdown())
"""

from __future__ import annotations

import logging
import re
import sys
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Causal engine path setup ────────────────────────────────────────────────────
# Allow importing from the causalgraphs app_f/ directory
_CAUSALGRAPHS = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Nexcraft", "causalgraphs")
)
_APP_F = os.path.join(_CAUSALGRAPHS, "app_f")
_EXPERT_BACKEND = os.path.join(_CAUSALGRAPHS, "expertsystem", "backend", "app")
for _p in (_APP_F, _EXPERT_BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ══════════════════════════════════════════════════════════════════════════════
# CVSS → domain score synthesis
# ══════════════════════════════════════════════════════════════════════════════

# Maps CVSS AV field to (reachability_key, network_exposure_score)
_AV_TO_REACHABILITY: Dict[str, Tuple[str, float]] = {
    "N": ("public_internet", 1.00),    # Network
    "A": ("partner_exposed", 0.75),    # Adjacent
    "L": ("vpc_internal",    0.30),    # Local
    "P": ("cluster_internal",0.10),    # Physical
}

# Scope:Changed amplifies attack surface (T1611 container escape, hypervisor breakout)
_SCOPE_ATTACK_SURFACE: Dict[str, float] = {"C": 0.75, "U": 0.35}

# PR field: privilege required — no auth needed implies misconfigured/open service
_PR_MISCONFIGURATION: Dict[str, float] = {"N": 0.60, "L": 0.40, "H": 0.20}

# Environment amplifies attack surface beyond the base CVE
_ENV_ATTACK_SURFACE_BOOST: Dict[str, float] = {
    "k8s":       0.20,   # shared kernel → cluster-wide blast
    "container": 0.10,
    "cloud_vm":  0.05,
    "bare_metal": 0.00,
    "mixed":     0.12,
}

_CRITICALITY_CROWN_JEWEL = {"crown_jewel", "critical", "high"}

_DOMAIN_TO_TACTICS: Dict[str, List[str]] = {
    "asset_exposure":   ["TA0001"],               # Initial Access
    "vuln_exposure":    ["TA0002"],               # Execution
    "misconfiguration": ["TA0004", "TA0003"],     # Privilege Escalation, Persistence
    "attack_surface":   ["TA0008", "TA0001"],     # Lateral Movement, Initial Access
    "patch_risk":       ["TA0002"],               # Execution (unpatched = exploitable)
}

# Maps ATT&CK tactic → most relevant data sources
_TACTIC_TO_SOURCES: Dict[str, List[str]] = {
    "TA0001": ["windows_security_events", "web_application_logs", "azure_activity", "aws_cloudtrail"],
    "TA0002": ["sysmon", "linux_auditd", "mde", "web_application_logs"],
    "TA0003": ["sysmon", "linux_auditd", "windows_security_events"],
    "TA0004": ["windows_security_events", "kubernetes_audit", "azure_activity", "aws_cloudtrail"],
    "TA0008": ["network_flows", "sysmon", "windows_security_events"],
}


def _parse_cvss_fields(cvss_vector: str) -> Dict[str, str]:
    """Parse CVSS:3.x/AV:N/AC:L/... into {'AV': 'N', 'AC': 'L', ...}."""
    fields: Dict[str, str] = {}
    for part in cvss_vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            fields[k.upper()] = v.upper()
    return fields


def cvss_to_domain_scores(
    cvss_vector: str,
    cvss_base: float,
    epss_score: float = 0.0,
    in_kev: bool = False,
    kev_ransomware: bool = False,
    environment_type: str = "bare_metal",
    asset_criticality: str = "medium",
    internet_facing: bool = False,
    has_controls: bool = False,
) -> Dict[str, float]:
    """
    Synthesise causal domain scores from CVSS vector + environment context.

    This implements Rung 1 of Pearl's Ladder — the observational layer.
    Each domain score represents a conditional probability given available evidence.

    Returns a dict ready for ExploitationRiskModel.score():
        p_asset_exposure, p_vuln_exposure, p_patch_risk,
        p_attack_surface, p_misconfiguration, reachability_value, is_crown_jewel
    """
    fields = _parse_cvss_fields(cvss_vector)
    av  = fields.get("AV", "L")
    ac  = fields.get("AC", "L")
    pr  = fields.get("PR", "N")
    scope = fields.get("S", "U")
    c   = fields.get("C", "N")
    i_  = fields.get("I", "N")
    a   = fields.get("A", "N")

    # Reachability from AV
    reachability_key, reachability_base = _AV_TO_REACHABILITY.get(av, ("vpc_internal", 0.30))

    # Internet-facing boosts reachability even for AV:L (e.g. container on public node)
    reachability_value = min(1.0, reachability_base + (0.20 if internet_facing and av == "L" else 0.0))

    # p_asset_exposure: how exposed is the ASSET itself (not just the vuln)
    criticality_weight = {"crown_jewel": 0.90, "high": 0.70, "medium": 0.50, "low": 0.25}.get(
        asset_criticality.lower(), 0.50
    )
    p_asset_exposure = min(1.0, reachability_value * 0.6 + criticality_weight * 0.4)

    # p_vuln_exposure: how exploitable is the VULNERABILITY
    # CVSS base (normalized) is the primary signal; EPSS adds exploit-in-wild evidence
    epss_boost = min(0.20, epss_score * 10.0)   # EPSS 0.02 → +0.20 boost
    kev_boost  = 0.25 if in_kev else 0.0
    ransomware_boost = 0.10 if kev_ransomware else 0.0
    ac_penalty = -0.10 if ac == "H" else 0.0    # High complexity = harder to exploit
    p_vuln_exposure = min(1.0, max(0.0,
        (cvss_base / 10.0) + epss_boost + kev_boost + ransomware_boost + ac_penalty
    ))

    # p_patch_risk: probability that the patch / remediation is NOT in place
    # KEV + ransomware = very high patch urgency (likely unpatched in many orgs)
    # EPSS > 0.01 = actively exploited = higher patch risk if we assume average org
    if in_kev and kev_ransomware:
        p_patch_risk = 0.85
    elif in_kev:
        p_patch_risk = 0.70
    elif epss_score > 0.01:
        p_patch_risk = 0.50
    else:
        p_patch_risk = 0.30
    if has_controls:
        p_patch_risk = max(0.10, p_patch_risk - 0.25)

    # p_attack_surface: how wide is the exploitable surface
    # S:Changed = vulnerability spans beyond the component (amplifier)
    # K8s/container = shared kernel / network = wider surface
    env_boost = _ENV_ATTACK_SURFACE_BOOST.get(environment_type.lower(), 0.0)
    scope_base = _SCOPE_ATTACK_SURFACE.get(scope, 0.35)
    p_attack_surface = min(1.0, scope_base + env_boost)

    # p_misconfiguration: are there IAM / configuration weaknesses enabling this?
    # PR:N = no auth required → service is open / misconfigured
    # PR:H = needs admin → less likely an open misconfig
    p_misconfiguration = _PR_MISCONFIGURATION.get(pr, 0.40)
    # Environments with complex RBAC (K8s, cloud) have higher misconfiguration risk
    if environment_type in ("k8s", "cloud_vm"):
        p_misconfiguration = min(1.0, p_misconfiguration + 0.15)

    is_crown_jewel = asset_criticality.lower() in _CRITICALITY_CROWN_JEWEL

    return {
        "p_asset_exposure":   round(p_asset_exposure,   4),
        "p_vuln_exposure":    round(p_vuln_exposure,     4),
        "p_patch_risk":       round(p_patch_risk,        4),
        "p_attack_surface":   round(p_attack_surface,    4),
        "p_misconfiguration": round(p_misconfiguration,  4),
        "reachability_value": round(reachability_value,  4),
        "reachability_key":   reachability_key,
        "is_crown_jewel":     is_crown_jewel,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Data source ranking from causal domain scores
# ══════════════════════════════════════════════════════════════════════════════

def rank_sources_by_causal_relevance(
    enabled_tactics: List[str],
    domain_scores: Dict[str, float],
    preferred_source: Optional[str] = None,
) -> List[Dict]:
    """
    Rank data sources by causal relevance to the enabled ATT&CK tactics and
    domain scores from the structural equation.

    Each source gets a relevance score = sum of (tactic_domain_score × tactic_coverage).
    The preferred_source (user-selected) is always returned first but still scored.
    """
    source_scores: Dict[str, float] = {}

    # Domain score for each tactic
    tactic_domain_map = {
        "TA0001": max(domain_scores.get("p_asset_exposure", 0),
                      domain_scores.get("p_attack_surface", 0)),
        "TA0002": domain_scores.get("p_vuln_exposure", 0),
        "TA0003": domain_scores.get("p_misconfiguration", 0) * 0.7,
        "TA0004": domain_scores.get("p_misconfiguration", 0),
        "TA0008": domain_scores.get("p_attack_surface", 0),
    }

    for tactic_id in enabled_tactics:
        tactic_weight = tactic_domain_map.get(tactic_id, 0.0)
        for source_id in _TACTIC_TO_SOURCES.get(tactic_id, []):
            source_scores[source_id] = source_scores.get(source_id, 0.0) + tactic_weight

    # Normalise to [0, 1]
    max_score = max(source_scores.values(), default=1.0)
    ranked = sorted(
        [
            {
                "source_id": sid,
                "relevance_score": round(score / max_score, 3),
                "driving_tactics": [
                    t for t in enabled_tactics if sid in _TACTIC_TO_SOURCES.get(t, [])
                ],
                "causal_explanation": _source_causal_explanation(sid, domain_scores, enabled_tactics),
            }
            for sid, score in source_scores.items()
        ],
        key=lambda x: x["relevance_score"],
        reverse=True,
    )

    # Promote user-selected source to top if not already there
    if preferred_source:
        ranked = [r for r in ranked if r["source_id"] == preferred_source] + \
                 [r for r in ranked if r["source_id"] != preferred_source]

    return ranked[:6]  # top 6 sources


def _source_causal_explanation(
    source_id: str,
    domain_scores: Dict[str, float],
    enabled_tactics: List[str],
) -> str:
    """One-line causal explanation for why this source is relevant."""
    ae = domain_scores.get("p_asset_exposure", 0)
    ve = domain_scores.get("p_vuln_exposure", 0)
    mc = domain_scores.get("p_misconfiguration", 0)
    asurf = domain_scores.get("p_attack_surface", 0)

    explanations: Dict[str, str] = {
        "windows_security_events": (
            f"P(access)={ae:.2f} — logon anomalies and lateral movement are primary risk paths"
        ),
        "sysmon": (
            f"P(exploit|access)={ve:.2f} — process execution and injection are the exploitation pathway"
        ),
        "network_flows": (
            f"P(attack_surface)={asurf:.2f} — network-level C2 beaconing or reconnaissance is elevated"
        ),
        "kubernetes_audit": (
            f"P(misconfiguration)={mc:.2f} — RBAC or privileged container misconfigs are the risk driver"
        ),
        "azure_activity": (
            f"P(misconfiguration)={mc:.2f} — cloud IAM privilege escalation path is active"
        ),
        "aws_cloudtrail": (
            f"P(misconfiguration)={mc:.2f} — AWS IAM or S3 misconfiguration is the risk driver"
        ),
        "linux_auditd": (
            f"P(exploit|access)={ve:.2f} — kernel or local privilege escalation requires syscall visibility"
        ),
        "mde": (
            f"P(exploitation)={ae*ve:.2f} — endpoint-level process and file telemetry captures the impact phase"
        ),
        "web_application_logs": (
            f"P(exploit|access)={ve:.2f} — web-facing RCE or injection is the primary exploitation route"
        ),
    }
    return explanations.get(source_id, f"relevant to enabled tactics: {', '.join(enabled_tactics)}")


# ══════════════════════════════════════════════════════════════════════════════
# Knowledge base retrieval
# ══════════════════════════════════════════════════════════════════════════════

def _kb_fetch_attack_techniques(tactic_ids: List[str], cve_id: str) -> List[Dict]:
    """Retrieve ATT&CK technique details from the vector store for enabled tactics."""
    try:
        from asteraskills.storage.vector_store import VectorStoreClient
        import asyncio

        client = VectorStoreClient()
        query = f"{cve_id} " + " ".join(tactic_ids)
        results = asyncio.run(client.query(
            collection_name="attack_techniques",
            query_text=query,
            top_k=6,
        ))
        return [
            {
                "technique_id":   r.get("metadata", {}).get("technique_id", ""),
                "technique_name": r.get("metadata", {}).get("name", ""),
                "tactic":         r.get("metadata", {}).get("tactic", ""),
                "description":    r.get("text", "")[:300],
            }
            for r in results
        ]
    except Exception as exc:
        log.debug("KB ATT&CK technique fetch failed: %s", exc)
        return []


def _kb_fetch_playbook_questions(
    query: str,
    source_id: str,
    investigation_type: Optional[str],
    top_k: int = 2,
) -> List[Dict]:
    """Retrieve NL investigation questions from the detection_playbooks collection."""
    try:
        from asteraskills.storage.vector_store import VectorStoreClient
        from asteraskills.storage.collections import DetectionCollections
        import asyncio

        client = VectorStoreClient()
        filters: Dict[str, Any] = {"source_id": source_id}
        if investigation_type:
            filters["investigation_type"] = investigation_type

        results = asyncio.run(client.query(
            collection_name=DetectionCollections.PLAYBOOKS,
            query_text=query,
            top_k=top_k,
            filter_params=filters,
        ))
        return [
            {
                "title":                  r.get("metadata", {}).get("title", ""),
                "trigger":                r.get("metadata", {}).get("trigger", ""),
                "investigation_type":     r.get("metadata", {}).get("investigation_type", ""),
                "investigation_questions":r.get("metadata", {}).get("investigation_questions", []),
                "attack_techniques":      r.get("metadata", {}).get("attack_techniques", []),
                "similarity":             round(r.get("score", 0), 3),
            }
            for r in results
        ]
    except Exception as exc:
        log.debug("KB playbook fetch failed for %s: %s", source_id, exc)
        return []


def _kb_fetch_cwe_context(cve_id: str) -> Optional[str]:
    """Retrieve CWE/CAPEC context for the CVE from the knowledge base."""
    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("cve_enrich")
        if not factory:
            return None
        tool = factory()
        raw = tool.invoke({"cve_id": cve_id})
        import json
        data = json.loads(raw) if isinstance(raw, str) else raw
        cwes = data.get("cwes", [])
        if cwes:
            return f"CWE context: {', '.join(str(c) for c in cwes[:3])}"
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Causal framing of investigation questions
# ══════════════════════════════════════════════════════════════════════════════

_TACTIC_INVESTIGATION_TYPE: Dict[str, str] = {
    "TA0001": "initial_access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege_escalation",
    "TA0008": "lateral_movement",
}

# Domain name → human-readable explanation prefix
_DOMAIN_FRAMING: Dict[str, str] = {
    "p_asset_exposure":   "Asset exposure is elevated",
    "p_vuln_exposure":    "Vulnerability exploitability is elevated",
    "p_patch_risk":       "Patch/remediation gap is likely",
    "p_attack_surface":   "Attack surface is broad",
    "p_misconfiguration": "Misconfiguration risk is elevated",
}


def _frame_questions_causally(
    questions: List[str],
    dominant_domain: str,
    domain_score: float,
    tactic_id: str,
    exploitation_probability: float,
) -> List[Dict]:
    """
    Annotate each NL investigation question with causal framing:
    - which causal domain drives it
    - the domain score
    - the ATT&CK tactic it maps to
    - priority order based on P(exploitation) × domain_score
    """
    tactic_name = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0008": "Lateral Movement",
    }.get(tactic_id, tactic_id)

    domain_label = _DOMAIN_FRAMING.get(dominant_domain, dominant_domain)

    framed = []
    for i, q in enumerate(questions):
        framed.append({
            "question":         q,
            "causal_domain":    dominant_domain,
            "domain_score":     round(domain_score, 3),
            "tactic":           f"{tactic_id} {tactic_name}",
            "causal_note":      (
                f"{domain_label} ({domain_score:.2f}) — "
                f"this question addresses the {tactic_name} pathway. "
                f"P(exploitation)={exploitation_probability:.2f}."
            ),
            "priority":         i + 1,
        })
    return framed


# ══════════════════════════════════════════════════════════════════════════════
# Counterfactual → compensating control mapping
# ══════════════════════════════════════════════════════════════════════════════

def _counterfactuals_to_controls(
    counterfactuals: Dict[str, float],
    environment_type: str = "bare_metal",
    asset_criticality: str = "medium",
    cve_id: str = "",
    cvss_vector: str = "",
) -> List[Dict]:
    """
    Convert causal counterfactual deltas into actionable compensating controls.
    Ranked by absolute delta (largest risk reduction first).
    Controls include environment-specific steps and data-platform queries so a
    security engineer can act immediately without further interpretation.
    """
    env = (environment_type or "bare_metal").lower()
    crit = (asset_criticality or "medium").lower()
    is_k8s       = "k8s" in env or "kube" in env or "container" in env
    is_cloud     = "cloud" in env or "vm" in env or "ec2" in env or "gce" in env
    is_crown     = crit == "crown_jewel"

    # ── Per-control step libraries, keyed by control type ──────────────────────
    _STEPS: Dict[str, Dict[str, List[str]]] = {
        "iam_hardening": {
            "k8s": [
                "Enumerate over-privileged service accounts:\n"
                "  `kubectl get clusterrolebindings -o json | "
                "jq '.items[] | select(.roleRef.name | test(\"admin|cluster\")) | "
                "{binding: .metadata.name, sa: .subjects}'`",
                "List pods running as root or with privilege escalation allowed:\n"
                "  `kubectl get pods -A -o json | "
                "jq '.items[] | select(.spec.containers[].securityContext.allowPrivilegeEscalation == true"
                " or .spec.securityContext.runAsUser == 0) | .metadata'`",
                "Identify service accounts with automountServiceAccountToken not disabled:\n"
                "  `kubectl get serviceaccounts -A -o json | "
                "jq '.items[] | select(.automountServiceAccountToken != false) | "
                "{ns: .metadata.namespace, name: .metadata.name}'`",
                "Restrict each affected ServiceAccount to minimum required verbs/resources "
                "using a scoped Role (not ClusterRole) bound to the specific namespace only.",
                "Enable PodSecurity admission at `restricted` level for crown-jewel namespaces:\n"
                "  `kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted`",
            ] if is_k8s else [
                "Audit IAM role assignments — remove wildcard or admin policies not needed "
                "by the service's documented function.",
                "Enforce least-privilege: attach only policies whose Action list is explicitly "
                "enumerated (no `*`) and whose Resource is scoped to the specific ARN/bucket/table.",
                "Rotate and scope service account keys; disable unused accounts.",
            ],
            "cloud": [
                "List IAM roles with wildcard permissions:\n"
                "  AWS: `aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument"
                " | tostring | contains(\"*\"))'`",
                "Audit attached policies and inline policies for `*:*` or `iam:PassRole`.",
                "Enable IAM Access Analyzer and triage findings for the affected resource.",
                "Remove unused access keys older than 90 days: `aws iam list-access-keys`.",
            ],
            "generic": [
                "Audit privileged account assignments and remove any accounts not actively used "
                "by the affected service in the last 30 days.",
                "Enforce separation of duties: no single account should hold both read and admin "
                "rights to the affected data store or service.",
                "Enable MFA for all privileged accounts touching this asset.",
            ],
        },
        "network_isolation": {
            "k8s": [
                "Apply a deny-all-ingress NetworkPolicy to the affected namespace immediately, "
                "then allowlist only required peer services:\n"
                "  ```yaml\n  apiVersion: networking.k8s.io/v1\n  kind: NetworkPolicy\n"
                "  metadata:\n    name: deny-all-ingress\n    namespace: <ns>\n"
                "  spec:\n    podSelector: {}\n    policyTypes: [Ingress]\n  ```",
                "Change affected Service type from LoadBalancer/NodePort to ClusterIP if external "
                "access is not required: `kubectl patch svc <svc> -p '{\"spec\":{\"type\":\"ClusterIP\"}}'`",
                "Verify no Ingress object exposes the affected pods externally:\n"
                "  `kubectl get ingress -A -o json | jq '.items[] | "
                "select(.spec.rules[].host | test(\"<service>\"))'`",
            ] if is_k8s else [
                "Update security group / firewall rule to block inbound access to the affected "
                "port from 0.0.0.0/0; restrict to specific CIDR ranges only.",
                "Place the service behind a private load balancer (internal-only) if it does not "
                "need public internet exposure.",
            ],
            "generic": [
                "Block inbound traffic to the affected service/port from untrusted networks.",
                "Route traffic through a WAF or reverse proxy to filter malformed inputs.",
            ],
        },
        "patch": {
            "k8s": [
                "Check current node kernel versions:\n"
                "  `kubectl get nodes -o custom-columns="
                "NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.osImage`",
                "Cordon and drain each affected node, then patch:\n"
                "  `kubectl cordon <node> && kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`\n"
                "  On the node: `apt-get update && apt-get upgrade -y linux-image-$(uname -r)`",
                "Verify patched kernel on re-join: `kubectl get nodes` — confirm kernel version bump.",
                "If managed cluster (EKS/GKE/AKS): trigger a node-pool upgrade via the cloud console "
                "or CLI to roll nodes to a patched AMI/image.",
            ] if is_k8s else [
                "Apply the vendor-issued patch per the security advisory.",
                "Schedule a maintenance window; validate patch in staging before production rollout.",
                "Verify the patched version is running: `uname -r` (kernel) or `<package> --version`.",
            ],
            "generic": [
                "Apply the vendor patch per the published security advisory.",
                "If patch is unavailable, apply vendor-recommended workaround and track the CVE fix ETA.",
            ],
        },
        "surface_reduction": {
            "k8s": [
                "Enumerate all exposed ports per pod:\n"
                "  `kubectl get pods -A -o json | jq '.items[] | "
                "{name:.metadata.name, ports:[.spec.containers[].ports[]?.containerPort]}'`",
                "Remove or comment out unused port declarations in the Deployment/StatefulSet spec.",
                "Disable the Kubernetes API server's unauthenticated port if still enabled "
                "(--insecure-port=0 in kube-apiserver manifest).",
                "Restrict RBAC verbs to only `get`, `list`, `watch` for read-only consumers; "
                "remove `create`, `delete`, `patch` where not needed.",
            ] if is_k8s else [
                "Disable unused services/ports on the host: `systemctl disable <service>`.",
                "Apply a host-based firewall (iptables/ufw) allowing only required ports.",
            ],
            "generic": [
                "Disable or remove features/endpoints not required by the service.",
                "Enforce network micro-segmentation so only named peers can reach the service.",
            ],
        },
        "emergency_combined": {
            "k8s": [
                "IMMEDIATE — apply NetworkPolicy deny-all-ingress (see network_isolation steps).",
                "IMMEDIATE — cordon all unpatched nodes (see patch steps).",
                "Within 2h — apply patch to drained nodes and uncordon.",
                "After patch — remove the temporary deny-all NetworkPolicy and re-apply the "
                "scoped allowlist.",
            ],
            "generic": [
                "IMMEDIATE — isolate the service from external traffic.",
                "Apply the patch within the maintenance window.",
                "Re-enable access after confirming the patched version is running.",
            ],
        },
    }

    # ── Natural-language data-platform questions per control type ──────────────
    # These are phrased so an engineer can paste them directly into a NL-to-SQL
    # data platform (e.g. the asteraskills query interface) without writing SQL.
    _cve = cve_id or "this CVE"
    _DATA_QUESTIONS: Dict[str, List[str]] = {
        "iam_hardening": (
            [
                "Which service accounts in the cluster have a ClusterRoleBinding to a role "
                "containing 'admin' or wildcard verbs, and in which namespaces do they run?",
                "Show me all RBAC binding create, update, patch, or delete events from the "
                "audit log in the last 7 days, grouped by user agent and namespace.",
                "Which pods are currently running as root or have allowPrivilegeEscalation "
                "set to true, outside of the kube-system namespace?",
                "List all service accounts that have automountServiceAccountToken enabled "
                "and are bound to roles with write permissions.",
            ] if is_k8s else [
                "Which IAM roles or users have wildcard (*) actions in their attached policies, "
                "and when were those policies last modified?",
                "Show all IAM policy attachment and access key creation events from the last "
                "7 days for the account hosting the affected asset.",
                "Which principals have iam:PassRole or sts:AssumeRole permissions that could "
                "allow privilege escalation to an admin role?",
            ]
        ),
        "network_isolation": (
            [
                "Show all inbound connections to the affected service in the last 24 hours "
                "that originated from IPs outside the known cluster CIDR ranges.",
                "Which namespaces in the cluster have no NetworkPolicy applied, and which "
                "pods in those namespaces have a Service of type LoadBalancer or NodePort?",
                "Are there any Ingress objects that expose pods from the affected namespace "
                "to the public internet?",
            ] if is_k8s else [
                "Which security groups allow inbound traffic from 0.0.0.0/0 on the port "
                "used by the affected service?",
                "Show all network flow log entries in the last 24 hours where the destination "
                "is the affected host and the source IP is outside the corporate CIDR range.",
            ]
        ),
        "patch": (
            [
                f"Which nodes in the cluster are running a kernel version affected by "
                f"{_cve}, and when did each node last restart?",
                "Show me all nodes that have been cordoned in the last 6 hours along with "
                "their current kernel version and scheduled drain status.",
                f"How many pods are currently scheduled on nodes that have not yet been "
                f"patched for {_cve}?",
            ] if is_k8s else [
                f"Which hosts in the asset inventory are running a version of the affected "
                f"package that is still vulnerable to {_cve}?",
                f"Show open vulnerability findings for {_cve} across all assets, grouped "
                f"by host and showing the installed versus fixed package version.",
            ]
        ),
        "surface_reduction": (
            [
                "List all container ports exposed across non-system namespaces, grouped by "
                "namespace, and flag any that are not referenced by a Service object.",
                "Which pods expose ports above 1024 that have no corresponding NetworkPolicy "
                "ingress rule restricting who can reach them?",
                "Show RBAC roles that grant verbs beyond get, list, and watch to any "
                "service account in the affected namespace.",
            ] if is_k8s else [
                "What ports are open on the affected host that are not in the approved "
                "service inventory, based on the most recent port scan?",
                "Show all services running on the affected host that have been active for "
                "fewer than 30 days and are listening on non-standard ports.",
            ]
        ),
        "emergency_combined": (
            [
                f"How many nodes are currently unpatched for {_cve} and still schedulable "
                f"(not yet cordoned)?",
                "Show the current patch and cordon status for every node in the cluster, "
                "ordered by kernel version ascending.",
                "Which workloads are running on unpatched nodes and have no NetworkPolicy "
                "restricting their inbound traffic right now?",
            ] if is_k8s else [
                f"Show the patch status and network isolation status for all hosts affected "
                f"by {_cve} from the remediation tracker.",
                f"Which assets flagged for {_cve} have neither been patched nor isolated "
                f"as of the last scan?",
            ]
        ),
    }

    # ── Base control definitions (unchanged metadata) ───────────────────────────
    _CONTROL_MAP = {
        "patch_risk=0": {
            "action": "Apply the vendor patch to all affected nodes/hosts",
            "type":   "patch",
            "sla":    "24h for KEV / crown-jewel; 7d for CVSS≥7; 30d otherwise"
                      if not is_crown else "Immediate (crown-jewel asset)",
        },
        "reachability=cluster_internal": {
            "action": "Isolate affected workload from external / untrusted network segments",
            "type":   "network_isolation",
            "sla":    "Immediate if internet-facing and unpatched",
        },
        "misconfiguration=0": {
            "action": "Remove excess privileges: scope RBAC/IAM to minimum required verbs and resources",
            "type":   "iam_hardening",
            "sla":    "48h" if not is_crown else "24h (crown-jewel asset)",
        },
        "attack_surface=0.1": {
            "action": "Disable unused endpoints, ports, and service bindings on the affected workload",
            "type":   "surface_reduction",
            "sla":    "72h",
        },
        "patch_risk=0, reachability=vpc_internal": {
            "action": "Emergency: isolate workload AND apply patch in the same maintenance window",
            "type":   "emergency_combined",
            "sla":    "Immediate",
        },
    }

    # ── Build controls ───────────────────────────────────────────────────────────
    controls = []
    for label, delta in sorted(counterfactuals.items(), key=lambda x: x[1]):
        risk_reduction = abs(delta)
        if risk_reduction < 0.02:
            continue
        matched_key = next((k for k in _CONTROL_MAP if k in label), None)
        if not matched_key:
            continue

        ctrl = dict(_CONTROL_MAP[matched_key])
        ctrl["risk_reduction_delta"] = round(risk_reduction, 4)
        ctrl["causal_intervention"]  = label

        # Resolve environment-specific steps
        ctrl_type = ctrl["type"]
        step_pool = _STEPS.get(ctrl_type, {})
        if is_k8s and "k8s" in step_pool:
            ctrl["steps"] = step_pool["k8s"]
        elif is_cloud and "cloud" in step_pool:
            ctrl["steps"] = step_pool["cloud"]
        else:
            ctrl["steps"] = step_pool.get("generic", [])

        # Natural-language data platform questions
        ctrl["data_queries"] = _DATA_QUESTIONS.get(ctrl_type, [])

        controls.append(ctrl)

    return sorted(controls, key=lambda x: x["risk_reduction_delta"], reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# Result dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SynthesisedPlaybook:
    """One data source's investigation playbook, causally grounded."""
    source_id: str
    relevance_score: float
    causal_explanation: str           # why this source is relevant
    driving_tactics: List[str]
    playbooks: List[Dict]             # raw playbook cards from KB
    framed_questions: List[Dict]      # NL questions with causal annotations
    primary_tables: List[str] = field(default_factory=list)
    platform_hints: List[str] = field(default_factory=list)


@dataclass
class PlaybookSynthesisResult:
    """Full output of PlaybookSynthesizer.synthesize()."""
    cve_id: str
    cvss_vector: str
    environment_type: str
    asset_criticality: str

    # Causal structural equation outputs
    domain_scores: Dict[str, float]
    p_exploitation: float
    risk_tier: str
    p_access: float
    p_exploit_given_access: float
    p_blocked: float

    # ATT&CK attribution
    enabled_tactics: List[str]
    primary_tactic_id: str
    primary_technique_id: str
    attack_techniques_kb: List[Dict]   # from vector store

    # Counterfactuals (Rung 2 — do-calculus interventions)
    counterfactuals: Dict[str, float]
    compensating_controls: List[Dict]

    # Synthesised playbooks (Rung 1 — observational queries)
    synthesised_playbooks: List[SynthesisedPlaybook]

    # Additional KB context
    cwe_context: Optional[str] = None

    def to_markdown(self) -> str:
        """Format as Markdown for display in the CVE investigation conversation."""
        lines = [
            f"## Causal Investigation Playbook — {self.cve_id}",
            "",
            "### Causal Risk Assessment",
            "",
            f"| Component | Value |",
            f"|---|---|",
            f"| **P(exploitation)** | `{self.p_exploitation:.4f}` — **{self.risk_tier}** |",
            f"| P(access) | `{self.p_access:.4f}` |",
            f"| P(exploit\\|access) | `{self.p_exploit_given_access:.4f}` |",
            f"| P(blocked) | `{self.p_blocked:.4f}` |",
            f"| Environment | `{self.environment_type}` |",
            f"| Asset criticality | `{self.asset_criticality}` |",
            "",
        ]

        # Domain scores
        lines += [
            "### Domain Scores (Ontology → Causal Input)",
            "",
            "| Domain | Score | Interpretation |",
            "|---|---|---|",
        ]
        _domain_labels = {
            "p_asset_exposure":   ("Asset Exposure",    "How exposed is the asset to attack"),
            "p_vuln_exposure":    ("Vuln Exploitability","Probability attacker can exploit the CVE"),
            "p_patch_risk":       ("Patch Gap Risk",     "Probability the patch is NOT in place"),
            "p_attack_surface":   ("Attack Surface",     "Breadth of the exploitable surface"),
            "p_misconfiguration": ("Misconfiguration",   "IAM/config weaknesses enabling the attack"),
        }
        for key, (label, interp) in _domain_labels.items():
            score = self.domain_scores.get(key, 0)
            bar = "█" * int(score * 10) + "░" * (10 - int(score * 10))
            lines.append(f"| {label} | `{score:.3f}` {bar} | {interp} |")
        lines.append("")

        # ATT&CK
        tactics_str = ", ".join(
            f"`{t}`" for t in self.enabled_tactics
        )
        lines += [
            "### Enabled ATT&CK Tactics",
            "",
            f"Enabled by domain scores: {tactics_str}  ",
            f"Primary: `{self.primary_tactic_id}` → technique `{self.primary_technique_id}`",
            "",
        ]

        # Counterfactuals
        if self.counterfactuals:
            lines += [
                "### Counterfactual Analysis (do-calculus — Rung 2)",
                "",
                "What reduces exploitation probability most:",
                "",
                "| Intervention | Δ P(exploitation) |",
                "|---|---|",
            ]
            for label, delta in sorted(self.counterfactuals.items(), key=lambda x: x[1]):
                direction = "↓" if delta < 0 else "↑"
                lines.append(f"| {label} | `{delta:+.4f}` {direction} |")
            lines.append("")

        # Compensating controls
        if self.compensating_controls:
            lines += ["### Compensating Controls (ranked by risk reduction)", ""]
            for i, ctrl in enumerate(self.compensating_controls[:3], 1):
                lines += [
                    f"{i}. **{ctrl['action']}**  ",
                    f"   *Type:* `{ctrl['type']}` · *SLA:* {ctrl['sla']} · "
                    f"*Risk reduction:* `{ctrl['risk_reduction_delta']:.3f}`",
                    "",
                ]
                steps = ctrl.get("steps") or []
                if steps:
                    lines.append("   **Steps:**")
                    for step in steps:
                        # indent multi-line steps
                        indented = step.replace("\n", "\n   ")
                        lines.append(f"   - {indented}")
                    lines.append("")
                data_queries = ctrl.get("data_queries") or []
                if data_queries:
                    lines.append(
                        "   **Ask your data platform** *(paste any of these as natural language)*:"
                    )
                    for j, q in enumerate(data_queries, 1):
                        lines.append(f"   {j}. _{q}_")
                    lines.append("")
            lines.append("")

        # Synthesised playbooks
        lines += ["### Investigation Playbooks by Data Source", ""]
        for pb in self.synthesised_playbooks:
            lines += [
                f"#### Source: `{pb.source_id}`",
                f"*{pb.causal_explanation}*  ",
                f"Driving tactics: {', '.join(f'`{t}`' for t in pb.driving_tactics)}",
                "",
            ]
            for playbook in pb.playbooks[:2]:
                lines += [
                    f"**{playbook.get('title', 'Playbook')}**  ",
                    f"Trigger: {playbook.get('trigger', '')}",
                    "",
                    "Investigation Questions *(with causal framing)*:",
                ]
            for fq in pb.framed_questions:
                lines += [
                    f"{fq['priority']}. {fq['question']}",
                    f"   > *{fq['causal_note']}*",
                ]
            lines.append("")

        if self.cwe_context:
            lines += [f"**Additional context:** {self.cwe_context}", ""]

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "cve_id":              self.cve_id,
            "p_exploitation":      self.p_exploitation,
            "risk_tier":           self.risk_tier,
            "domain_scores":       self.domain_scores,
            "enabled_tactics":     self.enabled_tactics,
            "counterfactuals":     self.counterfactuals,
            "compensating_controls": self.compensating_controls,
            "synthesised_playbooks": [
                {
                    "source_id":           pb.source_id,
                    "relevance_score":     pb.relevance_score,
                    "causal_explanation":  pb.causal_explanation,
                    "framed_questions":    pb.framed_questions,
                }
                for pb in self.synthesised_playbooks
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# PlaybookSynthesizer
# ══════════════════════════════════════════════════════════════════════════════

class PlaybookSynthesizer:
    """
    Synthesises causally-grounded investigation playbooks from CVE enrichment
    data, environment context, and the knowledge base vector store.

    Does NOT require a full security graph — synthesises domain scores from
    CVSS vector fields using the Pearl Rung 1 (observational) approach, then
    applies the causal structural equation to derive:
      - P(exploitation) and risk tier
      - Enabled ATT&CK tactics (which domains are elevated)
      - Counterfactual interventions (do-calculus)
      - Ranked data sources
      - KB-retrieved investigation questions, causally annotated

    With a full security graph (bundle parameter), the model switches to
    Rung 2 (interventional) using the actual graph node properties.
    """

    def synthesize(
        self,
        cve_id: str,
        cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_base: float = 9.8,
        epss_score: float = 0.0,
        in_kev: bool = False,
        kev_ransomware: bool = False,
        environment_type: str = "bare_metal",
        asset_criticality: str = "medium",
        internet_facing: bool = False,
        has_controls: bool = False,
        source_id: Optional[str] = None,     # user-selected source; None = auto-rank
        top_sources: int = 3,
    ) -> PlaybookSynthesisResult:
        """
        Full synthesis pipeline.

        1. Synthesise domain scores from CVSS + context (Rung 1)
        2. Run causal structural equation → P(exploitation), tactics, counterfactuals
        3. Rank data sources by causal relevance to enabled tactics
        4. Retrieve matching playbooks + NL questions from knowledge base
        5. Annotate questions with causal framing
        6. Map counterfactuals to compensating controls
        """
        # ── Step 1: Domain scores from CVSS + context ──────────────────────────
        domain_scores = cvss_to_domain_scores(
            cvss_vector=cvss_vector,
            cvss_base=cvss_base,
            epss_score=epss_score,
            in_kev=in_kev,
            kev_ransomware=kev_ransomware,
            environment_type=environment_type,
            asset_criticality=asset_criticality,
            internet_facing=internet_facing,
            has_controls=has_controls,
        )

        # ── Step 2: Causal structural equation ────────────────────────────────
        result = self._run_causal_model(domain_scores, entity_id=cve_id)

        # ── Step 3: Rank data sources ──────────────────────────────────────────
        ranked_sources = rank_sources_by_causal_relevance(
            enabled_tactics=result["enabled_tactics"],
            domain_scores=domain_scores,
            preferred_source=source_id,
        )

        # ── Step 4 & 5: Retrieve KB playbooks + causally frame questions ───────
        kb_query = (
            f"{cve_id} {environment_type} "
            + " ".join(result["enabled_tactics"])
        )

        synthesised_playbooks: List[SynthesisedPlaybook] = []
        for src in ranked_sources[:top_sources]:
            sid = src["source_id"]
            # Primary investigation type = first enabled tactic mapped to investigation type
            inv_type = next(
                (_TACTIC_INVESTIGATION_TYPE.get(t)
                 for t in src["driving_tactics"]
                 if t in _TACTIC_INVESTIGATION_TYPE),
                None,
            )

            pb_cards = _kb_fetch_playbook_questions(kb_query, sid, inv_type, top_k=2)

            # Determine dominant domain for this source's tactic cluster
            dominant_domain, dominant_score = self._dominant_domain_for_tactics(
                src["driving_tactics"], domain_scores
            )

            # Collect all questions, flatten from all cards
            all_questions: List[str] = []
            for card in pb_cards:
                all_questions.extend(card.get("investigation_questions", []))

            # Frame causally
            primary_tactic = src["driving_tactics"][0] if src["driving_tactics"] else "TA0001"
            framed = _frame_questions_causally(
                questions=all_questions[:8],   # max 8 questions per source
                dominant_domain=dominant_domain,
                domain_score=dominant_score,
                tactic_id=primary_tactic,
                exploitation_probability=result["p_exploitation"],
            )

            synthesised_playbooks.append(SynthesisedPlaybook(
                source_id=sid,
                relevance_score=src["relevance_score"],
                causal_explanation=src["causal_explanation"],
                driving_tactics=src["driving_tactics"],
                playbooks=pb_cards,
                framed_questions=framed,
            ))

        # ── KB: ATT&CK technique details ──────────────────────────────────────
        attack_techniques_kb = _kb_fetch_attack_techniques(
            result["enabled_tactics"], cve_id
        )

        # ── KB: CWE context ───────────────────────────────────────────────────
        cwe_context = _kb_fetch_cwe_context(cve_id)

        # ── Counterfactuals → controls ─────────────────────────────────────────
        compensating_controls = _counterfactuals_to_controls(
            result["counterfactuals"],
            environment_type=environment_type,
            asset_criticality=asset_criticality,
            cve_id=cve_id,
            cvss_vector=cvss_vector,
        )

        return PlaybookSynthesisResult(
            cve_id=cve_id,
            cvss_vector=cvss_vector,
            environment_type=environment_type,
            asset_criticality=asset_criticality,
            domain_scores={k: v for k, v in domain_scores.items()
                           if not isinstance(v, bool) and isinstance(v, float)},
            p_exploitation=result["p_exploitation"],
            risk_tier=result["risk_tier"],
            p_access=result["p_access"],
            p_exploit_given_access=result["p_exploit_given_access"],
            p_blocked=result["p_blocked"],
            enabled_tactics=result["enabled_tactics"],
            primary_tactic_id=result["primary_tactic_id"],
            primary_technique_id=result["primary_technique_id"],
            counterfactuals=result["counterfactuals"],
            compensating_controls=compensating_controls,
            attack_techniques_kb=attack_techniques_kb,
            synthesised_playbooks=synthesised_playbooks,
            cwe_context=cwe_context,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run_causal_model(self, domain_scores: Dict, entity_id: str) -> Dict:
        """
        Run the causal structural equation. Imports from causalgraphs app_f
        if available, otherwise falls back to the inline implementation.
        """
        try:
            from exploitation_risk_model import (
                ExploitationRiskModel,
                _enabled_tactics,
                _select_primary_tactic,
                _compute_counterfactuals,
                exploitation_structural_equation,
                ATTACK_TACTIC_MAP,
            )
            model = ExploitationRiskModel()
            result_obj = model.score(
                entity_id=entity_id,
                p_asset_exposure=domain_scores["p_asset_exposure"],
                p_vuln_exposure=domain_scores["p_vuln_exposure"],
                p_patch_risk=domain_scores["p_patch_risk"],
                p_attack_surface=domain_scores["p_attack_surface"],
                p_misconfiguration=domain_scores["p_misconfiguration"],
                reachability_value=domain_scores["reachability_value"],
                is_crown_jewel=domain_scores["is_crown_jewel"],
                include_counterfactuals=True,
                include_blast_radius=False,
            )
            return {
                "p_exploitation":      result_obj.exploitation_probability,
                "risk_tier":           result_obj.risk_tier,
                "p_access":            result_obj.p_access,
                "p_exploit_given_access": result_obj.p_exploit_given_access,
                "p_blocked":           result_obj.p_blocked,
                "enabled_tactics":     result_obj.enabled_tactics,
                "primary_tactic_id":   result_obj.primary_tactic_id,
                "primary_technique_id":result_obj.primary_technique_id,
                "counterfactuals":     result_obj.counterfactuals,
            }
        except ImportError:
            log.debug("causalgraphs not on path — using inline causal equation")
            return self._run_inline_causal_equation(domain_scores, entity_id)

    def _run_inline_causal_equation(self, domain_scores: Dict, entity_id: str) -> Dict:
        """Inline fallback: the same structural equation without the causalgraphs import."""
        ae  = domain_scores["p_asset_exposure"]
        ve  = domain_scores["p_vuln_exposure"]
        pr  = domain_scores["p_patch_risk"]
        asurf = domain_scores["p_attack_surface"]
        mc  = domain_scores["p_misconfiguration"]
        r   = domain_scores["reachability_value"]
        cj  = domain_scores["is_crown_jewel"]

        def c(x: float) -> float:
            return max(0.0, min(1.0, float(x)))

        p_access  = c(ae * r + 0.2 * asurf * r)
        p_exploit = c(ve + 0.15 * mc * ve)
        p_blocked = c((1.0 - pr) * (1.0 - 0.3 * mc))
        p_final   = p_access * p_exploit * (1.0 - p_blocked)
        if cj:
            p_final = min(1.0, p_final * 1.25)

        def tier(p: float) -> str:
            if p >= 0.70: return "CRITICAL"
            if p >= 0.45: return "HIGH"
            if p >= 0.25: return "MEDIUM"
            if p >= 0.10: return "LOW"
            return "MINIMAL"

        def run(**kw) -> float:
            _ae = kw.get("ae", ae); _ve = kw.get("ve", ve); _pr = kw.get("pr", pr)
            _as = kw.get("asurf", asurf); _mc = kw.get("mc", mc)
            _r  = kw.get("r", r); _cj = kw.get("cj", cj)
            _pa = c(_ae * _r + 0.2 * _as * _r)
            _pe = c(_ve + 0.15 * _mc * _ve)
            _pb = c((1.0 - _pr) * (1.0 - 0.3 * _mc))
            p = _pa * _pe * (1.0 - _pb)
            return min(1.0, p * 1.25) if _cj else p

        counterfactuals = {
            "do(patch_risk=0): fully patched":                   run(pr=0.0) - p_final,
            "do(reachability=cluster_internal): isolate":        run(r=0.15) - p_final,
            "do(misconfiguration=0): fix all IAM misconfigs":    run(mc=0.0) - p_final,
            "do(attack_surface=0.1): harden service exposure":   run(asurf=0.1) - p_final,
            "do(patch_risk=0, reachability=vpc_internal): patch+isolate": run(pr=0.0, r=0.30) - p_final,
        }

        enabled: List[str] = []
        if max(ae, asurf) >= 0.35: enabled.append("TA0001")
        if ve >= 0.35:             enabled.append("TA0002")
        if mc >= 0.35:             enabled.extend(["TA0004", "TA0003"])
        if asurf >= 0.35:          enabled.append("TA0008")
        enabled = list(dict.fromkeys(enabled))

        domain_tactic = {"TA0001": max(ae, asurf), "TA0002": ve, "TA0004": mc, "TA0008": asurf}
        primary = max(domain_tactic, key=domain_tactic.get)
        technique_map = {
            "TA0001": "T1190", "TA0002": "T1203",
            "TA0004": "T1068", "TA0008": "T1021",
        }

        return {
            "p_exploitation":         round(p_final, 4),
            "risk_tier":              tier(p_final),
            "p_access":               round(p_access, 4),
            "p_exploit_given_access": round(p_exploit, 4),
            "p_blocked":              round(p_blocked, 4),
            "enabled_tactics":        enabled,
            "primary_tactic_id":      primary,
            "primary_technique_id":   technique_map.get(primary, "T1190"),
            "counterfactuals":        {k: round(v, 4) for k, v in counterfactuals.items()},
        }

    def _dominant_domain_for_tactics(
        self, tactics: List[str], domain_scores: Dict
    ) -> Tuple[str, float]:
        """Return (domain_key, score) for the highest-scoring domain driving these tactics."""
        tactic_domain = {
            "TA0001": "p_asset_exposure",
            "TA0002": "p_vuln_exposure",
            "TA0003": "p_misconfiguration",
            "TA0004": "p_misconfiguration",
            "TA0008": "p_attack_surface",
        }
        best_domain = "p_asset_exposure"
        best_score  = 0.0
        for t in tactics:
            d = tactic_domain.get(t, "p_asset_exposure")
            s = domain_scores.get(d, 0.0)
            if s > best_score:
                best_domain = d
                best_score  = s
        return best_domain, best_score
