"""
detection_tools.py — CVE Detection & Investigation Tools
=========================================================
Six LangChain StructuredTools for conversational CVE alert investigation.

Registered in TOOL_REGISTRY as:
  detection_scenario_search    — semantic Q&A lookup from scenario knowledge base
  kill_chain_builder           — CVE → full ATT&CK kill chain with pre/post conditions
  priority_score_calculator    — multi-factor risk priority (CVSS + EPSS + KEV + exposure)
  cpe_investigation_guide      — how to find affected products and run verification commands
  detection_query_builder      — generate KQL / Splunk / Elastic detection queries
  cvss_vector_explainer        — field-by-field CVSS vector explanation with risk implication

All tools reuse existing asteraskills infrastructure (NVD, EPSS, CISA KEV, Qdrant)
and add the detection scenario knowledge layer on top.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Tool 1 — Detection Scenario Search
# ══════════════════════════════════════════════════════════════════════════════

class DetectionScenarioSearchInput(BaseModel):
    query: str = Field(
        description=(
            "Natural language question about CVE investigation, triage, detection, "
            "or remediation. Examples: 'should I page on-call for a local CVE?', "
            "'how do I find affected CPEs?', 'write a KQL query for exploitation detection'"
        )
    )
    domain: Optional[str] = Field(
        default=None,
        description="Filter by domain: secops | appsec | vm | detection_eng. Leave empty for all.",
    )
    role_level: Optional[str] = Field(
        default=None,
        description="Filter by role: junior | mid | senior. Leave empty for all.",
    )
    top_k: int = Field(default=3, description="Number of results to return (1–10).")


def _detection_scenario_search(
    query: str,
    domain: Optional[str] = None,
    role_level: Optional[str] = None,
    top_k: int = 3,
) -> str:
    """Search the detection scenario knowledge base for relevant Q&A pairs."""
    from asteraskills.storage.vector_store import VectorStoreClient
    from asteraskills.storage.collections import DetectionCollections
    import asyncio

    try:
        client = VectorStoreClient()
        filters: Dict[str, Any] = {}
        if domain:
            filters["domain"] = domain
        if role_level:
            filters["role_level"] = role_level

        results = asyncio.run(client.query(
            collection_name=DetectionCollections.SCENARIOS,
            query_text=query,
            top_k=min(top_k, 10),
            filter_params=filters if filters else None,
        ))

        if not results:
            return json.dumps({
                "success": False,
                "message": f"No scenarios found for query: '{query}'",
                "results": [],
            })

        formatted = []
        for r in results:
            meta = r.get("metadata", {})
            formatted.append({
                "scenario": meta.get("scenario_title", ""),
                "question": meta.get("question", ""),
                "answer_preview": meta.get("answer_summary", "")[:400],
                "domain": meta.get("domain", ""),
                "role_level": meta.get("role_level", ""),
                "attack_techniques": meta.get("attack_techniques", []),
                "has_queries": meta.get("has_queries", False),
                "similarity": round(r.get("score", 0), 3),
                "full_text": r.get("text", "")[:2000],
            })

        return json.dumps({
            "success": True,
            "query": query,
            "total_results": len(formatted),
            "results": formatted,
        })

    except Exception as exc:
        log.exception("detection_scenario_search failed")
        return json.dumps({"success": False, "error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# Tool 2 — Kill Chain Builder
# ══════════════════════════════════════════════════════════════════════════════

class KillChainBuilderInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-26855")
    attack_vector: Optional[str] = Field(
        default=None,
        description=(
            "Attack vector if already known: 'network' | 'adjacent' | 'local' | 'physical'. "
            "Extracted from CVSS vector if not provided."
        ),
    )
    target_context: Optional[str] = Field(
        default=None,
        description=(
            "Optional context about the target environment (e.g. 'kubernetes node', "
            "'shared hosting', 'cloud VM') to refine kill chain stages."
        ),
    )


# Kill chain stage templates keyed by attack vector
_KILL_CHAIN_TEMPLATES: Dict[str, List[Dict]] = {
    "network": [
        {"phase": "Reconnaissance", "tactic": "TA0043", "description": "Attacker scans for vulnerable service from internet", "pre_condition": "Service reachable from internet", "att&ck": ["T1595", "T1592"]},
        {"phase": "Initial Access", "tactic": "TA0001", "description": "Exploit public-facing service — no authentication required", "pre_condition": "Target running vulnerable version", "att&ck": ["T1190"]},
        {"phase": "Execution", "tactic": "TA0002", "description": "Exploit triggers code execution in process context", "pre_condition": "Exploit payload delivered", "att&ck": ["T1203"]},
        {"phase": "Impact / Post-Exploitation", "tactic": "TA0040", "description": "Attacker achieves objective: RCE, data access, DoS, or lateral movement", "pre_condition": "Execution successful", "att&ck": ["T1499", "T1078"]},
    ],
    "local": [
        {"phase": "Initial Access (other vector)", "tactic": "TA0001", "description": "Attacker must first obtain local shell via other means (phishing, credential theft, prior RCE)", "pre_condition": "Requires prior foothold — this CVE cannot provide initial access", "att&ck": ["T1078", "T1059", "T1566"]},
        {"phase": "Execution / Privilege Escalation", "tactic": "TA0004", "description": "Low-priv local user exploits CVE — may escalate or cause DoS", "pre_condition": "Attacker has local shell (any privilege level)", "att&ck": ["T1068"]},
        {"phase": "Impact", "tactic": "TA0040", "description": "Achieves DoS, privilege escalation, or data access depending on CVE impact", "pre_condition": "CVE successfully triggered", "att&ck": ["T1499"]},
    ],
    "adjacent": [
        {"phase": "Network Position", "tactic": "TA0043", "description": "Attacker must be on the same local network (LAN, VPN, or adjacent segment)", "pre_condition": "Attacker has network adjacency (e.g. compromised network device, insider)", "att&ck": ["T1557"]},
        {"phase": "Initial Access", "tactic": "TA0001", "description": "Exploit service reachable from adjacent network", "pre_condition": "Target reachable from attacker's segment", "att&ck": ["T1190"]},
        {"phase": "Execution / Impact", "tactic": "TA0002", "description": "Exploit triggers code execution or DoS", "pre_condition": "Service responding to attacker", "att&ck": ["T1203", "T1499"]},
    ],
    "physical": [
        {"phase": "Physical Access", "tactic": "TA0001", "description": "Attacker requires physical presence at the device", "pre_condition": "Physical access to the target device", "att&ck": ["T1200"]},
        {"phase": "Impact", "tactic": "TA0040", "description": "Exploit requires physical interaction to trigger", "pre_condition": "Device in attacker's physical reach", "att&ck": ["T1499"]},
    ],
}

_CVSS_AV_MAP = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}


def _parse_attack_vector_from_cvss(cvss_string: str) -> Optional[str]:
    m = re.search(r"AV:([NALP])", cvss_string, re.IGNORECASE)
    if m:
        return _CVSS_AV_MAP.get(m.group(1).upper())
    return None


def _build_kill_chain(
    cve_id: str,
    attack_vector: Optional[str] = None,
    target_context: Optional[str] = None,
) -> str:
    # Step 1: Enrich the CVE to get CVSS
    cve_data: Dict = {}
    cvss_string = ""
    try:
        from asteraskills.tools.cve_enrichment import _enrich_cve
        raw = _enrich_cve(cve_id)
        if isinstance(raw, str):
            cve_data = json.loads(raw)
        else:
            cve_data = raw
        cvss_string = cve_data.get("cvss_vector_string", "") or cve_data.get("cvss_v3_vector", "")
    except Exception as exc:
        log.debug("CVE enrichment for kill chain failed: %s", exc)

    # Step 2: Resolve attack vector
    av = attack_vector
    if not av and cvss_string:
        av = _parse_attack_vector_from_cvss(cvss_string)
    if not av:
        av = cve_data.get("attack_vector", "local").lower()
    av = av.lower()

    # Step 3: Get ATT&CK technique mappings
    technique_ids: List[str] = []
    try:
        from asteraskills.tools.cve_attack_mapper import _map_cve_to_attack
        mapping_raw = _map_cve_to_attack(cve_id)
        mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
        technique_ids = [t.get("technique_id", "") for t in mapping.get("techniques", [])
                        if t.get("technique_id")]
    except Exception as exc:
        log.debug("ATT&CK mapping for kill chain failed: %s", exc)

    # Step 4: Build kill chain
    stages = _KILL_CHAIN_TEMPLATES.get(av, _KILL_CHAIN_TEMPLATES["local"])

    # Inject specific technique IDs from the CVE mapping into the stages
    if technique_ids:
        # Add CVE-specific techniques to the Execution/Impact stage
        for stage in stages:
            if stage["tactic"] in ("TA0002", "TA0040", "TA0004"):
                stage["att&ck"] = list(set(stage["att&ck"] + technique_ids[:3]))

    # Step 5: Add container/K8s context if relevant
    context_notes = []
    if target_context:
        ctx = target_context.lower()
        if "kubernetes" in ctx or "k8s" in ctx or "container" in ctx:
            if av == "local":
                context_notes.append(
                    "⚠️  Kubernetes context: 'local' means within the node's kernel. "
                    "A compromised pod with hostPID/hostNetwork or a container escape "
                    "can bridge remote access → local kernel exploitation."
                )
        if "shared" in ctx:
            context_notes.append(
                "⚠️  Shared hosting: local DoS affects all tenants on the host."
            )

    result = {
        "cve_id": cve_id,
        "attack_vector": av,
        "cvss_vector": cvss_string,
        "kill_chain_stages": stages,
        "att&ck_techniques_mapped": technique_ids,
        "context_notes": context_notes,
        "pre_access_required": av in ("local", "physical"),
        "summary": (
            f"CVE {cve_id} requires {av} access. "
            + ("An attacker MUST have an existing foothold before using this CVE. "
               if av in ("local", "physical") else
               "This CVE can be exploited directly from the network. ")
            + f"Mapped to {len(technique_ids)} ATT&CK technique(s)."
        ),
    }

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Tool 3 — Priority Score Calculator
# ══════════════════════════════════════════════════════════════════════════════

class PriorityScoreInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-26855")
    asset_criticality: str = Field(
        default="medium",
        description="Business criticality of affected asset: crown_jewel | high | medium | low",
    )
    internet_facing: bool = Field(
        default=False,
        description="Is the affected asset directly reachable from the internet?",
    )
    in_container: bool = Field(
        default=False,
        description="Is the workload running in containers or Kubernetes?",
    )
    has_compensating_controls: bool = Field(
        default=False,
        description=(
            "Are compensating controls in place? "
            "(e.g. SELinux enforcing, network isolation, restricted shell access)"
        ),
    )


_CRITICALITY_MULTIPLIER = {
    "crown_jewel": 1.5, "high": 1.2, "medium": 1.0, "low": 0.6,
}
_AV_WEIGHT = {"network": 1.0, "adjacent": 0.7, "local": 0.3, "physical": 0.1}


def _calculate_priority(
    cve_id: str,
    asset_criticality: str = "medium",
    internet_facing: bool = False,
    in_container: bool = False,
    has_compensating_controls: bool = False,
) -> str:
    # Gather data
    cvss_base = 0.0
    epss_score = 0.0
    in_kev = False
    kev_ransomware = False
    av = "local"
    cvss_vector = ""

    try:
        from asteraskills.tools.cve_enrichment import _enrich_cve
        raw = _enrich_cve(cve_id)
        data = json.loads(raw) if isinstance(raw, str) else raw
        cvss_base = float(data.get("cvss_score", 0) or 0)
        epss_score = float(data.get("epss_score", 0) or 0)
        in_kev = bool(data.get("in_kev", False))
        kev_ransomware = bool(data.get("kev_ransomware_campaign", False))
        cvss_vector = data.get("cvss_vector_string", "") or ""
        if cvss_vector:
            parsed_av = _parse_attack_vector_from_cvss(cvss_vector)
            if parsed_av:
                av = parsed_av
        else:
            av = (data.get("attack_vector") or "local").lower()
    except Exception as exc:
        log.debug("CVE enrichment for priority failed: %s", exc)

    # Multi-factor risk score
    av_weight = _AV_WEIGHT.get(av, 0.3)
    crit_mult = _CRITICALITY_MULTIPLIER.get(asset_criticality.lower(), 1.0)
    epss_factor = 1.0 + (epss_score * 9.0)   # EPSS 0→1 maps to 1.0x → 10.0x multiplier
    exploit_factor = 1.5 if in_kev else 1.0
    container_factor = 1.3 if in_container and av == "local" else 1.0
    internet_factor = 1.2 if internet_facing else 1.0
    control_factor = 0.6 if has_compensating_controls else 1.0

    raw_score = (
        (cvss_base / 10.0)
        * av_weight
        * epss_factor
        * exploit_factor
        * crit_mult
        * container_factor
        * internet_factor
        * control_factor
    )
    normalized_score = min(1.0, raw_score)

    # Priority tier
    if in_kev and kev_ransomware:
        tier = "P0"
        sla = "48 hours (ransomware-linked KEV)"
        action = "Emergency patch window. Page on-call now."
    elif in_kev:
        tier = "P1"
        sla = "7 days (CISA KEV)"
        action = "Escalate to patch team immediately. No standard cycle."
    elif normalized_score >= 0.5:
        tier = "P2"
        sla = "14 days"
        action = "Prioritize in current sprint."
    elif normalized_score >= 0.25:
        tier = "P3"
        sla = "30 days"
        action = "Standard HIGH patch cycle."
    elif normalized_score >= 0.10:
        tier = "P4"
        sla = "90 days"
        action = "Standard patch cycle."
    else:
        tier = "P5"
        sla = "Next scheduled maintenance"
        action = "Informational. Track but no urgency."

    # Page on-call decision
    page_oncall = tier in ("P0", "P1") or (tier == "P2" and internet_facing)

    result = {
        "cve_id": cve_id,
        "priority_tier": tier,
        "sla": sla,
        "recommended_action": action,
        "page_on_call": page_oncall,
        "risk_score": round(normalized_score, 4),
        "factors": {
            "cvss_base": cvss_base,
            "epss_score": epss_score,
            "attack_vector": av,
            "av_weight": av_weight,
            "in_kev": in_kev,
            "kev_ransomware": kev_ransomware,
            "asset_criticality": asset_criticality,
            "internet_facing": internet_facing,
            "in_container": in_container,
            "has_compensating_controls": has_compensating_controls,
        },
        "rationale": (
            f"CVSS {cvss_base} ({av}) × EPSS {epss_score:.4f} × "
            f"{'KEV ' if in_kev else ''}"
            f"{'RANSOMWARE ' if kev_ransomware else ''}"
            f"asset={asset_criticality} "
            f"{'internet ' if internet_facing else ''}"
            f"{'containers ' if in_container else ''}"
            f"{'controls-applied' if has_compensating_controls else 'no-controls'} "
            f"→ score={normalized_score:.4f} [{tier}]"
        ),
    }

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Tool 4 — CPE Investigation Guide
# ══════════════════════════════════════════════════════════════════════════════

class CpeInvestigationInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-26855")
    environment: Optional[str] = Field(
        default=None,
        description=(
            "Target environment context: 'linux' | 'windows' | 'container' | "
            "'k8s' | 'debian' | 'ubuntu' | 'rhel' | 'alpine'"
        ),
    )


def _cpe_investigation_guide(
    cve_id: str,
    environment: Optional[str] = None,
) -> str:
    """Generate step-by-step instructions for identifying affected products and checking exposure."""
    cve_data: Dict = {}
    affected_products: List[str] = []

    try:
        from asteraskills.tools.cve_enrichment import _enrich_cve
        raw = _enrich_cve(cve_id)
        cve_data = json.loads(raw) if isinstance(raw, str) else raw
        affected_products = cve_data.get("affected_products", []) or []
    except Exception as exc:
        log.debug("CVE enrichment for CPE guide failed: %s", exc)

    # Parse vendor:product pairs
    cpe_pairs = []
    for p in affected_products:
        if ":" in str(p):
            parts = str(p).split(":")
            cpe_pairs.append({"vendor": parts[0], "product": parts[1] if len(parts) > 1 else parts[0]})
        else:
            cpe_pairs.append({"vendor": "", "product": str(p)})

    # Build environment-specific verification commands
    env = (environment or "").lower()
    commands = []

    # Linux kernel
    if any("linux_kernel" in p.get("product", "") for p in cpe_pairs) or "linux" in env:
        commands.extend([
            {
                "purpose": "Check current kernel version",
                "command": "uname -r",
                "expected_output": "Kernel version string, e.g. 6.5.0-35-generic",
            },
            {
                "purpose": "Check if ice (Intel E800) NIC driver is loaded",
                "command": "lsmod | grep ice",
                "expected_output": "Empty = not loaded (not exploitable). 'ice' row = driver active.",
            },
            {
                "purpose": "Check for Intel E800 NIC hardware presence",
                "command": "lspci | grep -i ethernet",
                "expected_output": "Look for 'Intel Ethernet' E800/E810/E823 series.",
            },
            {
                "purpose": "Check if distro has backported the fix (Ubuntu)",
                "command": f"apt changelog linux-image-$(uname -r) 2>/dev/null | grep {cve_id} | head -5",
                "expected_output": f"If '{cve_id}' appears, fix is already backported.",
            },
            {
                "purpose": "Check if distro has backported the fix (RHEL/CentOS)",
                "command": f"rpm -q --changelog kernel | grep {cve_id} | head -5",
                "expected_output": f"If '{cve_id}' appears, fix is backported.",
            },
        ])

    # Container/K8s context
    if "container" in env or "k8s" in env or "kubernetes" in env:
        commands.extend([
            {
                "purpose": "Check all Kubernetes node kernel versions",
                "command": "kubectl get nodes -o custom-columns='NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion'",
                "expected_output": "Table of nodes with their kernel versions.",
            },
            {
                "purpose": "Check for pods with hostNetwork (can reach ice driver directly)",
                "command": "kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata.name'",
                "expected_output": "List of pods with hostNetwork. Should be empty or only infra pods.",
            },
            {
                "purpose": "Check for privileged containers (can access kernel resources)",
                "command": "kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[].securityContext.privileged // false'",
                "expected_output": "All 'false' is ideal. Any 'true' = potential exploit surface.",
            },
        ])

    # Ansible bulk check
    commands.append({
        "purpose": "Check kernel version on all hosts via Ansible",
        "command": "ansible all -m command -a 'uname -r' -i inventory.ini",
        "expected_output": "Kernel version per host. Cross-check against NVD affected range.",
    })

    # NVD version range lookup
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    distro_advisories = {
        "ubuntu": f"https://ubuntu.com/security/{cve_id}",
        "debian": f"https://security-tracker.debian.org/tracker/{cve_id}",
        "rhel": f"https://access.redhat.com/security/cve/{cve_id}",
        "alpine": f"https://security.alpinelinux.org/vuln/{cve_id}",
    }

    result = {
        "cve_id": cve_id,
        "affected_products_from_nvd": affected_products,
        "cpe_pairs": cpe_pairs,
        "important_note": (
            "Containers do NOT have their own kernel — they share the host kernel. "
            "Check the container HOST kernel version, not the container image OS."
            if any("linux_kernel" in p.get("product", "") for p in cpe_pairs)
            else "Check the NVD Configurations section for exact affected version ranges."
        ),
        "verification_steps": commands,
        "reference_urls": {
            "nvd_configurations": nvd_url,
            **{k: v for k, v in distro_advisories.items()},
        },
        "decision_logic": [
            f"1. Check kernel/software version → in NVD affected range?",
            f"2. Check specific component (e.g. ice driver) → actually loaded?",
            f"3. Check distro advisory → fix already backported?",
            f"4. If all three confirm: affected. Patch or apply compensating controls.",
        ],
    }

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Tool 5 — Detection Query Builder
# ══════════════════════════════════════════════════════════════════════════════

class DetectionQueryBuilderInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-26855")
    platform: str = Field(
        default="kql",
        description="Target platform: kql | splunk | elastic | sigma",
    )
    detection_phase: str = Field(
        default="both",
        description=(
            "Which phase to generate queries for: "
            "'pre_exploitation' (pre-access detection), "
            "'post_exploitation' (exploitation + impact detection), "
            "'both'"
        ),
    )


def _detection_query_builder(
    cve_id: str,
    platform: str = "kql",
    detection_phase: str = "both",
) -> str:
    """Generate detection queries for a CVE across different SIEM platforms."""
    cve_data: Dict = {}
    cwe_ids: List[str] = []
    techniques: List[str] = []

    try:
        from asteraskills.tools.cve_enrichment import _enrich_cve
        raw = _enrich_cve(cve_id)
        cve_data = json.loads(raw) if isinstance(raw, str) else raw
        cwe_ids = cve_data.get("cwe_ids", []) or []
    except Exception as exc:
        log.debug("CVE enrichment for query builder failed: %s", exc)

    try:
        from asteraskills.tools.cve_attack_mapper import _map_cve_to_attack
        mapping_raw = _map_cve_to_attack(cve_id)
        mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
        techniques = [t.get("technique_id", "") for t in mapping.get("techniques", [])
                     if t.get("technique_id")]
    except Exception as exc:
        log.debug("ATT&CK mapping for query builder failed: %s", exc)

    # Build queries using LLM with context
    try:
        from asteraskills.core.llm import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = get_llm(temperature=0.1)
        context = {
            "cve_id": cve_id,
            "cvss_score": cve_data.get("cvss_score"),
            "attack_vector": cve_data.get("attack_vector"),
            "cvss_vector": cve_data.get("cvss_vector_string"),
            "description": cve_data.get("description", "")[:800],
            "cwe_ids": cwe_ids,
            "att&ck_techniques": techniques[:5],
            "platform": platform,
        }

        system = (
            "You are a detection engineering expert. Generate practical, ready-to-use "
            "detection queries for the given CVE. Focus on behavioral indicators, not just "
            "signature matching. Include both pre-exploitation (attacker gaining access) and "
            "post-exploitation (exploit triggered) phases. Add inline comments explaining "
            "each part of the query."
        )
        prompt = (
            f"Generate {platform.upper()} detection queries for {cve_id}.\n\n"
            f"CVE Context:\n{json.dumps(context, indent=2)}\n\n"
            f"Detection phase: {detection_phase}\n\n"
            f"Return JSON with structure:\n"
            f'{{"pre_exploitation": [{{"title": str, "query": str, "explanation": str, "false_positive_notes": str}}], '
            f'"post_exploitation": [{{"title": str, "query": str, "explanation": str, "false_positive_notes": str}}], '
            f'"platform": str, "cve_id": str}}'
        )

        resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=prompt)])
        content = resp.content if hasattr(resp, "content") else str(resp)

        # Extract JSON from LLM response
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            return json_match.group(0)

    except Exception as exc:
        log.debug("LLM query generation failed: %s — using static templates", exc)

    # Static fallback queries (KQL)
    av = (cve_data.get("attack_vector") or "local").lower()
    static_queries = _build_static_queries(cve_id, av, cwe_ids, platform)
    return json.dumps(static_queries, indent=2)


def _build_static_queries(
    cve_id: str, av: str, cwe_ids: List[str], platform: str
) -> Dict:
    """Static query templates when LLM is unavailable."""
    cve_escaped = cve_id.replace("-", r"\-")

    if platform == "kql":
        pre = [{
            "title": f"Suspicious local shell access — pre-exploitation indicator for {cve_id}",
            "query": (
                f"// Pre-exploitation: detect unexpected low-priv shell activity\n"
                f"DeviceLogonEvents\n"
                f"| where TimeGenerated > ago(24h)\n"
                f"| where ActionType == 'LogonSuccess'\n"
                f"| where AccountName !in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')\n"
                f"| where DeviceName in (/* add affected host names */)\n"
                f"| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP"
            ) if av == "local" else (
                f"// Pre-exploitation: detect external connection attempts\n"
                f"DeviceNetworkEvents\n"
                f"| where TimeGenerated > ago(1h)\n"
                f"| where ActionType == 'InboundConnectionAccepted'\n"
                f"| where RemoteIPType == 'Public'\n"
                f"| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)\n"
                f"| extend country = tostring(parse_json(GeoIPInfo).country)\n"
                f"| project TimeGenerated, DeviceName, RemoteIP, LocalPort, country"
            ),
            "explanation": "Detects the access pattern that must precede exploitation.",
            "false_positive_notes": "Legitimate remote admin sessions. Reduce with IP allowlist.",
        }]
        post = [{
            "title": f"Kernel panic / exploitation signature for {cve_id}",
            "query": (
                f"// Post-exploitation: kernel crash or NULL pointer dereference\n"
                f"Syslog\n"
                f"| where TimeGenerated > ago(6h)\n"
                f"| where SyslogMessage has_any ('Kernel panic', 'NULL pointer dereference', 'ice_bridge_setlink')\n"
                f"| project TimeGenerated, HostName, SyslogMessage\n"
                f"| sort by TimeGenerated desc"
            ) if "CWE-476" in " ".join(cwe_ids) else (
                f"// Post-exploitation: unexpected process spawning after {cve_id}\n"
                f"DeviceProcessEvents\n"
                f"| where TimeGenerated > ago(1h)\n"
                f"| where InitiatingProcessFileName in~ ('java.exe', 'python.exe', 'node.exe')\n"
                f"| where ProcessCommandLine has_any ('cmd.exe', '/bin/sh', '/bin/bash', 'curl', 'wget')\n"
                f"| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName"
            ),
            "explanation": "Detects the exploitation or immediate post-exploitation activity.",
            "false_positive_notes": "Hardware failures also cause kernel panics. Correlate with login activity.",
        }]
    else:
        # Generic placeholder for other platforms
        pre = [{"title": f"Pre-exploitation for {cve_id}", "query": f"/* {platform} query — use LLM mode for full generation */", "explanation": "", "false_positive_notes": ""}]
        post = [{"title": f"Post-exploitation for {cve_id}", "query": f"/* {platform} query — use LLM mode for full generation */", "explanation": "", "false_positive_notes": ""}]

    return {
        "cve_id": cve_id,
        "platform": platform,
        "pre_exploitation": pre,
        "post_exploitation": post,
        "note": "Static template. For richer LLM-generated queries, ensure ANTHROPIC_API_KEY or OPENAI_API_KEY is set.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Tool 6 — CVSS Vector Explainer
# ══════════════════════════════════════════════════════════════════════════════

class CvssVectorExplainerInput(BaseModel):
    cvss_string: str = Field(
        description=(
            "CVSS v3 vector string, e.g. CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H "
            "OR a CVE ID to look up (e.g. CVE-2024-26855)"
        )
    )


_CVSS_FIELD_DEFINITIONS = {
    "AV": {
        "name": "Attack Vector",
        "values": {
            "N": ("Network", "Remotely exploitable from internet. HIGHEST risk. No physical/local access needed.", 1.0),
            "A": ("Adjacent", "Requires same LAN/network segment. Lower risk than Network.", 0.7),
            "L": ("Local",    "Requires local OS shell. Attacker must already have foothold.", 0.3),
            "P": ("Physical", "Requires physical device access. Lowest network-based risk.", 0.1),
        },
    },
    "AC": {
        "name": "Attack Complexity",
        "values": {
            "L": ("Low",  "No special conditions needed. Easy to reliably exploit.", 1.0),
            "H": ("High", "Requires specific conditions or race conditions. Harder to exploit consistently.", 0.5),
        },
    },
    "PR": {
        "name": "Privileges Required",
        "values": {
            "N": ("None",  "No authentication required. Any anonymous attacker qualifies.", 1.0),
            "L": ("Low",   "Requires low-privilege account (any authenticated user).", 0.7),
            "H": ("High",  "Requires high-privilege (admin) account. Harder for attacker.", 0.3),
        },
    },
    "UI": {
        "name": "User Interaction",
        "values": {
            "N": ("None",     "Attacker acts alone. No victim interaction required.", 1.0),
            "R": ("Required", "Victim must take an action (click link, open file). Lowers exploitability.", 0.6),
        },
    },
    "S": {
        "name": "Scope",
        "values": {
            "U": ("Unchanged", "Impact limited to the vulnerable component only.", 1.0),
            "C": ("Changed",   "Attack can affect components beyond the vulnerable one (e.g. hypervisor escape).", 1.5),
        },
    },
    "C": {
        "name": "Confidentiality Impact",
        "values": {
            "N": ("None", "No data disclosure. Attacker cannot read sensitive data."),
            "L": ("Low",  "Some data disclosed, but limited in scope or sensitivity."),
            "H": ("High", "All data accessible, or critical secrets exposed."),
        },
    },
    "I": {
        "name": "Integrity Impact",
        "values": {
            "N": ("None", "No data modification. Attacker cannot alter files or data."),
            "L": ("Low",  "Limited modification possible."),
            "H": ("High", "Complete integrity loss — attacker can modify any data."),
        },
    },
    "A": {
        "name": "Availability Impact",
        "values": {
            "N": ("None", "No availability impact. Service remains operational."),
            "L": ("Low",  "Reduced performance or intermittent availability."),
            "H": ("High", "Complete availability loss — system crash, reboot, or service unavailability."),
        },
    },
}


def _explain_cvss_vector(cvss_string: str) -> str:
    """Parse and explain a CVSS v3 vector string field by field."""
    # If it looks like a CVE ID, look up the CVSS vector first
    if re.match(r"CVE-\d{4}-\d+", cvss_string, re.IGNORECASE):
        try:
            from asteraskills.tools.cve_enrichment import _enrich_cve
            raw = _enrich_cve(cvss_string)
            data = json.loads(raw) if isinstance(raw, str) else raw
            cvss_string = data.get("cvss_vector_string", "") or data.get("cvss_v3_vector", "")
            if not cvss_string:
                return json.dumps({"error": f"No CVSS v3 vector found for {cvss_string}"})
        except Exception as exc:
            return json.dumps({"error": f"CVE lookup failed: {exc}"})

    # Parse the vector
    # e.g. CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
    fields_raw = re.findall(r"([A-Z]+):([A-Z])", cvss_string)
    if not fields_raw:
        return json.dumps({"error": f"Could not parse CVSS vector: '{cvss_string}'"})

    explained_fields = []
    risk_flags = []

    for field_abbr, value_abbr in fields_raw:
        if field_abbr == "CVSS":
            continue
        defn = _CVSS_FIELD_DEFINITIONS.get(field_abbr)
        if not defn:
            continue
        val_defn = defn["values"].get(value_abbr)
        if not val_defn:
            continue

        val_name = val_defn[0]
        val_desc = val_defn[1]

        entry = {
            "field": f"{field_abbr}: {value_abbr}",
            "meaning": f"{defn['name']} = {val_name}",
            "implication": val_desc,
        }
        explained_fields.append(entry)

        # Flag high-risk conditions
        if field_abbr == "AV" and value_abbr == "N":
            risk_flags.append("⚠️  AV:N — remotely exploitable, highest attack surface")
        if field_abbr == "AV" and value_abbr == "L":
            risk_flags.append("ℹ️  AV:L — attacker must have local shell first; cannot be used for initial access")
        if field_abbr == "PR" and value_abbr == "N":
            risk_flags.append("⚠️  PR:N — no authentication required")
        if field_abbr == "C" and value_abbr == "H":
            risk_flags.append("🔴  C:H — complete confidentiality loss (credential/data theft possible)")
        if field_abbr == "I" and value_abbr == "H":
            risk_flags.append("🔴  I:H — complete integrity loss (code injection / data manipulation possible)")
        if field_abbr == "A" and value_abbr == "H":
            risk_flags.append("🟠  A:H — system crash / DoS possible (availability fully lost)")
        if field_abbr == "S" and value_abbr == "C":
            risk_flags.append("⚠️  S:C — scope change: exploit can jump to other components")
        if field_abbr == "C" and value_abbr == "N" and field_abbr == "I":
            pass  # Handled above

    # Determine triage summary
    impact_fields = {f: v for f, v in fields_raw if f in ("C", "I", "A")}
    c = impact_fields.get("C", "N")
    integrity = impact_fields.get("I", "N")
    a = impact_fields.get("A", "N")
    av = dict(fields_raw).get("AV", "L")

    if c == "N" and integrity == "N" and a == "H":
        triage_summary = "DoS only — no data theft, no code injection. Attacker can crash the service."
    elif c == "H" or integrity == "H":
        triage_summary = "Data breach / code execution possible. Treat as high urgency."
    else:
        triage_summary = "Limited impact. Review specific field values for details."

    return json.dumps({
        "cvss_vector": cvss_string,
        "field_explanations": explained_fields,
        "risk_flags": risk_flags,
        "triage_summary": triage_summary,
        "impact_profile": {
            "confidentiality": {"value": c, "label": {"N": "None", "L": "Low", "H": "High"}.get(c, c)},
            "integrity": {"value": integrity, "label": {"N": "None", "L": "Low", "H": "High"}.get(integrity, integrity)},
            "availability": {"value": a, "label": {"N": "None", "L": "Low", "H": "High"}.get(a, a)},
            "attack_vector": {"value": av, "label": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}.get(av, av)},
        },
    }, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Tool registry — factory functions
# ══════════════════════════════════════════════════════════════════════════════

def make_detection_scenario_search() -> StructuredTool:
    return StructuredTool(
        name="detection_scenario_search",
        description=(
            "Search the detection scenario knowledge base for Q&A guidance on CVE triage, "
            "kill chain analysis, CPE lookup, detection queries, and remediation. "
            "Use when an engineer asks a HOW/WHAT/SHOULD question about CVE investigation."
        ),
        args_schema=DetectionScenarioSearchInput,
        func=lambda **kw: _detection_scenario_search(**kw),
    )


def make_kill_chain_builder() -> StructuredTool:
    return StructuredTool(
        name="kill_chain_builder",
        description=(
            "Build a full ATT&CK kill chain for a CVE. Shows all phases from reconnaissance "
            "to impact, pre-conditions at each stage, and which ATT&CK techniques are enabled. "
            "Adjusts for attack vector (network vs local) and target context (K8s, containers)."
        ),
        args_schema=KillChainBuilderInput,
        func=lambda **kw: _build_kill_chain(**kw),
    )


def make_priority_score_calculator() -> StructuredTool:
    return StructuredTool(
        name="priority_score_calculator",
        description=(
            "Calculate multi-factor risk priority for a CVE on specific assets. "
            "Combines CVSS base score, EPSS exploit probability, CISA KEV status, "
            "asset criticality, internet exposure, and compensating controls into a "
            "P0-P5 priority tier with SLA and page-on-call recommendation."
        ),
        args_schema=PriorityScoreInput,
        func=lambda **kw: _calculate_priority(**kw),
    )


def make_cpe_investigation_guide() -> StructuredTool:
    return StructuredTool(
        name="cpe_investigation_guide",
        description=(
            "Generate step-by-step instructions for identifying whether your systems are "
            "affected by a CVE. Returns specific shell commands to run, what to look for, "
            "and how to check distro-backported patches. Adapts for Linux, containers, K8s."
        ),
        args_schema=CpeInvestigationInput,
        func=lambda **kw: _cpe_investigation_guide(**kw),
    )


def make_detection_query_builder() -> StructuredTool:
    return StructuredTool(
        name="detection_query_builder",
        description=(
            "Generate detection queries (KQL, Splunk, Elastic, Sigma) for a CVE. "
            "Produces both pre-exploitation (attacker gaining access) and post-exploitation "
            "(exploit triggered) queries with inline explanations and false positive guidance."
        ),
        args_schema=DetectionQueryBuilderInput,
        func=lambda **kw: _detection_query_builder(**kw),
    )


def make_cvss_vector_explainer() -> StructuredTool:
    return StructuredTool(
        name="cvss_vector_explainer",
        description=(
            "Explain a CVSS v3 vector string field by field in plain English. "
            "Accepts a CVSS string (AV:L/AC:L/...) or a CVE ID to look up. "
            "Highlights risk flags (AV:N = network-exploitable, A:H = DoS possible) "
            "and provides a triage summary."
        ),
        args_schema=CvssVectorExplainerInput,
        func=lambda **kw: _explain_cvss_vector(**kw),
    )


# ══════════════════════════════════════════════════════════════════════════════
# Tool 7 — Detection Playbook Search (by data source + similarity)
# ══════════════════════════════════════════════════════════════════════════════

# Static catalog for fast listing without Qdrant round-trip
_DATA_SOURCE_CATALOG: List[Dict] = [
    {
        "source_id": "windows_security_events",
        "description": "Windows Event Log — Security channel (logon, privilege, audit events)",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic", "QRadar"],
        "primary_tables": ["SecurityEvent", "WinEventLog:Security"],
        "investigation_types": ["initial_access", "lateral_movement", "privilege_escalation"],
    },
    {
        "source_id": "sysmon",
        "description": "Microsoft Sysinternals System Monitor — process, network, file events",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic"],
        "primary_tables": ["Sysmon", "index=sysmon"],
        "investigation_types": ["execution", "defense_evasion", "command_and_control"],
    },
    {
        "source_id": "azure_activity",
        "description": "Azure control-plane activity — resource changes, IAM, sign-in",
        "platform_hints": ["Microsoft Sentinel"],
        "primary_tables": ["AzureActivity"],
        "investigation_types": ["privilege_escalation", "initial_access"],
    },
    {
        "source_id": "aws_cloudtrail",
        "description": "AWS API activity — IAM, S3, EC2 control-plane events",
        "platform_hints": ["Splunk", "Athena", "Microsoft Sentinel", "Elastic"],
        "primary_tables": ["AWSCloudTrail", "index=aws sourcetype=aws:cloudtrail"],
        "investigation_types": ["privilege_escalation", "exfiltration"],
    },
    {
        "source_id": "kubernetes_audit",
        "description": "Kubernetes API server audit log — pod lifecycle, RBAC, exec events",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic", "Loki"],
        "primary_tables": ["AzureDiagnostics", "KubeAuditAdmin_CL"],
        "investigation_types": ["privilege_escalation", "execution"],
    },
    {
        "source_id": "network_flows",
        "description": "NetFlow / NSG flow logs / Zeek conn — IP-level traffic summaries",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic", "Zeek"],
        "primary_tables": ["AzureNetworkAnalytics_CL", "CommonSecurityLog", "zeek_conn"],
        "investigation_types": ["command_and_control", "reconnaissance", "exfiltration"],
    },
    {
        "source_id": "linux_auditd",
        "description": "Linux kernel audit daemon — syscall, file, exec, network events",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic"],
        "primary_tables": ["Syslog", "auditd"],
        "investigation_types": ["privilege_escalation", "execution"],
    },
    {
        "source_id": "mde",
        "description": "Microsoft Defender for Endpoint — process, file, network, logon device events",
        "platform_hints": ["Microsoft Defender Portal", "Microsoft Sentinel"],
        "primary_tables": ["DeviceEvents", "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"],
        "investigation_types": ["impact", "execution", "lateral_movement"],
    },
    {
        "source_id": "web_application_logs",
        "description": "IIS / Nginx / Apache access logs — HTTP method, URI, status, user-agent",
        "platform_hints": ["Microsoft Sentinel", "Splunk", "Elastic"],
        "primary_tables": ["W3CIISLog", "CustomLog_CL", "nginx_access"],
        "investigation_types": ["initial_access", "execution"],
    },
]


class PlaybookSearchInput(BaseModel):
    query: str = Field(
        description=(
            "Natural language description of what you are investigating. "
            "Examples: 'lateral movement via stolen credentials', "
            "'container escape from privileged pod', "
            "'ransomware precursor on endpoint', "
            "'suspicious outbound connection from script host'"
        )
    )
    source_id: Optional[str] = Field(
        default=None,
        description=(
            "Filter to a specific data source. One of: windows_security_events, sysmon, "
            "azure_activity, aws_cloudtrail, kubernetes_audit, network_flows, "
            "linux_auditd, mde, web_application_logs. Leave empty to search all sources."
        ),
    )
    investigation_type: Optional[str] = Field(
        default=None,
        description=(
            "Filter by investigation type: initial_access | lateral_movement | "
            "privilege_escalation | execution | command_and_control | exfiltration | "
            "defense_evasion | reconnaissance | impact"
        ),
    )
    top_k: int = Field(default=3, description="Number of playbooks to return (1–5).")


def _detection_playbook_search(
    query: str,
    source_id: Optional[str] = None,
    investigation_type: Optional[str] = None,
    top_k: int = 3,
) -> str:
    """
    Similarity-search the detection_playbooks Qdrant collection and return matching
    playbooks with their natural language investigation questions.
    """
    from asteraskills.storage.vector_store import VectorStoreClient
    from asteraskills.storage.collections import DetectionCollections
    import asyncio

    try:
        client = VectorStoreClient()
        filters: Dict[str, Any] = {}
        if source_id:
            filters["source_id"] = source_id
        if investigation_type:
            filters["investigation_type"] = investigation_type

        results = asyncio.run(client.query(
            collection_name=DetectionCollections.PLAYBOOKS,
            query_text=query,
            top_k=min(top_k, 5),
            filter_params=filters if filters else None,
        ))

        if not results:
            # Graceful fallback: return static catalog matches on source_id
            fallback = [
                s for s in _DATA_SOURCE_CATALOG
                if not source_id or s["source_id"] == source_id
            ][:top_k]
            return json.dumps({
                "success": True,
                "source": "static_catalog_fallback",
                "message": "No vector store results — returning data source catalog entries.",
                "results": fallback,
            }, indent=2)

        formatted = []
        for r in results:
            meta = r.get("metadata", {})
            formatted.append({
                "playbook_title": meta.get("title", ""),
                "source_id": meta.get("source_id", ""),
                "investigation_type": meta.get("investigation_type", ""),
                "trigger": meta.get("trigger", ""),
                "platform_hints": meta.get("platform_hints", []),
                "primary_tables": meta.get("primary_tables", []),
                "investigation_questions": meta.get("investigation_questions", []),
                "attack_techniques": meta.get("attack_techniques", []),
                "similarity": round(r.get("score", 0), 3),
            })

        return json.dumps({
            "success": True,
            "query": query,
            "filters": {"source_id": source_id, "investigation_type": investigation_type},
            "total_results": len(formatted),
            "results": formatted,
        }, indent=2)

    except Exception as exc:
        log.exception("detection_playbook_search failed")
        return json.dumps({"success": False, "error": str(exc)})


# ══════════════════════════════════════════════════════════════════════════════
# Tool 8 — List Playbook Data Sources
# ══════════════════════════════════════════════════════════════════════════════

class ListDataSourcesInput(BaseModel):
    investigation_type: Optional[str] = Field(
        default=None,
        description=(
            "Filter sources that cover a specific investigation type: "
            "initial_access | lateral_movement | privilege_escalation | execution | "
            "command_and_control | exfiltration | defense_evasion | reconnaissance | impact. "
            "Leave empty to list all sources."
        ),
    )


def _list_playbook_data_sources(investigation_type: Optional[str] = None) -> str:
    """
    Return the catalog of available detection playbook data sources.
    Each entry lists what the source covers, which platforms support it, and
    which investigation types have playbooks available for that source.
    """
    sources = _DATA_SOURCE_CATALOG
    if investigation_type:
        sources = [
            s for s in sources
            if investigation_type.lower() in [t.lower() for t in s.get("investigation_types", [])]
        ]

    if not sources:
        return json.dumps({
            "success": True,
            "message": f"No data sources found for investigation_type='{investigation_type}'.",
            "sources": [],
        }, indent=2)

    return json.dumps({
        "success": True,
        "total": len(sources),
        "filter": {"investigation_type": investigation_type},
        "sources": sources,
        "usage_hint": (
            "Pass source_id to detection_playbook_search to get the natural language "
            "investigation questions for that source. Then use detection_query_builder "
            "to convert a question into a platform-specific query."
        ),
    }, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Tool 9 — Synthesize Playbook (causal + KB grounded)
# ══════════════════════════════════════════════════════════════════════════════

class SynthesizePlaybookInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-26855")
    cvss_vector: Optional[str] = Field(
        default=None,
        description="CVSS v3 vector string. Looked up automatically if not provided.",
    )
    cvss_base: Optional[float] = Field(
        default=None,
        description="CVSS base score (0–10). Looked up automatically if not provided.",
    )
    epss_score: float = Field(
        default=0.0,
        description="EPSS probability (0–1) from EPSS lookup.",
    )
    in_kev: bool = Field(
        default=False,
        description="Whether the CVE is in the CISA KEV catalog.",
    )
    kev_ransomware: bool = Field(
        default=False,
        description="Whether the CISA KEV entry is associated with a ransomware campaign.",
    )
    environment_type: str = Field(
        default="bare_metal",
        description="Target environment: k8s | container | cloud_vm | bare_metal | mixed",
    )
    asset_criticality: str = Field(
        default="medium",
        description="Asset criticality: crown_jewel | high | medium | low",
    )
    internet_facing: bool = Field(
        default=False,
        description="Whether the affected service is reachable from the internet.",
    )
    has_controls: bool = Field(
        default=False,
        description="Whether compensating controls (EDR, WAF, network isolation) are in place.",
    )
    source_id: Optional[str] = Field(
        default=None,
        description=(
            "Preferred data source to lead with. One of: windows_security_events, sysmon, "
            "azure_activity, aws_cloudtrail, kubernetes_audit, network_flows, "
            "linux_auditd, mde, web_application_logs. Leave empty for auto-ranking."
        ),
    )


def _synthesize_playbook(
    cve_id: str,
    cvss_vector: Optional[str] = None,
    cvss_base: Optional[float] = None,
    epss_score: float = 0.0,
    in_kev: bool = False,
    kev_ransomware: bool = False,
    environment_type: str = "bare_metal",
    asset_criticality: str = "medium",
    internet_facing: bool = False,
    has_controls: bool = False,
    source_id: Optional[str] = None,
) -> str:
    """Synthesise a causally-grounded investigation playbook from CVE + context."""

    # Auto-fetch CVSS if not provided
    _cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    _cvss_base   = cvss_base   or 9.8

    if not cvss_vector or cvss_base is None:
        try:
            from asteraskills.tools.cve_enrichment import _enrich_cve
            raw = _enrich_cve(cve_id)
            cve_data = json.loads(raw) if isinstance(raw, str) else raw
            _cvss_vector = cve_data.get("cvss_vector") or _cvss_vector
            _cvss_base   = float(cve_data.get("cvss_score") or _cvss_base)
        except Exception as exc:
            log.debug("Auto-fetch CVSS failed for %s: %s", cve_id, exc)

    try:
        from asteraskills.agents.playbook_synthesizer import PlaybookSynthesizer
        synth = PlaybookSynthesizer()
        result = synth.synthesize(
            cve_id=cve_id,
            cvss_vector=_cvss_vector,
            cvss_base=_cvss_base,
            epss_score=epss_score,
            in_kev=in_kev,
            kev_ransomware=kev_ransomware,
            environment_type=environment_type,
            asset_criticality=asset_criticality,
            internet_facing=internet_facing,
            has_controls=has_controls,
            source_id=source_id,
        )
        return json.dumps(result.to_dict(), indent=2)
    except Exception as exc:
        log.exception("synthesize_playbook failed")
        return json.dumps({"success": False, "error": str(exc)})


# ── Factory functions ─────────────────────────────────────────────────────────

def make_detection_playbook_search() -> StructuredTool:
    return StructuredTool(
        name="detection_playbook_search",
        description=(
            "Find detection engineering playbooks for a given investigation scenario and data source. "
            "Returns natural language investigation questions that work across any SIEM platform. "
            "Use when an engineer selects a data source and wants to know what to look for."
        ),
        args_schema=PlaybookSearchInput,
        func=lambda **kw: _detection_playbook_search(**kw),
    )


def make_synthesize_playbook() -> StructuredTool:
    return StructuredTool(
        name="synthesize_playbook",
        description=(
            "Generate a causally-grounded investigation playbook for a CVE. "
            "Synthesises domain scores from the CVSS vector + environment context, "
            "runs the causal structural equation (Pearl Rung 1/2), ranks data sources "
            "by which ATT&CK tactics are enabled, retrieves matching investigation "
            "questions from the knowledge base, and annotates each question with "
            "its causal driver. Also computes counterfactual interventions (do-calculus) "
            "and maps them to compensating controls. "
            "Use this when the user has provided enough context (environment + criticality) "
            "for a full analysis."
        ),
        args_schema=SynthesizePlaybookInput,
        func=lambda **kw: _synthesize_playbook(**kw),
    )


def make_list_playbook_data_sources() -> StructuredTool:
    return StructuredTool(
        name="list_playbook_data_sources",
        description=(
            "List all available detection playbook data sources (Windows Security Events, Sysmon, "
            "CloudTrail, Kubernetes Audit, etc.). Shows which investigation types each source covers "
            "and which SIEM platforms are supported. Use this when the user asks which data source "
            "to choose or wants to see what playbooks are available."
        ),
        args_schema=ListDataSourcesInput,
        func=lambda **kw: _list_playbook_data_sources(**kw),
    )


# ── TOOL_REGISTRY entries ─────────────────────────────────────────────────────

DETECTION_TOOL_REGISTRY = {
    "detection_scenario_search":    make_detection_scenario_search,
    "kill_chain_builder":           make_kill_chain_builder,
    "priority_score_calculator":    make_priority_score_calculator,
    "cpe_investigation_guide":      make_cpe_investigation_guide,
    "detection_query_builder":      make_detection_query_builder,
    "cvss_vector_explainer":        make_cvss_vector_explainer,
    "detection_playbook_search":    make_detection_playbook_search,
    "list_playbook_data_sources":   make_list_playbook_data_sources,
    "synthesize_playbook":          make_synthesize_playbook,
}
