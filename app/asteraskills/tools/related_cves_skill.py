"""
RelatedCVEsSkill — Capability 3 (revised): intent-routed Related CVE Discovery.

A single polymorphic tool that accepts natural language or structured queries
and routes through an intent classifier to one of four dispatch paths:

  Path 1 — software / package   → sbom_cve_context (single-component SBOM)
  Path 2 — ATT&CK technique     → cve_attack_mappings direct join
  Path 3 — ATT&CK tactic        → tactic → T-codes → Path 2
  Path 4 — Kill chain phase     → phase → tactic cluster → T-codes → Path 2

All paths converge at a rank-and-dedup stage before returning results.
SBOM inputs additionally run ATT&CK hydration + related CVE expansion.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.agents.skills.cve_query_router import classify_cve_query
from asteraskills.tools.base import SecurityTool, ToolResult

logger = logging.getLogger(__name__)


# ── Pydantic schemas ────────────────────────────────────────────────────────────

class RelatedCVEsInput(BaseModel):
    query: str = Field(
        description=(
            "Natural language or structured query. Examples: "
            "'CVEs for openssl 3.0.7', "
            "'CVEs exploiting T1190', "
            "'CVEs in Initial Access tactic', "
            "'CVEs in Delivery kill chain phase', "
            "'pkg:npm/lodash@4.17.21'"
        )
    )
    max_results: int = Field(default=20, ge=1, le=100)
    min_cvss: float = Field(default=0.0, ge=0.0, le=10.0)


class RawCVEHit(BaseModel):
    cve_id: str
    cvss_score: float = 0.0
    epss_score: float = 0.0
    exploit_maturity: str = "none"
    matched_technique_ids: List[str] = Field(default_factory=list)
    matched_tactic_ids: List[str] = Field(default_factory=list)
    source_path: str = ""
    description: str = ""


class RankedCVEResult(BaseModel):
    cve_id: str
    cvss_score: float
    epss_score: float
    exploit_maturity: str
    matched_technique_ids: List[str]
    composite_score: float
    source_path: str
    description: str


# ── Rank and dedup ──────────────────────────────────────────────────────────────

def _rank_and_dedup(
    hits: List[RawCVEHit],
    max_results: int = 20,
    min_cvss: float = 0.0,
    total_query_techniques: int = 0,
) -> List[RankedCVEResult]:
    """
    1. Deduplicate by cve_id (merge matched_technique_ids across paths).
    2. Score: CVSS × 0.35 + EPSS × 0.35 + exploit bonus + technique coverage × 0.20.
    3. Return top max_results.
    """
    grouped: Dict[str, List[RawCVEHit]] = defaultdict(list)
    for h in hits:
        grouped[h.cve_id].append(h)

    exploit_bonus_map = {"none": 0.0, "poc": 0.1, "weaponised": 0.3}
    results: List[RankedCVEResult] = []

    for cve_id, group in grouped.items():
        merged_techniques = list({t for h in group for t in h.matched_technique_ids})
        base = group[0]
        cvss = base.cvss_score
        if cvss < min_cvss:
            continue
        epss = base.epss_score
        maturity = base.exploit_maturity

        base_score = (cvss / 10.0) * 0.35
        epss_weight = epss * 0.35
        e_bonus = exploit_bonus_map.get(maturity, 0.0)
        if total_query_techniques > 0:
            tech_cov = (len(merged_techniques) / total_query_techniques) * 0.20
        else:
            tech_cov = 0.0
        composite = base_score + epss_weight + e_bonus + tech_cov

        results.append(
            RankedCVEResult(
                cve_id=cve_id,
                cvss_score=cvss,
                epss_score=epss,
                exploit_maturity=maturity,
                matched_technique_ids=merged_techniques,
                composite_score=round(composite, 4),
                source_path=base.source_path,
                description=base.description,
            )
        )

    results.sort(key=lambda r: r.composite_score, reverse=True)
    return results[:max_results]


# ── Dispatch helpers ────────────────────────────────────────────────────────────

def _lookup_by_technique_ids(
    technique_ids: List[str],
    min_cvss: float = 0.0,
    limit: int = 150,
) -> List[RawCVEHit]:
    """Path 2: direct cve_attack_mappings JOIN cve_intelligence per T-code."""
    if not technique_ids:
        return []
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            rows = session.execute(
                text("""
                    SELECT
                        ci.cve_id,
                        ci.cvss_score,
                        ci.epss_score,
                        ci.exploit_maturity,
                        ci.description,
                        array_agg(DISTINCT cam.technique_id) AS techniques,
                        array_agg(DISTINCT cam.tactic) AS tactics
                    FROM cve_intelligence ci
                    JOIN cve_attack_mappings cam ON ci.cve_id = cam.cve_id
                    WHERE cam.technique_id = ANY(:technique_ids)
                      AND (ci.cvss_score >= :min_cvss OR ci.cvss_score IS NULL)
                    GROUP BY ci.cve_id, ci.cvss_score, ci.epss_score,
                             ci.exploit_maturity, ci.description
                    ORDER BY ci.epss_score DESC NULLS LAST,
                             ci.cvss_score DESC NULLS LAST
                    LIMIT :limit
                """),
                {
                    "technique_ids": technique_ids,
                    "min_cvss": min_cvss,
                    "limit": limit,
                },
            ).fetchall()
            return [
                RawCVEHit(
                    cve_id=r[0],
                    cvss_score=float(r[1] or 0),
                    epss_score=float(r[2] or 0),
                    exploit_maturity=r[3] or "none",
                    description=r[4] or "",
                    matched_technique_ids=list(r[5] or []),
                    matched_tactic_ids=list(r[6] or []),
                    source_path="technique",
                )
                for r in rows
            ]
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.warning("technique lookup failed: %s", exc)
    return []


def _tactic_to_technique_ids(tactic_ids: List[str]) -> List[str]:
    """Resolve tactic IDs to technique IDs via attack_techniques_index or Qdrant."""
    technique_ids: List[str] = []
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            rows = session.execute(
                text("""
                    SELECT DISTINCT technique_id
                    FROM attack_techniques_index
                    WHERE tactic_id = ANY(:tactic_ids)
                       OR tactic_name = ANY(:tactic_ids)
                """),
                {"tactic_ids": tactic_ids},
            ).fetchall()
            technique_ids = [r[0] for r in rows if r[0]]
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("attack_techniques_index lookup failed: %s", exc)

    if not technique_ids:
        # Qdrant semantic fallback filtered by tactic payload
        try:
            from asteraskills.storage.vector_store import get_vector_store_client
            from asteraskills.storage.collections import AttackCollections

            client = get_vector_store_client()
            for ta_id in tactic_ids:
                hits = client.similarity_search_with_score(
                    query=ta_id,
                    collection_name=AttackCollections.techniques(),
                    top_k=50,
                    filter={"tactic": ta_id},
                )
                for doc, _ in hits:
                    tid = (doc.metadata or {}).get("technique_id") or (doc.metadata or {}).get("id", "")
                    if tid:
                        technique_ids.append(tid)
        except Exception as exc:
            logger.debug("Qdrant tactic → T-codes failed: %s", exc)

    return list(dict.fromkeys(technique_ids))


def _dispatch_software(
    query: str, min_cvss: float, max_results: int
) -> List[RawCVEHit]:
    """Path 1: delegate to sbom_cve_context as a single-component call."""
    try:
        from asteraskills.tools.sbom_cve_context import _execute_sbom_cve_context

        # Try to parse out a version from the query (e.g. "openssl 3.0.7")
        import re

        version_match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", query)
        version = version_match.group(1) if version_match else "0"
        name = query.replace(version, "").strip() if version != "0" else query

        # Handle purl directly
        if query.startswith("pkg:"):
            data = _execute_sbom_cve_context("", "", purl=query)
        else:
            data = _execute_sbom_cve_context(name, version)

        hits: List[RawCVEHit] = []
        for rec in data.get("cves", []):
            cvss = rec.get("cvss_score", 0.0)
            if cvss < min_cvss:
                continue
            hits.append(
                RawCVEHit(
                    cve_id=rec["cve_id"],
                    cvss_score=cvss,
                    epss_score=rec.get("epss_score", 0.0),
                    exploit_maturity=rec.get("exploit_maturity", "none"),
                    matched_technique_ids=rec.get("technique_ids", []),
                    source_path="software",
                )
            )
        return hits
    except Exception as exc:
        logger.warning("software dispatch failed: %s", exc)
    return []


def _dispatch_sbom(query: str, min_cvss: float) -> Dict[str, Any]:
    """SBOM path: parse file / parse purl → per-component CVE + expansion."""
    try:
        from asteraskills.tools.sbom_cve_context import _execute_sbom_cve_context

        if query.startswith("pkg:"):
            data = _execute_sbom_cve_context("", "", purl=query)
            return {"openssl@unknown": data}

        # If it looks like a file path, try to read and parse
        import os

        if os.path.isfile(query):
            return _parse_sbom_file(query, min_cvss)
    except Exception as exc:
        logger.warning("SBOM dispatch failed: %s", exc)
    return {}


def _parse_sbom_file(path: str, min_cvss: float) -> Dict[str, Any]:
    """Parse CycloneDX / SPDX JSON and call sbom_cve_context per component."""
    import json

    from asteraskills.tools.sbom_cve_context import _execute_sbom_cve_context

    with open(path) as f:
        doc = json.load(f)

    components = []
    # CycloneDX
    for comp in doc.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl")
        if name:
            components.append((name, version, purl))
    # SPDX
    for pkg in doc.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        if name:
            components.append((name, version, None))

    results: Dict[str, Any] = {}
    for name, version, purl in components:
        key = f"{name}@{version}"
        data = _execute_sbom_cve_context(name, version, purl=purl)
        results[key] = data
    return results


# ── ATT&CK hydration + related CVE expansion for SBOM ──────────────────────────

def _enrich_cve_with_attack(cve_ids: List[str]) -> Dict[str, List[str]]:
    """Return {cve_id: [technique_id, ...]} for CVEs missing mappings."""
    if not cve_ids:
        return {}
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            rows = session.execute(
                text("""
                    SELECT cve_id, technique_id
                    FROM cve_attack_mappings
                    WHERE cve_id = ANY(:ids)
                """),
                {"ids": cve_ids},
            ).fetchall()
            mapping: Dict[str, List[str]] = defaultdict(list)
            for cve_id, tid in rows:
                mapping[cve_id].append(tid)
            return dict(mapping)
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("enrich_cve_with_attack failed: %s", exc)
    return {}


def _expand_related_cves_for_component(
    component_cves: List[Dict[str, Any]],
    known_cve_ids: set[str],
    max_related: int = 10,
    min_cvss: float = 0.0,
) -> List[RankedCVEResult]:
    """Collect technique IDs from component CVEs, fan out to sibling CVEs."""
    technique_ids = list({t for c in component_cves for t in c.get("technique_ids", [])})
    if not technique_ids:
        return []
    hits = _lookup_by_technique_ids(technique_ids, min_cvss=min_cvss, limit=150)
    hits = [h for h in hits if h.cve_id not in known_cve_ids]
    return _rank_and_dedup(
        hits,
        max_results=max_related,
        min_cvss=min_cvss,
        total_query_techniques=len(technique_ids),
    )


# ── Main execute ────────────────────────────────────────────────────────────────

def _execute_related_cves(
    query: str,
    max_results: int = 20,
    min_cvss: float = 0.0,
) -> Dict[str, Any]:
    intent = classify_cve_query(query)
    logger.debug(
        "related_cves intent=%s terms=%s confidence=%.2f",
        intent.intent_type,
        intent.resolved_terms,
        intent.confidence,
    )

    # ── SBOM path ──────────────────────────────────────────────────────────
    if intent.intent_type == "sbom":
        component_map = _dispatch_sbom(query, min_cvss)
        source_map: Dict[str, Any] = {}
        for comp_key, comp_data in component_map.items():
            cves = comp_data.get("cves", [])
            cve_ids = {c["cve_id"] for c in cves}
            # Hydrate missing technique mappings
            unmapped = [c["cve_id"] for c in cves if not c.get("technique_ids")]
            if unmapped:
                tech_map = _enrich_cve_with_attack(unmapped)
                for c in cves:
                    if c["cve_id"] in tech_map:
                        c["technique_ids"] = tech_map[c["cve_id"]]
            # Expand related CVEs
            related = _expand_related_cves_for_component(
                cves, cve_ids, max_related=10, min_cvss=min_cvss
            )
            all_techniques = list({t for c in cves for t in c.get("technique_ids", [])})
            source_map[comp_key] = {
                "cpe_uri": comp_data.get("cpe_uri", ""),
                "direct_cves": [c["cve_id"] for c in cves],
                "related_cves": [
                    {
                        "cve_id": r.cve_id,
                        "shared_techniques": r.matched_technique_ids,
                        "composite_score": r.composite_score,
                    }
                    for r in related
                ],
                "max_cvss": max((c.get("cvss_score", 0) for c in cves), default=0),
                "technique_surface": all_techniques,
            }
        return {
            "query": query,
            "intent_type": "sbom",
            "source_map": source_map,
        }

    # ── Technique path (Path 2) ────────────────────────────────────────────
    if intent.intent_type == "technique":
        hits = _lookup_by_technique_ids(
            intent.resolved_terms, min_cvss=min_cvss, limit=max_results * 3
        )
        ranked = _rank_and_dedup(
            hits,
            max_results=max_results,
            min_cvss=min_cvss,
            total_query_techniques=len(intent.resolved_terms),
        )
        return {
            "query": query,
            "intent_type": "technique",
            "technique_ids": intent.resolved_terms,
            "results": [r.model_dump() for r in ranked],
        }

    # ── Tactic path (Path 3) ───────────────────────────────────────────────
    if intent.intent_type == "tactic":
        technique_ids = _tactic_to_technique_ids(intent.resolved_terms)
        hits = _lookup_by_technique_ids(technique_ids, min_cvss=min_cvss, limit=max_results * 3)
        ranked = _rank_and_dedup(
            hits,
            max_results=max_results,
            min_cvss=min_cvss,
            total_query_techniques=len(technique_ids),
        )
        return {
            "query": query,
            "intent_type": "tactic",
            "tactic_ids": intent.resolved_terms,
            "technique_ids": technique_ids,
            "results": [r.model_dump() for r in ranked],
        }

    # ── Kill chain path (Path 4) ───────────────────────────────────────────
    if intent.intent_type == "kill_chain":
        # resolved_terms are already tactic IDs from the classifier
        technique_ids = _tactic_to_technique_ids(intent.resolved_terms)
        hits = _lookup_by_technique_ids(technique_ids, min_cvss=min_cvss, limit=max_results * 3)
        ranked = _rank_and_dedup(
            hits,
            max_results=max_results,
            min_cvss=min_cvss,
            total_query_techniques=len(technique_ids),
        )
        return {
            "query": query,
            "intent_type": "kill_chain",
            "tactic_ids": intent.resolved_terms,
            "technique_ids": technique_ids,
            "results": [r.model_dump() for r in ranked],
        }

    # ── Software / default path (Path 1) ──────────────────────────────────
    hits = _dispatch_software(query, min_cvss=min_cvss, max_results=max_results * 3)
    ranked = _rank_and_dedup(hits, max_results=max_results, min_cvss=min_cvss)
    return {
        "query": query,
        "intent_type": "software",
        "results": [r.model_dump() for r in ranked],
    }


# ── Tool factory ────────────────────────────────────────────────────────────────

class RelatedCVEsSkillTool(SecurityTool):
    """Capability 3: polymorphic related-CVE discovery via intent routing."""

    @property
    def tool_name(self) -> str:
        return "related_cves"

    def cache_key(self, **kwargs) -> str:
        return f"related_cves:{kwargs.get('query', '')}:{kwargs.get('min_cvss', 0)}"

    def execute(
        self,
        query: str,
        max_results: int = 20,
        min_cvss: float = 0.0,
    ) -> ToolResult:
        try:
            data = _execute_related_cves(query, max_results, min_cvss)
            return ToolResult(
                success=True,
                data=data,
                source="cve_attack_mappings+cpe_registry",
                timestamp=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            logger.error("RelatedCVEsSkillTool failed: %s", exc)
            return ToolResult(
                success=False,
                data=None,
                source="cve_attack_mappings+cpe_registry",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(exc),
            )


def create_related_cves_tool() -> StructuredTool:
    """Create LangChain tool for intent-routed related CVE discovery (Capability 3)."""
    tool_instance = RelatedCVEsSkillTool()

    def _execute(
        query: str,
        max_results: int = 20,
        min_cvss: float = 0.0,
    ) -> Dict[str, Any]:
        return tool_instance.execute(query, max_results, min_cvss).to_dict()

    return StructuredTool.from_function(
        func=_execute,
        name="related_cves",
        description=(
            "Find CVEs related to a software package, ATT&CK technique, tactic, kill chain phase, "
            "or SBOM. Accepts natural language or structured queries: "
            "'openssl 3.0.7', 'T1190', 'Initial Access', 'Exploitation kill chain phase', "
            "'pkg:npm/lodash@4.17.21'. "
            "Routes through an intent classifier and returns ranked CVE results with CVSS, EPSS, "
            "exploit maturity, and ATT&CK technique coverage."
        ),
        args_schema=RelatedCVEsInput,
    )
