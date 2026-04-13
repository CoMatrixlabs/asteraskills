"""
SBOMCVEContextTool — Capability 2: SBOM CVE Source Attribution.

Given a software component (name + version, purl, or raw CPE URI), resolves
it to a canonical CPE, looks up all CVEs affecting that CPE, and hydrates
each CVE with pre-computed ATT&CK technique mappings.

Three-step internal flow:
  Step 1 — CPE normalization   (purl / name → cpe_names Qdrant / Postgres)
  Step 2 — CVE lookup          (cve_cpe_links → cve_intelligence)
  Step 3 — Technique hydration (cve_attack_mappings)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import SecurityTool, ToolResult

logger = logging.getLogger(__name__)

VECTOR_SCORE_THRESHOLD = 0.82
VECTOR_TOP_K = 3


# ── Pydantic schemas ────────────────────────────────────────────────────────────

class SBOMComponentInput(BaseModel):
    component_name: str = Field(description="Package / library name (e.g. 'openssl')")
    component_version: str = Field(description="Version string (e.g. '3.0.7')")
    purl: Optional[str] = Field(
        default=None,
        description="Package URL e.g. pkg:pypi/cryptography@41.0.3",
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description="Ecosystem hint: pypi | npm | maven | golang | rpm | deb",
    )


class CVESourceRecord(BaseModel):
    cve_id: str
    cvss_score: float = 0.0
    epss_score: float = 0.0
    exploit_maturity: str = "none"
    cwe_ids: List[str] = Field(default_factory=list)
    technique_ids: List[str] = Field(default_factory=list)
    source_component: str = ""
    source_cpe_uri: str = ""
    version_in_range: bool = False


class SBOMCVEContextOutput(BaseModel):
    component: str
    cpe_uri: str
    resolution_confidence: float
    cves: List[CVESourceRecord]
    total_critical: int
    total_weaponised: int


# ── Step 1: CPE normalisation ───────────────────────────────────────────────────

def _parse_purl(purl: str) -> tuple[str, str]:
    """Extract (package_name, version) from a purl string."""
    try:
        # pkg:ecosystem/name@version
        m = re.match(r"pkg:[^/]+/([^@\s]+)@([^\s]+)", purl)
        if m:
            return m.group(1).split("/")[-1], m.group(2)
    except Exception:
        pass
    return "", ""


def _strip_common_suffixes(name: str) -> str:
    for suffix in ("-dev", "-lib", "-utils", "-core", "-common"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _resolve_cpe_exact(cpe_uri: str, session: Any) -> Optional[tuple[str, float]]:
    """Return (cpe_uri, confidence=1.0) for an exact Postgres match."""
    try:
        from sqlalchemy import text

        row = session.execute(
            text("SELECT cpe_name FROM cpe_names WHERE cpe_name = :uri LIMIT 1"),
            {"uri": cpe_uri},
        ).fetchone()
        if row:
            return row[0], 1.0
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cpe_names exact lookup: %s", exc)
    return None


def _resolve_cpe_by_name(name: str, version: str, session: Any) -> Optional[tuple[str, float]]:
    """Try vendor/product SQL lookup then Qdrant vector search."""
    clean = _strip_common_suffixes(name.lower())

    # SQL lookup first
    try:
        from sqlalchemy import text

        row = session.execute(
            text("""
                SELECT cpe_name FROM cpe_names
                WHERE (LOWER(vendor) = :name OR LOWER(product) = :name)
                LIMIT 1
            """),
            {"name": clean},
        ).fetchone()
        if row:
            return row[0], 0.95
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cpe_names name lookup: %s", exc)

    # Qdrant vector fallback
    try:
        from asteraskills.storage.vector_store import get_vector_store_client

        query = f"{name} {version}".strip()
        client = get_vector_store_client()
        hits = client.similarity_search_with_score(
            query=query,
            collection_name="cpe_names",
            top_k=VECTOR_TOP_K,
        )
        for doc, score in hits:
            if score >= VECTOR_SCORE_THRESHOLD:
                payload = doc.metadata if hasattr(doc, "metadata") else {}
                cpe = payload.get("cpe_name", doc.page_content)
                return cpe, float(score)
    except Exception as exc:
        logger.debug("cpe_names vector search: %s", exc)

    return None


# ── Step 2: CVE lookup ──────────────────────────────────────────────────────────

def _cves_for_cpe(cpe_uri: str, session: Any) -> List[Dict[str, Any]]:
    """Fetch CVEs from cve_cpe_links → cve_intelligence."""
    try:
        from sqlalchemy import text

        rows = session.execute(
            text("""
                SELECT
                    ci.cve_id,
                    ci.cvss_score,
                    ci.epss_score,
                    ci.exploit_maturity,
                    ci.cwe_ids,
                    ccl.version_start_incl,
                    ccl.version_end_excl,
                    ccl.version_end_incl
                FROM cve_cpe_links ccl
                JOIN cve_intelligence ci ON ci.cve_id = ccl.cve_id
                WHERE ccl.cpe_uri = :cpe_uri AND ccl.is_vulnerable = TRUE
                ORDER BY ci.cvss_score DESC
                LIMIT 100
            """),
            {"cpe_uri": cpe_uri},
        ).fetchall()
        return [
            {
                "cve_id": r[0],
                "cvss_score": float(r[1] or 0),
                "epss_score": float(r[2] or 0),
                "exploit_maturity": r[3] or "none",
                "cwe_ids": r[4] or [],
                "version_start_incl": r[5],
                "version_end_excl": r[6],
                "version_end_incl": r[7],
            }
            for r in rows
        ]
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cve_cpe_links query: %s", exc)
    return []


def _nvd_cves_fallback(cpe_uri: str) -> List[Dict[str, Any]]:
    """Fallback: NVD CPE search API when local data is absent."""
    import requests

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cpeName": cpe_uri},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        out = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            cvss = 0.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    cvss = float(metrics[0].get("cvssData", {}).get("baseScore", 0))
                    break
            out.append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "epss_score": 0.0,
                "exploit_maturity": "none",
                "cwe_ids": [],
                "version_start_incl": None,
                "version_end_excl": None,
                "version_end_incl": None,
            })
        return out
    except Exception as exc:
        logger.debug("NVD CPE fallback: %s", exc)
    return []


# ── Step 3: Technique hydration ─────────────────────────────────────────────────

def _hydrate_techniques(cve_ids: List[str], session: Any) -> Dict[str, List[str]]:
    """Return {cve_id: [technique_id, ...]} for given CVE IDs."""
    if not cve_ids:
        return {}
    try:
        from sqlalchemy import text

        rows = session.execute(
            text("""
                SELECT cve_id, technique_id
                FROM cve_attack_mappings
                WHERE cve_id = ANY(:ids)
            """),
            {"ids": cve_ids},
        ).fetchall()
        mapping: Dict[str, List[str]] = {}
        for cve_id, technique_id in rows:
            mapping.setdefault(cve_id, []).append(technique_id)
        return mapping
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cve_attack_mappings hydration: %s", exc)
    return {}


# ── Core execution ──────────────────────────────────────────────────────────────

def _execute_sbom_cve_context(
    component_name: str,
    component_version: str,
    purl: Optional[str] = None,
    ecosystem: Optional[str] = None,
) -> Dict[str, Any]:
    component_label = f"{component_name}@{component_version}"

    # ── Step 1: CPE normalisation ──────────────────────────────────────────
    resolved_cpe: Optional[str] = None
    confidence: float = 0.0

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session

        with get_security_intel_session("cve_attack") as session:
            if purl:
                pkg_name, pkg_ver = _parse_purl(purl)
                if not pkg_name:
                    pkg_name, pkg_ver = component_name, component_version
                result = _resolve_cpe_by_name(pkg_name, pkg_ver, session)
                if result:
                    resolved_cpe, confidence = result

            if resolved_cpe is None:
                result = _resolve_cpe_by_name(component_name, component_version, session)
                if result:
                    resolved_cpe, confidence = result

            if resolved_cpe is None:
                return {
                    "component": component_label,
                    "cpe_uri": "",
                    "resolution_confidence": 0.0,
                    "cves": [],
                    "total_critical": 0,
                    "total_weaponised": 0,
                }

            # ── Step 2: CVE lookup ─────────────────────────────────────────
            raw_cves = _cves_for_cpe(resolved_cpe, session)
            if not raw_cves:
                raw_cves = _nvd_cves_fallback(resolved_cpe)

            if not raw_cves:
                return {
                    "component": component_label,
                    "cpe_uri": resolved_cpe,
                    "resolution_confidence": confidence,
                    "cves": [],
                    "total_critical": 0,
                    "total_weaponised": 0,
                }

            # ── Step 3: Technique hydration ────────────────────────────────
            cve_ids = [c["cve_id"] for c in raw_cves]
            technique_map = _hydrate_techniques(cve_ids, session)

    except Exception as exc:
        logger.warning("sbom_cve_context session failed: %s", exc)
        resolved_cpe = resolved_cpe or ""
        raw_cves = []
        technique_map = {}

    records: List[Dict[str, Any]] = []
    total_critical = 0
    total_weaponised = 0

    for c in raw_cves:
        cve_id = c["cve_id"]
        record = CVESourceRecord(
            cve_id=cve_id,
            cvss_score=c["cvss_score"],
            epss_score=c["epss_score"],
            exploit_maturity=c["exploit_maturity"],
            cwe_ids=c["cwe_ids"] if isinstance(c["cwe_ids"], list) else [],
            technique_ids=technique_map.get(cve_id, []),
            source_component=component_label,
            source_cpe_uri=resolved_cpe or "",
            version_in_range=bool(
                c.get("version_start_incl") or c.get("version_end_excl")
            ),
        )
        if c["cvss_score"] >= 9.0:
            total_critical += 1
        if c["exploit_maturity"] == "weaponised":
            total_weaponised += 1
        records.append(record.model_dump())

    return {
        "component": component_label,
        "cpe_uri": resolved_cpe or "",
        "resolution_confidence": confidence,
        "cves": records,
        "total_critical": total_critical,
        "total_weaponised": total_weaponised,
    }


# ── Tool factory ────────────────────────────────────────────────────────────────

class SBOMCVEContextTool(SecurityTool):
    """Capability 2: SBOM component → CPE → CVEs with ATT&CK hydration."""

    @property
    def tool_name(self) -> str:
        return "sbom_cve_context"

    def cache_key(self, **kwargs) -> str:
        return (
            f"sbom_cve:{kwargs.get('component_name', '')}:"
            f"{kwargs.get('component_version', '')}"
        )

    def execute(
        self,
        component_name: str,
        component_version: str,
        purl: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> ToolResult:
        try:
            data = _execute_sbom_cve_context(
                component_name, component_version, purl, ecosystem
            )
            return ToolResult(
                success=True,
                data=data,
                source="cpe_registry+cve_intelligence",
                timestamp=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            logger.error("SBOMCVEContextTool failed: %s", exc)
            return ToolResult(
                success=False,
                data=None,
                source="cpe_registry+cve_intelligence",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(exc),
            )


def create_sbom_cve_context_tool() -> StructuredTool:
    """Create LangChain tool for SBOM CVE source attribution (Capability 2)."""
    tool_instance = SBOMCVEContextTool()

    def _execute(
        component_name: str,
        component_version: str,
        purl: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_instance.execute(
            component_name, component_version, purl, ecosystem
        ).to_dict()

    return StructuredTool.from_function(
        func=_execute,
        name="sbom_cve_context",
        description=(
            "Given a software component name + version (or purl), resolve it to a canonical "
            "CPE URI, then return all CVEs affecting that component with CVSS, EPSS, exploit "
            "maturity, and ATT&CK technique mappings. Use for SBOM analysis and per-component "
            "CVE attribution."
        ),
        args_schema=SBOMComponentInput,
    )
