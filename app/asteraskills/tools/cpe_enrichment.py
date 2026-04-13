"""
CPEEnrichmentTool — Stage 1.5 of CVE → ATT&CK → Control pipeline.

Resolves ``affected_products`` strings from Stage 1 (CVEDetail) to canonical
CPE URIs with exact vendor / product / version-range data from the CPE
dictionary, then persists the matches in ``cve_cpe_links``.

**Resolution strategy (two-pass):**
  Pass 1 — URI exact match against ``cpe_names`` Postgres table.
  Pass 2 — Vector search fallback (Qdrant ``cpe_names`` collection, cosine).

No external HTTP is required; all reads come from the local CPE registry.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import SecurityTool, ToolResult

logger = logging.getLogger(__name__)

# ── Thresholds ──────────────────────────────────────────────────────────────────
VECTOR_SCORE_THRESHOLD = 0.82
VECTOR_TOP_K = 5


# ── Pydantic schemas ────────────────────────────────────────────────────────────

class CPEMatchResult(BaseModel):
    cpe_uri: str
    vendor: str = ""
    product: str = ""
    version_start_incl: Optional[str] = None
    version_end_excl: Optional[str] = None
    version_end_incl: Optional[str] = None
    match_criteria_id: Optional[str] = None
    is_vulnerable: bool = True
    resolution_method: str = "uri_exact"  # "uri_exact" | "vector_match"
    resolution_score: Optional[float] = None


class CPEEnrichmentInput(BaseModel):
    cve_id: str = Field(description="CVE identifier (e.g. CVE-2024-3400)")
    affected_products: List[str] = Field(
        description="List of affected product strings from CVEDetail.affected_products"
    )


class CPEEnrichmentOutput(BaseModel):
    cve_id: str
    cpe_matches: List[CPEMatchResult]
    resolution_method: str  # "uri_exact" | "vector_match" | "empty"


# ── Internal helpers ────────────────────────────────────────────────────────────

def _is_cpe_uri(s: str) -> bool:
    return s.startswith("cpe:") and s.count(":") >= 4


def _exact_match(product_str: str, session: Any) -> Optional[CPEMatchResult]:
    """Pass 1 — direct Postgres lookup on cpe_names."""
    try:
        from sqlalchemy import text

        row = session.execute(
            text("""
                SELECT cpe_name, vendor, product, version, title
                FROM cpe_names
                WHERE cpe_name = :uri
                LIMIT 1
            """),
            {"uri": product_str},
        ).fetchone()
        if row:
            return CPEMatchResult(
                cpe_uri=row[0],
                vendor=row[1] or "",
                product=row[2] or "",
                resolution_method="uri_exact",
            )
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cpe_names exact lookup failed: %s", exc)
    return None


def _vector_match(product_str: str) -> Optional[CPEMatchResult]:
    """Pass 2 — embed + Qdrant cosine search on cpe_names collection."""
    try:
        from asteraskills.storage.vector_store import get_vector_store_client

        client = get_vector_store_client()
        hits = client.similarity_search_with_score(
            query=product_str,
            collection_name="cpe_names",
            top_k=VECTOR_TOP_K,
        )
        for doc, score in hits:
            if score >= VECTOR_SCORE_THRESHOLD:
                payload = doc.metadata if hasattr(doc, "metadata") else {}
                return CPEMatchResult(
                    cpe_uri=payload.get("cpe_name", doc.page_content),
                    vendor=payload.get("vendor", ""),
                    product=payload.get("product", ""),
                    resolution_method="vector_match",
                    resolution_score=float(score),
                )
    except Exception as exc:
        logger.debug("cpe_names vector search failed: %s", exc)
    return None


def _load_version_ranges(
    cpe_uri: str, session: Any
) -> List[Dict[str, Any]]:
    """Fetch version range rows from cpe_match_criteria via cpe_nodes."""
    try:
        from sqlalchemy import text

        rows = session.execute(
            text("""
                SELECT
                    cm.match_criteria_id::text,
                    cm.version_start_including,
                    cm.version_end_excluding,
                    cm.version_end_including,
                    cm.vulnerable
                FROM cpe_match_criteria cm
                JOIN cpe_nodes cn ON cn.match_criteria_id = cm.match_criteria_id
                WHERE cn.cpe_name = :cpe_uri
                LIMIT 20
            """),
            {"cpe_uri": cpe_uri},
        ).fetchall()
        return [
            {
                "match_criteria_id": r[0],
                "version_start_incl": r[1],
                "version_end_excl": r[2],
                "version_end_incl": r[3],
                "is_vulnerable": bool(r[4]),
            }
            for r in rows
        ]
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cpe_match_criteria lookup failed for %s: %s", cpe_uri, exc)
        return []


def _upsert_cve_cpe_links(cve_id: str, matches: List[CPEMatchResult]) -> None:
    """Persist resolved CPE matches into cve_cpe_links (upsert)."""
    if not matches:
        return
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            for m in matches:
                session.execute(
                    text("""
                        INSERT INTO cve_cpe_links (
                            cve_id, cpe_uri, match_criteria_id,
                            vendor, product,
                            version_start_incl, version_end_excl, version_end_incl,
                            is_vulnerable, resolution_method, resolution_score,
                            created_at, updated_at
                        ) VALUES (
                            :cve_id, :cpe_uri, :match_criteria_id,
                            :vendor, :product,
                            :version_start_incl, :version_end_excl, :version_end_incl,
                            :is_vulnerable, :resolution_method, :resolution_score,
                            NOW(), NOW()
                        )
                        ON CONFLICT (cve_id, cpe_uri, COALESCE(match_criteria_id::text, 'null'))
                        DO UPDATE SET
                            vendor = EXCLUDED.vendor,
                            product = EXCLUDED.product,
                            version_start_incl = EXCLUDED.version_start_incl,
                            version_end_excl = EXCLUDED.version_end_excl,
                            version_end_incl = EXCLUDED.version_end_incl,
                            is_vulnerable = EXCLUDED.is_vulnerable,
                            resolution_method = EXCLUDED.resolution_method,
                            resolution_score = EXCLUDED.resolution_score,
                            updated_at = NOW()
                    """),
                    {
                        "cve_id": cve_id,
                        "cpe_uri": m.cpe_uri,
                        "match_criteria_id": m.match_criteria_id,
                        "vendor": m.vendor,
                        "product": m.product,
                        "version_start_incl": m.version_start_incl,
                        "version_end_excl": m.version_end_excl,
                        "version_end_incl": m.version_end_incl,
                        "is_vulnerable": m.is_vulnerable,
                        "resolution_method": m.resolution_method,
                        "resolution_score": m.resolution_score,
                    },
                )
    except Exception as exc:
        if "does not exist" not in str(exc).lower():
            logger.debug("cve_cpe_links upsert failed: %s", exc)


# ── Core execution ──────────────────────────────────────────────────────────────

def _execute_cpe_enrich(
    cve_id: str,
    affected_products: List[str],
) -> Dict[str, Any]:
    """
    Resolve affected_products to canonical CPE matches.

    Returns a dict compatible with CPEEnrichmentOutput.
    """
    cve_id = cve_id.strip().upper()
    if not affected_products:
        return {
            "cve_id": cve_id,
            "cpe_matches": [],
            "resolution_method": "empty",
        }

    matches: List[CPEMatchResult] = []
    any_vector = False

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session

        with get_security_intel_session("cve_attack") as session:
            for product_str in affected_products:
                if not product_str:
                    continue
                match: Optional[CPEMatchResult] = None

                # Pass 1: exact URI match (only for CPE-formatted strings)
                if _is_cpe_uri(product_str):
                    match = _exact_match(product_str, session)

                # Pass 2: vector search fallback
                if match is None:
                    match = _vector_match(product_str)
                    if match:
                        any_vector = True

                if match is None:
                    continue

                # Hydrate version ranges from cpe_match_criteria
                ranges = _load_version_ranges(match.cpe_uri, session)
                if ranges:
                    for r in ranges:
                        enriched = match.model_copy(
                            update={
                                "match_criteria_id": r["match_criteria_id"],
                                "version_start_incl": r["version_start_incl"],
                                "version_end_excl": r["version_end_excl"],
                                "version_end_incl": r["version_end_incl"],
                                "is_vulnerable": r["is_vulnerable"],
                            }
                        )
                        matches.append(enriched)
                else:
                    matches.append(match)

    except Exception as exc:
        logger.warning("CPE enrichment DB session failed: %s", exc)

    # Deduplicate on (cpe_uri, match_criteria_id)
    seen: set[tuple[str, Optional[str]]] = set()
    deduped: List[CPEMatchResult] = []
    for m in matches:
        key = (m.cpe_uri, m.match_criteria_id)
        if key not in seen:
            seen.add(key)
            deduped.append(m)

    _upsert_cve_cpe_links(cve_id, deduped)

    method = "empty"
    if deduped:
        method = "vector_match" if any_vector else "uri_exact"

    return {
        "cve_id": cve_id,
        "cpe_matches": [m.model_dump() for m in deduped],
        "resolution_method": method,
    }


# ── Tool factory ────────────────────────────────────────────────────────────────

class CPEEnrichmentTool(SecurityTool):
    """Stage 1.5: resolve CVE affected_products to canonical CPE URIs."""

    @property
    def tool_name(self) -> str:
        return "cpe_enrich"

    def cache_key(self, **kwargs) -> str:
        return f"cpe_enrich:{kwargs.get('cve_id', '')}"

    def execute(self, cve_id: str, affected_products: List[str]) -> ToolResult:
        try:
            data = _execute_cpe_enrich(cve_id, affected_products)
            return ToolResult(
                success=True,
                data=data,
                source="cpe_registry",
                timestamp=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            logger.error("CPEEnrichmentTool failed: %s", exc)
            return ToolResult(
                success=False,
                data=None,
                source="cpe_registry",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(exc),
            )


def create_cpe_enrichment_tool() -> StructuredTool:
    """Create LangChain tool for CPE enrichment (Stage 1.5 of pipeline)."""
    tool_instance = CPEEnrichmentTool()

    def _execute(cve_id: str, affected_products: List[str]) -> Dict[str, Any]:
        return tool_instance.execute(cve_id, affected_products).to_dict()

    return StructuredTool.from_function(
        func=_execute,
        name="cpe_enrich",
        description=(
            "Stage 1.5: resolve a CVE's affected_products to canonical CPE URIs with "
            "vendor, product, and version-range data from the local CPE dictionary. "
            "Pass the cve_id and affected_products list from cve_enrich output. "
            "No external HTTP required — reads from local CPE registry (Postgres + Qdrant)."
        ),
        args_schema=CPEEnrichmentInput,
    )
