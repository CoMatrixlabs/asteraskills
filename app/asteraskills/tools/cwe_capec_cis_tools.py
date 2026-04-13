"""
CWE, CAPEC, CIS Controls lookup tools (Postgres + vector store) and
LLM-assisted risk synthesis for attack→control mappings already stored in DB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from sqlalchemy import text

from asteraskills.tools.base import ToolResult, SecurityTool
from asteraskills.storage.collections import FrameworkCollections, ThreatIntelCollections
from asteraskills.storage.sqlalchemy_session import get_security_intel_session
from asteraskills.storage.vector_store import get_vector_store_client

logger = logging.getLogger(__name__)

DEFAULT_CIS_FRAMEWORK_ID = "cis_controls_v8_1"


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _extract_json_block(text: str) -> Any:
    text = (text or "").strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if m:
            text = m.group(1).strip()
    return json.loads(text)


# ---------------------------------------------------------------------------
# Vector: CWE / CAPEC semantic search
# ---------------------------------------------------------------------------


async def _semantic_threat_intel(
    query: str,
    *,
    entity_type: str,
    top_k: int,
) -> List[Dict[str, Any]]:
    if not (query or "").strip():
        return []
    client = get_vector_store_client()
    try:
        await client.initialize()
    except Exception:
        pass
    where = client.normalize_filter({"entity_type": entity_type})
    raw = await client.query(
        collection_name=ThreatIntelCollections.cwe_capec(),
        query_texts=[query.strip()],
        n_results=max(1, min(50, top_k)),
        where=where,
    )
    out: List[Dict[str, Any]] = []
    docs = (raw.get("documents") or [[]])[0] or []
    metas = (raw.get("metadatas") or [[]])[0] or []
    dists = (raw.get("distances") or [[]])[0] or []
    ids = (raw.get("ids") or [[]])[0] or []
    for i, content in enumerate(docs):
        meta = metas[i] if i < len(metas) else {}
        score = dists[i] if i < len(dists) else None
        did = ids[i] if i < len(ids) else None
        out.append({
            "id": did,
            "entity_id": (meta or {}).get("id", ""),
            "name": (meta or {}).get("name", ""),
            "content_excerpt": (content or "")[:1200],
            "similarity_score": score,
            "metadata": meta or {},
        })
    return out


# ---------------------------------------------------------------------------
# CWE lookup
# ---------------------------------------------------------------------------


class CWELookupInput(BaseModel):
    cwe_id: Optional[str] = Field(
        default=None,
        description="Exact CWE id, e.g. CWE-79. When set, loads from Postgres.",
    )
    semantic_query: Optional[str] = Field(
        default=None,
        description="Natural-language query for semantic search in the CWE/CAPEC vector collection (CWE entries only).",
    )
    top_k: int = Field(default=8, ge=1, le=30, description="Vector hits when semantic_query is used.")
    include_capec_links: bool = Field(
        default=True,
        description="When resolving by cwe_id, include linked CAPEC ids from cwe_to_capec.",
    )


class CWELookupTool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "cwe_lookup"

    def cache_key(self, **kwargs) -> str:
        return f"cwe:{kwargs.get('cwe_id')}:{kwargs.get('semantic_query')}"

    def execute(
        self,
        cwe_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
        top_k: int = 8,
        include_capec_links: bool = True,
    ) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        try:
            data: Dict[str, Any] = {"cwe_id": cwe_id, "semantic_hits": [], "postgres": None}
            if cwe_id:
                cid = cwe_id.strip()
                if not cid.upper().startswith("CWE-"):
                    cid = f"CWE-{cid.replace('CWE-', '').replace('cwe-', '')}"
                with get_security_intel_session("cve_attack") as session:
                    row = session.execute(
                        text(
                            "SELECT cwe_id, name, description, raw_data FROM cwe_entries WHERE cwe_id = :id"
                        ),
                        {"id": cid},
                    ).fetchone()
                    if row:
                        data["postgres"] = {
                            "cwe_id": row[0],
                            "name": row[1],
                            "description": (row[2] or "")[:8000],
                        }
                    capec_ids: List[str] = []
                    if include_capec_links:
                        for r in session.execute(
                            text("SELECT capec_id FROM cwe_to_capec WHERE cwe_id = :id ORDER BY capec_id"),
                            {"id": cid},
                        ).fetchall():
                            if r[0]:
                                capec_ids.append(str(r[0]))
                    data["linked_capec_ids"] = capec_ids

            if semantic_query and semantic_query.strip():
                hits = _run_async(
                    _semantic_threat_intel(semantic_query.strip(), entity_type="cwe", top_k=top_k)
                )
                data["semantic_hits"] = hits

            if not data.get("postgres") and not data.get("semantic_hits"):
                return ToolResult(
                    success=True,
                    data={**data, "message": "No CWE row for id and no semantic hits (check vector ingest)."},
                    source="cwe_lookup",
                    timestamp=ts,
                )
            return ToolResult(success=True, data=data, source="cwe_lookup", timestamp=ts)
        except Exception as e:
            logger.exception("cwe_lookup failed")
            return ToolResult(
                success=False,
                data=None,
                source="cwe_lookup",
                timestamp=ts,
                error_message=str(e),
            )


def create_cwe_lookup_tool() -> StructuredTool:
    t = CWELookupTool()

    def _go(
        cwe_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
        top_k: int = 8,
        include_capec_links: bool = True,
    ) -> Dict[str, Any]:
        return t.execute(
            cwe_id=cwe_id,
            semantic_query=semantic_query,
            top_k=top_k,
            include_capec_links=include_capec_links,
        ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="cwe_lookup",
        description=(
            "Look up CWE weakness: by exact CWE id from Postgres (name, description, linked CAPEC ids) "
            "and/or semantic search over ingested CWE vectors (threat_intel_cwe_capec collection)."
        ),
        args_schema=CWELookupInput,
    )


# ---------------------------------------------------------------------------
# CAPEC lookup
# ---------------------------------------------------------------------------


class CAPECLookupInput(BaseModel):
    capec_id: Optional[str] = Field(default=None, description="Exact CAPEC id, e.g. CAPEC-66.")
    semantic_query: Optional[str] = Field(
        default=None,
        description="Natural-language query; searches CAPEC vectors only.",
    )
    top_k: int = Field(default=8, ge=1, le=30)


class CAPECLookupTool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "capec_lookup"

    def cache_key(self, **kwargs) -> str:
        return f"capec:{kwargs.get('capec_id')}:{kwargs.get('semantic_query')}"

    def execute(
        self,
        capec_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
        top_k: int = 8,
    ) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        try:
            data: Dict[str, Any] = {"capec_id": capec_id, "semantic_hits": [], "postgres": None}
            if capec_id:
                pid = capec_id.strip()
                if not pid.upper().startswith("CAPEC-"):
                    pid = f"CAPEC-{pid.replace('CAPEC-', '').replace('capec-', '')}"
                with get_security_intel_session("cve_attack") as session:
                    row = session.execute(
                        text(
                            "SELECT capec_id, name, description, related_cwes, raw_data FROM capec WHERE capec_id = :id"
                        ),
                        {"id": pid},
                    ).fetchone()
                    if row:
                        data["postgres"] = {
                            "capec_id": row[0],
                            "name": row[1],
                            "description": (row[2] or "")[:8000],
                            "related_cwes": row[3],
                        }
            if semantic_query and semantic_query.strip():
                data["semantic_hits"] = _run_async(
                    _semantic_threat_intel(semantic_query.strip(), entity_type="capec", top_k=top_k)
                )
            if not data.get("postgres") and not data.get("semantic_hits"):
                return ToolResult(
                    success=True,
                    data={**data, "message": "No CAPEC row for id and no semantic hits."},
                    source="capec_lookup",
                    timestamp=ts,
                )
            return ToolResult(success=True, data=data, source="capec_lookup", timestamp=ts)
        except Exception as e:
            logger.exception("capec_lookup failed")
            return ToolResult(
                success=False,
                data=None,
                source="capec_lookup",
                timestamp=ts,
                error_message=str(e),
            )


def create_capec_lookup_tool() -> StructuredTool:
    t = CAPECLookupTool()

    def _go(
        capec_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
        top_k: int = 8,
    ) -> Dict[str, Any]:
        return t.execute(capec_id=capec_id, semantic_query=semantic_query, top_k=top_k).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="capec_lookup",
        description=(
            "Look up MITRE CAPEC pattern: Postgres by id (name, description, related CWEs) "
            "and/or semantic search on ingested CAPEC vectors."
        ),
        args_schema=CAPECLookupInput,
    )


# ---------------------------------------------------------------------------
# CIS Controls v8.1 — semantic search on framework items (vector)
# ---------------------------------------------------------------------------


class CISControlsSearchInput(BaseModel):
    query: str = Field(description="Natural-language query (risk lens, scenario, or control text).")
    tactic: Optional[str] = Field(
        default=None,
        description="Optional kill-chain tactic slug to pre-filter (e.g. persistence). Uses framework item tactic_domains.",
    )
    top_k: int = Field(default=8, ge=1, le=30)
    score_threshold: float = Field(default=0.30, description="Minimum similarity score.")


async def _cis_framework_search_async(
    query: str,
    tactic: Optional[str],
    top_k: int,
    score_threshold: float,
) -> List[Dict[str, Any]]:
    from asteraskills.tools.framework_item_retrieval import _format_result

    client = get_vector_store_client()
    try:
        await client.initialize()
    except Exception:
        pass
    where: Dict[str, Any] = {"framework_id": DEFAULT_CIS_FRAMEWORK_ID}
    if tactic and tactic.strip():
        where["tactic_domains__contains"] = tactic.strip().lower().replace(" ", "-")
    norm = client.normalize_filter(where)
    raw = await client.query(
        collection_name=FrameworkCollections.items(),
        query_texts=[query.strip()],
        n_results=max(1, top_k * 2),
        where=norm,
    )
    docs = (raw.get("documents") or [[]])[0] or []
    metas = (raw.get("metadatas") or [[]])[0] or []
    dists = (raw.get("distances") or [[]])[0] or []
    ids = (raw.get("ids") or [[]])[0] or []
    out: List[Dict[str, Any]] = []
    for i, content in enumerate(docs):
        meta = metas[i] if i < len(metas) else {}
        score = float(dists[i]) if i < len(dists) and dists[i] is not None else 0.0
        if score < score_threshold:
            continue
        iid = (meta or {}).get("item_id") or (ids[i] if i < len(ids) else "")
        out.append(
            _format_result(
                str(iid),
                DEFAULT_CIS_FRAMEWORK_ID,
                meta or {},
                content or "",
                score,
            )
        )
        if len(out) >= top_k:
            break
    return out


def create_cis_controls_search_tool() -> StructuredTool:
    def _go(
        query: str,
        tactic: Optional[str] = None,
        top_k: int = 8,
        score_threshold: float = 0.30,
    ) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        try:
            hits = _run_async(
                _cis_framework_search_async(query, tactic, top_k, score_threshold)
            )
            return ToolResult(
                success=True,
                data={"framework_id": DEFAULT_CIS_FRAMEWORK_ID, "items": hits, "count": len(hits)},
                source="cis_controls_vector",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            logger.exception("cis_controls_search failed")
            return ToolResult(
                success=False,
                data=None,
                source="cis_controls_vector",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="cis_controls_search",
        description=(
            "Semantic search CIS Controls v8.1 framework items (vector index: framework_items, "
            "framework_id=cis_controls_v8_1). Optional tactic slug filters tactic_domains."
        ),
        args_schema=CISControlsSearchInput,
    )


# ---------------------------------------------------------------------------
# CWE → ATT&CK rows from DB (cwe_technique_mappings / cwe_capec_attack_mappings)
# ---------------------------------------------------------------------------


class CWEToAttackIntelInput(BaseModel):
    cwe_id: str = Field(description="CWE id e.g. CWE-79")


def create_cwe_to_attack_intel_tool() -> StructuredTool:
    def _go(cwe_id: str) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        cid = cwe_id.strip()
        if not cid.upper().startswith("CWE-"):
            cid = f"CWE-{cid.replace('CWE-', '').replace('cwe-', '')}"
        try:
            with get_security_intel_session("cve_attack") as session:
                tech_rows = session.execute(
                    text(
                        """
                        SELECT technique_id, tactic, confidence, mapping_source
                        FROM cwe_technique_mappings
                        WHERE cwe_id = :c
                        ORDER BY technique_id, tactic
                        """
                    ),
                    {"c": cid},
                ).fetchall()
                triple_rows = session.execute(
                    text(
                        """
                        SELECT capec_id, attack_id, tactic, mapping_basis, confidence, example_cves
                        FROM cwe_capec_attack_mappings
                        WHERE cwe_id = :c
                        ORDER BY attack_id, tactic
                        """
                    ),
                    {"c": cid},
                ).fetchall()
            return ToolResult(
                success=True,
                data={
                    "cwe_id": cid,
                    "technique_mappings": [
                        {
                            "technique_id": r[0],
                            "tactic": r[1],
                            "confidence": r[2],
                            "mapping_source": r[3],
                        }
                        for r in tech_rows
                    ],
                    "cwe_capec_attack_mappings": [
                        {
                            "capec_id": r[0],
                            "attack_id": r[1],
                            "tactic": r[2],
                            "mapping_basis": r[3],
                            "confidence": r[4],
                            "example_cves": r[5],
                        }
                        for r in triple_rows
                    ],
                },
                source="postgres_cwe_attack_intel",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            err = str(e).lower()
            if "does not exist" in err or "undefined_table" in err:
                return ToolResult(
                    success=True,
                    data={"cwe_id": cid, "technique_mappings": [], "cwe_capec_attack_mappings": [], "message": str(e)},
                    source="postgres_cwe_attack_intel",
                    timestamp=ts,
                ).to_dict()
            return ToolResult(
                success=False,
                data=None,
                source="postgres_cwe_attack_intel",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="cwe_to_attack_intel",
        description=(
            "Return CWE→ATT&CK mappings persisted by the CWE/CAPEC mapper: cwe_technique_mappings "
            "and cwe_capec_attack_mappings (basis, confidence, example CVEs)."
        ),
        args_schema=CWEToAttackIntelInput,
    )


# ---------------------------------------------------------------------------
# Stored attack → control + LLM risk synthesis
# ---------------------------------------------------------------------------


class AttackStoredControlRiskInput(BaseModel):
    technique_id: str = Field(description="ATT&CK technique id e.g. T1059")
    tactic: str = Field(description="Kill-chain tactic slug e.g. execution")
    framework_id: Optional[str] = Field(
        default=None,
        description="Filter to one framework_id (e.g. cis_controls_v8_1). Omit for all.",
    )
    max_mappings: int = Field(default=20, ge=1, le=50, description="Cap rows sent to the LLM.")


_ATTACK_CONTROL_RISK_SYSTEM = """You are a senior security architect. You synthesize risk across:
(1) the ATT&CK technique in context,
(2) each mapped control or scenario item,
(3) loss outcomes and tactic risk already associated with the mapping.

Return ONLY valid JSON (no markdown) with this shape:
{
  "attack_summary": "one short paragraph",
  "overall_exposure": "critical|high|medium|low",
  "items": [
    {
      "item_id": "string",
      "framework_id": "string",
      "composite_risk": "critical|high|medium|low",
      "attack_risk_notes": "string",
      "scenario_loss_notes": "string",
      "control_effectiveness_notes": "string",
      "priority_rank": 1
    }
  ]
}

Rank items by composite_risk (1 = highest priority). Use mapping fields honestly; do not invent controls not in the input."""


def _fetch_stored_mappings(
    technique_id: str,
    tactic_slug: str,
    framework_id: Optional[str],
    max_mappings: int,
) -> List[Dict[str, Any]]:
    tid = technique_id.strip().upper()
    tactic = tactic_slug.strip().lower().replace(" ", "-")
    rows_out: List[Dict[str, Any]] = []
    with get_security_intel_session("cve_attack") as session:
        if framework_id and framework_id.strip():
            q = text(
                """
                SELECT item_id, framework_id, relevance_score, confidence, rationale,
                       tactic_risk_lens, blast_radius, loss_outcomes
                FROM attack_control_mappings_multi
                WHERE technique_id = :tid AND tactic = :tactic AND framework_id = :fid
                ORDER BY relevance_score DESC NULLS LAST
                LIMIT :lim
                """
            )
            params = {"tid": tid, "tactic": tactic, "fid": framework_id.strip().lower(), "lim": max_mappings}
        else:
            q = text(
                """
                SELECT item_id, framework_id, relevance_score, confidence, rationale,
                       tactic_risk_lens, blast_radius, loss_outcomes
                FROM attack_control_mappings_multi
                WHERE technique_id = :tid AND tactic = :tactic
                ORDER BY relevance_score DESC NULLS LAST
                LIMIT :lim
                """
            )
            params = {"tid": tid, "tactic": tactic, "lim": max_mappings}
        try:
            for r in session.execute(q, params).fetchall():
                rows_out.append(
                    {
                        "item_id": r[0],
                        "framework_id": r[1],
                        "relevance_score": float(r[2]) if r[2] is not None else None,
                        "confidence": r[3],
                        "rationale": r[4],
                        "tactic_risk_lens": r[5],
                        "blast_radius": r[6],
                        "loss_outcomes": r[7] if isinstance(r[7], list) else (r[7] or []),
                    }
                )
        except Exception as e:
            logger.debug("attack_control_mappings_multi query: %s", e)

        if rows_out:
            return rows_out

        # Fallback: phase-1 attack_technique_control_mapping + controls
        try:
            fq = text(
                """
                SELECT c.id, fr.id, c.name, c.description,
                       atcm.mitigation_effectiveness, atcm.confidence_score, atcm.notes
                FROM attack_technique_control_mapping atcm
                JOIN controls c ON atcm.control_id = c.id
                JOIN frameworks fr ON c.framework_id = fr.id
                WHERE atcm.attack_technique_id = :tid
                ORDER BY atcm.confidence_score DESC NULLS LAST
                LIMIT :lim
                """
            )
            for r in session.execute(fq, {"tid": tid, "lim": max_mappings}).fetchall():
                rows_out.append(
                    {
                        "item_id": r[0],
                        "framework_id": r[1],
                        "relevance_score": float(r[5]) if r[5] is not None else None,
                        "confidence": str(r[5]) if r[5] is not None else "medium",
                        "rationale": (r[6] or "")[:2000],
                        "tactic_risk_lens": f"tactic context: {tactic}",
                        "blast_radius": "",
                        "loss_outcomes": [],
                        "control_name": r[2],
                        "control_description": (r[3] or "")[:1500],
                        "mitigation_effectiveness": r[4],
                    }
                )
        except Exception as e:
            logger.debug("attack_technique_control_mapping fallback: %s", e)
    return rows_out


def _execute_attack_stored_control_risk(
    technique_id: str,
    tactic: str,
    framework_id: Optional[str] = None,
    max_mappings: int = 20,
) -> Dict[str, Any]:
    from asteraskills.tools.attack_tools import ATTACKEnrichmentTool
    from asteraskills.core.llm import get_llm
    from asteraskills.config.settings import get_settings

    ts = datetime.utcnow().isoformat()
    tactic_slug = tactic.strip().lower().replace(" ", "-")
    mappings = _fetch_stored_mappings(technique_id, tactic_slug, framework_id, max_mappings)
    if not mappings:
        return ToolResult(
            success=True,
            data={
                "technique_id": technique_id.strip().upper(),
                "tactic": tactic_slug,
                "message": "No stored attack→control mappings for this pair (run scenario ingest or CVE mapping pipeline).",
                "llm": None,
                "stored_mappings": [],
            },
            source="attack_stored_control_risk",
            timestamp=ts,
        ).to_dict()

    settings = get_settings()
    pg_dsn = settings.get_attack_db_dsn() if hasattr(settings, "get_attack_db_dsn") else None
    enricher = ATTACKEnrichmentTool(use_postgres=bool(pg_dsn), pg_dsn=pg_dsn)
    try:
        tech = enricher.get_technique(technique_id.strip().upper())
        attack_blob = {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "description": (tech.description or "")[:1200],
            "tactics": list(tech.tactics or []),
            "platforms": list(tech.platforms or []),
        }
    except Exception:
        attack_blob = {"technique_id": technique_id.strip().upper(), "name": technique_id, "description": ""}

    payload = {"attack": attack_blob, "tactic": tactic_slug, "mappings": mappings}
    user = (
        "Synthesize risk from the following JSON. Consider residual risk if controls are weak or loss outcomes severe.\n\n"
        + json.dumps(payload, indent=2)[:28000]
    )
    content = ""
    try:
        llm = get_llm(temperature=0.2)
        resp = llm.invoke(
            [SystemMessage(content=_ATTACK_CONTROL_RISK_SYSTEM), HumanMessage(content=user)]
        )
        content = resp.content if hasattr(resp, "content") else str(resp)
        parsed = _extract_json_block(content)
    except json.JSONDecodeError as e:
        logger.warning("LLM risk synthesis JSON parse failed: %s", e)
        parsed = {"raw_text": (content or "")[:4000], "parse_error": str(e)}
    except Exception as e:
        logger.exception("attack_stored_control_risk LLM failed")
        return ToolResult(
            success=False,
            data={"stored_mappings": mappings, "attack": attack_blob},
            source="attack_stored_control_risk",
            timestamp=ts,
            error_message=str(e),
        ).to_dict()

    return ToolResult(
        success=True,
        data={
            "technique_id": attack_blob.get("technique_id"),
            "tactic": tactic_slug,
            "stored_mappings": mappings,
            "llm_synthesis": parsed,
        },
        source="attack_stored_control_risk",
        timestamp=ts,
    ).to_dict()


def create_attack_stored_control_risk_tool() -> StructuredTool:
    return StructuredTool.from_function(
        func=_execute_attack_stored_control_risk,
        name="attack_stored_control_risk",
        description=(
            "Load attack→control mappings already stored in Postgres (attack_control_mappings_multi, "
            "or fallback attack_technique_control_mapping), then use an LLM to synthesize composite risk "
            "across the attack, scenario loss signals, and each control. Pass tactic as kill-chain slug."
        ),
        args_schema=AttackStoredControlRiskInput,
    )
