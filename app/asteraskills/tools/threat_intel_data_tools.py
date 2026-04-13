"""
Tools for threat_intel_data pipeline outputs: Postgres tables populated by
``ingest_from_files`` / ``cwe_enrich`` and vector collections used when ATT&CK
techniques and attack→control mappings are embedded (same flow as scenario ingest).

No local filesystem reads in agent tools — suitable for containerized services.
Run ``indexing_cli.cwe_capec_attack_vector_ingest --from-db`` (or CI job with
``--from-json``) to populate the CWE→CAPEC→ATT&CK mapping collection.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field
from sqlalchemy import text

from asteraskills.tools.base import ToolResult, SecurityTool
from asteraskills.storage.sqlalchemy_session import get_security_intel_session
from asteraskills.storage.vector_store import get_vector_store_client

logger = logging.getLogger(__name__)


def _normalize_cwe(cwe_id: str) -> str:
    cid = cwe_id.strip()
    if not cid.upper().startswith("CWE-"):
        cid = f"CWE-{cid.replace('CWE-', '').replace('cwe-', '')}"
    return cid


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _attack_collections_from_settings() -> tuple[str, str]:
    from asteraskills.storage.collections import vector_collection

    return (
        vector_collection("attack_techniques"),
        vector_collection("attack_control_mappings"),
    )


async def _semantic_attack_collection_async(
    query: str,
    collection_name: str,
    document_type: str,
    top_k: int,
    score_threshold: float,
    extra_where: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    client = get_vector_store_client()
    try:
        await client.initialize()
    except Exception:
        pass
    where: Dict[str, Any] = {"document_type": document_type}
    if extra_where:
        where.update(extra_where)
    norm = client.normalize_filter(where)
    raw = await client.query(
        collection_name=collection_name,
        query_texts=[query.strip()],
        n_results=max(1, min(50, top_k * 2)),
        where=norm,
    )
    out: List[Dict[str, Any]] = []
    docs = (raw.get("documents") or [[]])[0] or []
    metas = (raw.get("metadatas") or [[]])[0] or []
    dists = (raw.get("distances") or [[]])[0] or []
    ids = (raw.get("ids") or [[]])[0] or []
    for i, content in enumerate(docs):
        meta = dict(metas[i] if i < len(metas) else {})
        score = float(dists[i]) if i < len(dists) and dists[i] is not None else 0.0
        if score < score_threshold:
            continue
        did = ids[i] if i < len(ids) else None
        row = {"id": did, "similarity_score": score, "content_excerpt": (content or "")[:2000], "metadata": meta}
        out.append(row)
        if len(out) >= top_k:
            break
    return out


def _truncate_cve_record(obj: Any, max_str: int = 2000) -> Any:
    if isinstance(obj, dict):
        return {k: _truncate_cve_record(v, max_str) for k, v in list(obj.items())[:80]}
    if isinstance(obj, list):
        return [_truncate_cve_record(x, max_str) for x in obj[:50]]
    if isinstance(obj, str) and len(obj) > max_str:
        return obj[:max_str] + "…"
    return obj


# ---------------------------------------------------------------------------
# nvd_cves_by_cwe (Postgres)
# ---------------------------------------------------------------------------


class NVDCvesByCWEInput(BaseModel):
    cwe_id: str = Field(description="CWE id e.g. CWE-79")
    limit: int = Field(default=25, ge=1, le=200, description="Max CVE rows to return")
    cve_id: Optional[str] = Field(
        default=None,
        description="Optional exact CVE id filter within this CWE",
    )


class NVDCvesByCWETool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "nvd_cves_by_cwe_db"

    def cache_key(self, **kwargs) -> str:
        return f"nvd_cwe:{kwargs.get('cwe_id')}:{kwargs.get('cve_id')}:{kwargs.get('limit')}"

    def execute(
        self,
        cwe_id: str,
        limit: int = 25,
        cve_id: Optional[str] = None,
    ) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        cid = cwe_id.strip()
        if not cid.upper().startswith("CWE-"):
            cid = f"CWE-{cid.replace('CWE-', '').replace('cwe-', '')}"
        try:
            with get_security_intel_session("cve_attack") as session:
                if cve_id and cve_id.strip():
                    rows = session.execute(
                        text(
                            """
                            SELECT cve_id, normalized_data
                            FROM nvd_cves_by_cwe
                            WHERE cwe_id = :cwe AND cve_id = :cve
                            LIMIT 1
                            """
                        ),
                        {"cwe": cid, "cve": cve_id.strip().upper()},
                    ).fetchall()
                else:
                    rows = session.execute(
                        text(
                            """
                            SELECT cve_id, normalized_data
                            FROM nvd_cves_by_cwe
                            WHERE cwe_id = :cwe
                            ORDER BY cve_id
                            LIMIT :lim
                            """
                        ),
                        {"cwe": cid, "lim": limit},
                    ).fetchall()
            items: List[Dict[str, Any]] = []
            for r in rows:
                raw = r[1]
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        pass
                items.append(
                    {
                        "cve_id": r[0],
                        "normalized_data": _truncate_cve_record(raw),
                    }
                )
            return ToolResult(
                success=True,
                data={"cwe_id": cid, "count": len(items), "cves": items},
                source="postgres_nvd_cves_by_cwe",
                timestamp=ts,
            )
        except Exception as e:
            err = str(e).lower()
            if "does not exist" in err or "undefined_table" in err:
                return ToolResult(
                    success=True,
                    data={"cwe_id": cid, "cves": [], "message": "nvd_cves_by_cwe not available"},
                    source="postgres_nvd_cves_by_cwe",
                    timestamp=ts,
                )
            logger.exception("nvd_cves_by_cwe_db failed")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_nvd_cves_by_cwe",
                timestamp=ts,
                error_message=str(e),
            )


def create_nvd_cves_by_cwe_db_tool() -> StructuredTool:
    t = NVDCvesByCWETool()

    def _go(cwe_id: str, limit: int = 25, cve_id: Optional[str] = None) -> Dict[str, Any]:
        return t.execute(cwe_id, limit, cve_id).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="nvd_cves_by_cwe_db",
        description=(
            "List CVEs for a CWE from Postgres ``nvd_cves_by_cwe`` (normalized snapshot from "
            "threat_intel_data / cwe_enrich ingest). Truncates large JSON fields."
        ),
        args_schema=NVDCvesByCWEInput,
    )


# ---------------------------------------------------------------------------
# cisa_kev (Postgres catalog)
# ---------------------------------------------------------------------------


class CISAKEVDBInput(BaseModel):
    cve_id: Optional[str] = Field(default=None, description="Exact CVE id; if omitted, returns recent catalog rows.")
    limit: int = Field(default=30, ge=1, le=500)


class CISAKEVDBTool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "cisa_kev_db"

    def cache_key(self, **kwargs) -> str:
        return f"kev_db:{kwargs.get('cve_id')}:{kwargs.get('limit')}"

    def execute(self, cve_id: Optional[str] = None, limit: int = 30) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        try:
            with get_security_intel_session("cve_attack") as session:
                if cve_id and cve_id.strip():
                    row = session.execute(
                        text(
                            """
                            SELECT cve_id, catalog_date, raw_data
                            FROM cisa_kev
                            WHERE cve_id = :cve
                            """
                        ),
                        {"cve": cve_id.strip().upper()},
                    ).fetchone()
                    if not row:
                        return ToolResult(
                            success=True,
                            data={"cve_id": cve_id.strip().upper(), "in_kev": False, "entry": None},
                            source="postgres_cisa_kev",
                            timestamp=ts,
                        )
                    raw = row[2]
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw)
                        except Exception:
                            pass
                    return ToolResult(
                        success=True,
                        data={
                            "cve_id": row[0],
                            "in_kev": True,
                            "catalog_date": row[1],
                            "entry": _truncate_cve_record(raw),
                        },
                        source="postgres_cisa_kev",
                        timestamp=ts,
                    )
                rows = session.execute(
                    text(
                        """
                        SELECT cve_id, catalog_date, raw_data
                        FROM cisa_kev
                        ORDER BY cve_id
                        LIMIT :lim
                        """
                    ),
                    {"lim": limit},
                ).fetchall()
            entries = []
            for r in rows:
                raw = r[2]
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        pass
                entries.append(
                    {"cve_id": r[0], "catalog_date": r[1], "entry": _truncate_cve_record(raw)}
                )
            return ToolResult(
                success=True,
                data={"count": len(entries), "entries": entries},
                source="postgres_cisa_kev",
                timestamp=ts,
            )
        except Exception as e:
            err = str(e).lower()
            if "does not exist" in err or "undefined_table" in err:
                return ToolResult(
                    success=True,
                    data={"entries": [], "message": "cisa_kev table not available"},
                    source="postgres_cisa_kev",
                    timestamp=ts,
                )
            return ToolResult(
                success=False,
                data=None,
                source="postgres_cisa_kev",
                timestamp=ts,
                error_message=str(e),
            )


def create_cisa_kev_db_tool() -> StructuredTool:
    t = CISAKEVDBTool()

    def _go(cve_id: Optional[str] = None, limit: int = 30) -> Dict[str, Any]:
        return t.execute(cve_id, limit).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="cisa_kev_db",
        description=(
            "Query the CISA KEV catalog from Postgres (ingested from threat_intel_data "
            "cisa_kev.json). Lookup one CVE or list recent rows."
        ),
        args_schema=CISAKEVDBInput,
    )


# ---------------------------------------------------------------------------
# attack_enterprise_techniques (Postgres)
# ---------------------------------------------------------------------------


class AttackEnterpriseTechniqueInput(BaseModel):
    technique_id: str = Field(description="ATT&CK technique id e.g. T1059")


class AttackEnterpriseTechniqueTool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "attack_enterprise_technique_db"

    def cache_key(self, **kwargs) -> str:
        return f"ent_tech:{kwargs.get('technique_id')}"

    def execute(self, technique_id: str) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        tid = technique_id.strip().upper()
        try:
            with get_security_intel_session("cve_attack") as session:
                row = session.execute(
                    text(
                        """
                        SELECT technique_id, name, description, raw_data
                        FROM attack_enterprise_techniques
                        WHERE technique_id = :tid
                        """
                    ),
                    {"tid": tid},
                ).fetchone()
            if not row:
                return ToolResult(
                    success=True,
                    data={"technique_id": tid, "found": False, "message": "Not in attack_enterprise_techniques"},
                    source="postgres_attack_enterprise_techniques",
                    timestamp=ts,
                )
            raw = row[3]
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    pass
            return ToolResult(
                success=True,
                data={
                    "technique_id": row[0],
                    "found": True,
                    "name": row[1],
                    "description": (row[2] or "")[:8000],
                    "raw_data": _truncate_cve_record(raw, max_str=4000),
                },
                source="postgres_attack_enterprise_techniques",
                timestamp=ts,
            )
        except Exception as e:
            err = str(e).lower()
            if "does not exist" in err or "undefined_table" in err:
                return ToolResult(
                    success=True,
                    data={"technique_id": tid, "found": False, "message": str(e)},
                    source="postgres_attack_enterprise_techniques",
                    timestamp=ts,
                )
            return ToolResult(
                success=False,
                data=None,
                source="postgres_attack_enterprise_techniques",
                timestamp=ts,
                error_message=str(e),
            )


def create_attack_enterprise_technique_db_tool() -> StructuredTool:
    t = AttackEnterpriseTechniqueTool()

    def _go(technique_id: str) -> Dict[str, Any]:
        return t.execute(technique_id).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="attack_enterprise_technique_db",
        description=(
            "Fetch one MITRE ATT&CK enterprise technique row from Postgres "
            "``attack_enterprise_techniques`` (from attack_enterprise_techniques.json ingest)."
        ),
        args_schema=AttackEnterpriseTechniqueInput,
    )


# ---------------------------------------------------------------------------
# Semantic search: attack techniques & attack→control mapping vectors
# ---------------------------------------------------------------------------


class SemanticAttackTechniqueInput(BaseModel):
    query: str = Field(description="Natural-language query for ATT&CK technique search")
    top_k: int = Field(default=8, ge=1, le=30)
    score_threshold: float = Field(default=0.28, description="Minimum similarity (Chroma cosine similarity 0–1)")


def create_semantic_attack_technique_search_tool() -> StructuredTool:
    def _go(query: str, top_k: int = 8, score_threshold: float = 0.28) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        coll, _ = _attack_collections_from_settings()
        try:
            hits = _run_async(
                _semantic_attack_collection_async(
                    query,
                    coll,
                    "techniques",
                    top_k,
                    score_threshold,
                )
            )
            return ToolResult(
                success=True,
                data={"collection": coll, "document_type": "techniques", "hits": hits},
                source="vector_attack_techniques",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            logger.exception("semantic_attack_technique_search failed")
            return ToolResult(
                success=False,
                data=None,
                source="vector_attack_techniques",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="semantic_attack_technique_search",
        description=(
            "Semantic search over the ATT&CK techniques vector index "
            "(settings.ATTACK_TECHNIQUES_COLLECTION / attack_techniques). "
            "Uses metadata document_type=techniques."
        ),
        args_schema=SemanticAttackTechniqueInput,
    )


class SemanticAttackControlMappingInput(BaseModel):
    query: str = Field(description="Natural-language query (technique context, scenario, control)")
    framework_id: Optional[str] = Field(
        default=None,
        description="Optional filter e.g. cis_controls_v8_1",
    )
    top_k: int = Field(default=8, ge=1, le=30)
    score_threshold: float = Field(default=0.28, description="Minimum similarity")


def create_semantic_attack_control_mapping_search_tool() -> StructuredTool:
    def _go(
        query: str,
        framework_id: Optional[str] = None,
        top_k: int = 8,
        score_threshold: float = 0.28,
    ) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        _, coll = _attack_collections_from_settings()
        extra = None
        if framework_id and framework_id.strip():
            extra = {"framework_id": framework_id.strip().lower()}
        try:
            hits = _run_async(
                _semantic_attack_collection_async(
                    query,
                    coll,
                    "attack_control_mappings",
                    top_k,
                    score_threshold,
                    extra_where=extra,
                )
            )
            return ToolResult(
                success=True,
                data={
                    "collection": coll,
                    "document_type": "attack_control_mappings",
                    "framework_filter": framework_id,
                    "hits": hits,
                },
                source="vector_attack_control_mappings",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            logger.exception("semantic_attack_control_mapping_search failed")
            return ToolResult(
                success=False,
                data=None,
                source="vector_attack_control_mappings",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="semantic_attack_control_mapping_search",
        description=(
            "Semantic search stored attack→control mapping embeddings "
            "(settings.ATTACK_CONTROL_MAPPINGS_COLLECTION / attack_control_mappings; "
            "scenario ingest / CVE pipeline). Optional framework_id metadata filter."
        ),
        args_schema=SemanticAttackControlMappingInput,
    )


# ---------------------------------------------------------------------------
# Semantic search: CWE→CAPEC→ATT&CK mapping vectors
# ---------------------------------------------------------------------------


class SemanticCWECAPEAttackInput(BaseModel):
    query: str = Field(description="Natural-language query (weakness, technique, tactic, exploit context)")
    top_k: int = Field(default=10, ge=1, le=40)
    cwe_id: Optional[str] = Field(default=None, description="Optional metadata filter: CWE id")
    attack_id: Optional[str] = Field(default=None, description="Optional metadata filter: ATT&CK technique id")
    tactic: Optional[str] = Field(default=None, description="Optional metadata filter: tactic slug")


async def _semantic_cwe_capec_attack_async(
    query: str,
    top_k: int,
    *,
    cwe_id: Optional[str] = None,
    attack_id: Optional[str] = None,
    tactic: Optional[str] = None,
) -> List[Dict[str, Any]]:
    from asteraskills.ingestion.cwe_vector_constants import (
        ENTITY_TYPE,
        cwe_capec_attack_collection_name,
    )

    if not (query or "").strip():
        return []
    coll = cwe_capec_attack_collection_name()
    client = get_vector_store_client()
    try:
        await client.initialize()
    except Exception:
        pass
    where: Dict[str, Any] = {"entity_type": ENTITY_TYPE}
    if cwe_id and cwe_id.strip():
        where["cwe_id"] = _normalize_cwe(cwe_id)
    if attack_id and attack_id.strip():
        where["attack_id"] = attack_id.strip().upper()
    if tactic and tactic.strip():
        where["tactic"] = tactic.strip().lower().replace(" ", "-")
    norm = client.normalize_filter(where)
    raw = await client.query(
        collection_name=coll,
        query_texts=[query.strip()],
        n_results=max(1, min(40, top_k)),
        where=norm,
    )
    out: List[Dict[str, Any]] = []
    docs = (raw.get("documents") or [[]])[0] or []
    metas = (raw.get("metadatas") or [[]])[0] or []
    dists = (raw.get("distances") or [[]])[0] or []
    ids = (raw.get("ids") or [[]])[0] or []
    for i, content in enumerate(docs):
        meta = dict(metas[i] if i < len(metas) else {})
        score = dists[i] if i < len(dists) else None
        did = ids[i] if i < len(ids) else None
        out.append(
            {
                "id": did,
                "collection": coll,
                "similarity_score": float(score) if score is not None else None,
                "content_excerpt": (content or "")[:1500],
                "metadata": meta,
            }
        )
        if len(out) >= top_k:
            break
    return out


def create_semantic_cwe_capec_attack_search_tool() -> StructuredTool:
    def _go(
        query: str,
        top_k: int = 10,
        cwe_id: Optional[str] = None,
        attack_id: Optional[str] = None,
        tactic: Optional[str] = None,
    ) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        try:
            hits = _run_async(
                _semantic_cwe_capec_attack_async(
                    query,
                    top_k,
                    cwe_id=cwe_id,
                    attack_id=attack_id,
                    tactic=tactic,
                )
            )
            return ToolResult(
                success=True,
                data={"hits": hits, "count": len(hits)},
                source="vector_cwe_capec_attack",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            logger.exception("semantic_cwe_capec_attack_search failed")
            return ToolResult(
                success=False,
                data=None,
                source="vector_cwe_capec_attack",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="semantic_cwe_capec_attack_search",
        description=(
            "Semantic search over the CWE→CAPEC→ATT&CK mapping vector collection "
            "(ingest: indexing_cli.cwe_capec_attack_vector_ingest). "
            "Optional metadata filters: cwe_id, attack_id, tactic."
        ),
        args_schema=SemanticCWECAPEAttackInput,
    )


# ---------------------------------------------------------------------------
# cwe_capec_attack_mappings (Postgres; mapper / ingest — no local files)
# ---------------------------------------------------------------------------


class CWECAPEAttackMappingsDBInput(BaseModel):
    cwe_id: Optional[str] = Field(default=None, description="Filter by CWE id e.g. CWE-79")
    attack_id: Optional[str] = Field(
        default=None,
        description="Filter by ATT&CK technique id e.g. T1059 (column attack_id)",
    )
    tactic: Optional[str] = Field(default=None, description="Kill-chain tactic slug e.g. execution")
    limit: int = Field(default=100, ge=1, le=500)


def create_cwe_capec_attack_mappings_db_tool() -> StructuredTool:
    def _go(
        cwe_id: Optional[str] = None,
        attack_id: Optional[str] = None,
        tactic: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        ts = datetime.utcnow().isoformat()
        conds: List[str] = []
        params: Dict[str, Any] = {"lim": min(int(limit), 500)}
        if cwe_id and cwe_id.strip():
            conds.append("cwe_id = :cwe")
            params["cwe"] = _normalize_cwe(cwe_id)
        if attack_id and attack_id.strip():
            conds.append("attack_id = :aid")
            params["aid"] = attack_id.strip().upper()
        if tactic and tactic.strip():
            conds.append("tactic = :tactic")
            params["tactic"] = tactic.strip().lower().replace(" ", "-")
        where_sql = " AND ".join(conds) if conds else "TRUE"
        try:
            with get_security_intel_session("cve_attack") as session:
                rows = session.execute(
                    text(
                        f"""
                        SELECT cwe_id, capec_id, attack_id, tactic, mapping_basis,
                               confidence, example_cves
                        FROM cwe_capec_attack_mappings
                        WHERE {where_sql}
                        ORDER BY cwe_id, attack_id, tactic
                        LIMIT :lim
                        """
                    ),
                    params,
                ).fetchall()
            mappings: List[Dict[str, Any]] = []
            for r in rows:
                ex = r[6]
                if isinstance(ex, str):
                    try:
                        ex = json.loads(ex)
                    except Exception:
                        pass
                mappings.append(
                    {
                        "cwe_id": r[0],
                        "capec_id": r[1],
                        "attack_id": r[2],
                        "tactic": r[3],
                        "mapping_basis": r[4],
                        "confidence": r[5],
                        "example_cves": ex if isinstance(ex, list) else ex,
                    }
                )
            return ToolResult(
                success=True,
                data={"count": len(mappings), "mappings": mappings},
                source="postgres_cwe_capec_attack_mappings",
                timestamp=ts,
            ).to_dict()
        except Exception as e:
            err = str(e).lower()
            if "does not exist" in err or "undefined_table" in err:
                return ToolResult(
                    success=True,
                    data={"count": 0, "mappings": [], "message": str(e)},
                    source="postgres_cwe_capec_attack_mappings",
                    timestamp=ts,
                ).to_dict()
            logger.exception("cwe_capec_attack_mappings_db failed")
            return ToolResult(
                success=False,
                data=None,
                source="postgres_cwe_capec_attack_mappings",
                timestamp=ts,
                error_message=str(e),
            ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="cwe_capec_attack_mappings_db",
        description=(
            "Query Postgres ``cwe_capec_attack_mappings`` (CWE/CAPEC→ATT&CK rows from mapper ingest). "
            "Optional filters: cwe_id, attack_id, tactic. No filesystem."
        ),
        args_schema=CWECAPEAttackMappingsDBInput,
    )
