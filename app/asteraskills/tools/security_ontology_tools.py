"""
Read-only semantic search over the ``security_ontology`` Qdrant collection.

Ingest writes: ``python -m app.ingestion.security_ontology_ingest`` (complianceskill repo).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.storage.collections import OntologyCollections
from asteraskills.storage.vector_store import get_vector_store_client

log = logging.getLogger(__name__)


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


class SecurityOntologySearchInput(BaseModel):
    query: str = Field(
        description=(
            "Natural language or keywords: node type (e.g. kubernetes pod), edge type "
            "(e.g. runs_in), or enum value (e.g. network_exposure public_internet)."
        ),
    )
    kind: Optional[str] = Field(
        default=None,
        description="Optional filter: node_type | edge_type | enum_member",
    )
    top_k: int = Field(default=8, ge=1, le=25)


def _security_ontology_search(
    query: str,
    kind: Optional[str] = None,
    top_k: int = 8,
) -> str:
    async def _go():
        client = get_vector_store_client()
        try:
            await client.initialize()
        except Exception:
            pass
        where = None
        if kind:
            where = client.normalize_filter({"kind": kind})
        return await client.query(
            collection_name=OntologyCollections.security_ontology(),
            query_texts=[query],
            n_results=top_k,
            where=where,
        )

    try:
        result = _run_async(_go())
    except Exception as exc:
        log.exception("security_ontology_search failed")
        return json.dumps({"success": False, "error": str(exc)})

    if not result or not result.get("documents") or not result["documents"][0]:
        return json.dumps({"success": True, "results": [], "message": "no hits"})

    ids_list = result.get("ids", [[]])[0]
    docs_list = result["documents"][0]
    metas_list = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]

    rows: List[Dict[str, Any]] = []
    for i in range(min(len(metas_list), len(docs_list))):
        dist = distances[i] if i < len(distances) else 1.0
        score = 1.0 / (1.0 + float(dist)) if dist is not None else 0.0
        meta = metas_list[i] or {}
        rows.append(
            {
                "id": ids_list[i] if i < len(ids_list) else "",
                "score": round(score, 4),
                "kind": meta.get("kind"),
                "type_id": meta.get("type_id"),
                "enum_name": meta.get("enum_name"),
                "member_id": meta.get("member_id"),
                "ontology_version": meta.get("ontology_version"),
                "text_preview": (docs_list[i] or "")[:400],
            }
        )

    return json.dumps({"success": True, "query": query, "results": rows}, indent=2)


def make_security_ontology_search() -> StructuredTool:
    return StructuredTool.from_function(
        name="security_ontology_search",
        description=(
            "Semantic search over the security graph ontology (node types, edge types, enum members). "
            "Read-only; use for mapping informal terms to canonical ontology ids."
        ),
        func=lambda **kw: _security_ontology_search(**kw),
        args_schema=SecurityOntologySearchInput,
    )


SECURITY_ONTOLOGY_TOOL_REGISTRY = {
    "security_ontology_search": make_security_ontology_search,
}
