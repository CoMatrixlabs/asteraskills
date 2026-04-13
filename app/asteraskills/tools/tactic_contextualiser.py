"""
TacticContextualiserTool — derive tactic_risk_lens for a technique under a specific tactic.
Caches results in Postgres (tactic_contexts) and AttackCollections.tactic_contexts().
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.attack_tools import ATTACKEnrichmentTool, ATTACKTechniqueDetail
from asteraskills.config.settings import get_settings
from asteraskills.storage.collections import AttackCollections
from asteraskills.storage.vector_store import get_vector_store_client

logger = logging.getLogger(__name__)


class TacticContextualiserInput(BaseModel):
    """Input schema for TacticContextualiserTool."""
    technique_id: str = Field(description="ATT&CK technique ID (e.g., T1078)")
    tactic: str = Field(description="Kill chain phase slug (e.g., persistence, initial-access)")


def _run_async(coro):
    """Run async coroutine from sync context."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _query_tactic_context_postgres(technique_id: str, tactic: str) -> Optional[Dict[str, Any]]:
    """Query tactic_contexts Postgres table."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("""
                    SELECT technique_id, tactic, tactic_risk_lens, blast_radius, primary_asset_types
                    FROM tactic_contexts
                    WHERE technique_id = :tid AND tactic = :tactic
                """),
                {"tid": technique_id, "tactic": tactic},
            )
            row = result.fetchone()
            if row:
                return {
                    "technique_id": row[0],
                    "tactic": row[1],
                    "tactic_risk_lens": row[2],
                    "blast_radius": row[3] or "identity",
                    "primary_asset_types": row[4] or [],
                    "source": "cache_postgres",
                }
    except Exception as e:
        if "does not exist" not in str(e).lower() and "relation" not in str(e).lower():
            logger.warning(f"Postgres tactic_contexts lookup failed: {e}")
    return None


def _point_query_tactic_context_qdrant(technique_id: str, tactic: str) -> Optional[Dict[str, Any]]:
    """Point-query AttackCollections.tactic_contexts() by technique_id and tactic metadata."""

    async def _query():
        client = get_vector_store_client()
        try:
            await client.initialize()
        except Exception:
            pass
        where = client.normalize_filter({
            "technique_id": technique_id,
            "tactic": tactic,
        })
        result = await client.query(
            collection_name=AttackCollections.tactic_contexts(),
            query_texts=[f"technique {technique_id} tactic {tactic}"],
            n_results=1,
            where=where,
        )
        if result and result.get("metadatas") and result["metadatas"][0]:
            meta = result["metadatas"][0][0] if result["metadatas"][0] else {}
            docs = result.get("documents", [[]])
            content = docs[0][0] if docs and docs[0] else ""
            if meta.get("technique_id") == technique_id and meta.get("tactic") == tactic:
                return {
                    "technique_id": technique_id,
                    "tactic": tactic,
                    "tactic_risk_lens": content or meta.get("tactic_risk_lens", ""),
                    "blast_radius": meta.get("blast_radius", "identity"),
                    "primary_asset_types": meta.get("primary_asset_types", []),
                    "source": "cache_qdrant",
                }
        return None

    try:
        return _run_async(_query())
    except Exception as e:
        logger.warning(f"Qdrant TACTIC_CONTEXTS lookup failed: {e}")
        return None


def _derive_tactic_risk_lens(
    technique: ATTACKTechniqueDetail,
    tactic: str,
    llm,
) -> tuple[str, str, List[str]]:
    """Call LLM to derive tactic_risk_lens, blast_radius, primary_asset_types."""
    prompt = f"""Given this ATT&CK technique and the tactic "{tactic}", derive:
1. tactic_risk_lens: 2-3 sentences framing the technique's risk profile specifically under this tactic
2. blast_radius: one of identity, endpoint, data, network, process
3. primary_asset_types: list of 1-3 primary asset types affected (e.g. ["user_accounts", "cloud_identity"])

Technique: {technique.technique_id} - {technique.name}
Description: {technique.description[:500]}
Tactics: {technique.tactics}

Return valid JSON only: {{"tactic_risk_lens": "...", "blast_radius": "...", "primary_asset_types": [...]}}"""

    try:
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        # Strip markdown code blocks if present
        if "```" in content:
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        data = json.loads(content.strip())
        return (
            data.get("tactic_risk_lens", ""),
            data.get("blast_radius", "identity"),
            data.get("primary_asset_types", []),
        )
    except Exception as e:
        logger.error(f"LLM tactic derivation failed: {e}")
        return (
            f"Risk under {tactic}: {technique.description[:200]}...",
            "identity",
            [],
        )


def _write_tactic_context_postgres(
    technique_id: str,
    tactic: str,
    tactic_risk_lens: str,
    blast_radius: str,
    primary_asset_types: List[str],
) -> None:
    """Write to tactic_contexts Postgres table."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            session.execute(
                text("""
                    INSERT INTO tactic_contexts (technique_id, tactic, tactic_risk_lens, blast_radius, primary_asset_types)
                    VALUES (:tid, :tactic, :lens, :radius, :assets)
                    ON CONFLICT (technique_id, tactic) DO UPDATE SET
                        tactic_risk_lens = EXCLUDED.tactic_risk_lens,
                        blast_radius = EXCLUDED.blast_radius,
                        primary_asset_types = EXCLUDED.primary_asset_types
                """),
                {
                    "tid": technique_id,
                    "tactic": tactic,
                    "lens": tactic_risk_lens,
                    "radius": blast_radius,
                    "assets": primary_asset_types,
                },
            )
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.warning(f"Failed to write tactic_contexts to Postgres: {e}")


def _write_tactic_context_qdrant(
    technique_id: str,
    tactic: str,
    tactic_risk_lens: str,
    blast_radius: str,
    primary_asset_types: List[str],
) -> None:
    """Write to AttackCollections.tactic_contexts() via vector store."""

    async def _add():
        client = get_vector_store_client()
        try:
            await client.initialize()
        except Exception:
            pass
        doc_id = f"{technique_id}::{tactic}"
        await client.add_documents(
            collection_name=AttackCollections.tactic_contexts(),
            documents=[tactic_risk_lens],
            metadatas=[{
                "technique_id": technique_id,
                "tactic": tactic,
                "blast_radius": blast_radius,
                "primary_asset_types": primary_asset_types,
            }],
            ids=[doc_id],
        )

    try:
        _run_async(_add())
    except Exception as e:
        logger.warning(f"Failed to write TACTIC_CONTEXTS to vector store: {e}")


def _execute_tactic_contextualise(technique_id: str, tactic: str) -> Dict[str, Any]:
    """Execute TacticContextualiserTool."""
    tid = technique_id.strip().upper()
    tactic_slug = tactic.strip().lower().replace(" ", "-")

    # 1. Postgres cache
    cached = _query_tactic_context_postgres(tid, tactic_slug)
    if cached:
        return cached

    # 2. Qdrant cache (point lookup - simplified: query by metadata)
    qdrant_cached = _point_query_tactic_context_qdrant(tid, tactic_slug)
    if qdrant_cached:
        # Repair: write back to Postgres
        _write_tactic_context_postgres(
            tid, tactic_slug,
            qdrant_cached["tactic_risk_lens"],
            qdrant_cached["blast_radius"],
            qdrant_cached.get("primary_asset_types", []),
        )
        return qdrant_cached

    # 3. Get technique and validate tactic
    settings = get_settings()
    pg_dsn = settings.get_attack_db_dsn() if hasattr(settings, "get_attack_db_dsn") else None
    enricher = ATTACKEnrichmentTool(use_postgres=bool(pg_dsn), pg_dsn=pg_dsn)
    technique = enricher.get_technique(tid)

    if tactic_slug not in technique.kill_chain_phases:
        raise ValueError(
            f"Tactic '{tactic_slug}' is not in technique {tid}'s kill_chain_phases: {technique.kill_chain_phases}"
        )

    # 4. Derive via LLM
    from asteraskills.core.llm import get_llm
    llm = get_llm(temperature=0.2)
    tactic_risk_lens, blast_radius, primary_asset_types = _derive_tactic_risk_lens(
        technique, tactic_slug, llm
    )

    # 5. Write to Postgres
    _write_tactic_context_postgres(tid, tactic_slug, tactic_risk_lens, blast_radius, primary_asset_types)

    # 6. Write to Qdrant
    _write_tactic_context_qdrant(tid, tactic_slug, tactic_risk_lens, blast_radius, primary_asset_types)

    # 7. Update enricher cache (tactic_contexts)
    technique.tactic_contexts[tactic_slug] = tactic_risk_lens
    enricher._local_cache[tid] = technique

    return {
        "technique_id": tid,
        "tactic": tactic_slug,
        "tactic_risk_lens": tactic_risk_lens,
        "blast_radius": blast_radius,
        "primary_asset_types": primary_asset_types,
        "source": "derived",
    }


def create_tactic_contextualiser_tool() -> StructuredTool:
    """Create LangChain tool for tactic contextualisation."""
    return StructuredTool.from_function(
        func=_execute_tactic_contextualise,
        name="attack_tactic_contextualise",
        description="Derive a tactic-specific risk lens for an ATT&CK technique. Returns tactic_risk_lens, blast_radius, primary_asset_types. Use kill_chain_phases slug (e.g. persistence, initial-access).",
        args_schema=TacticContextualiserInput,
    )
