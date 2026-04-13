"""
CVE vector sync — embed unsynced CVE descriptions and upsert into Qdrant
``cve_vectors`` collection.

Tracks ingestion state via ``embedding_synced_at`` column on ``cve_intelligence``.
Run this after the CVE enrichment pipeline to keep semantic search up to date.

Usage:
    python -m asteraskills.ingestion.cve.cve_vector_sync --batch-size 500
    # or from indexing_cli
    python indexing_cli/cve_vector_cli.py sync --batch-size 500
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CVE_VECTORS_COLLECTION = "cve_vectors"
DEFAULT_BATCH_SIZE = 500


# ── Schema prerequisite SQL ─────────────────────────────────────────────────────

DDL_EMBEDDING_SYNCED_AT = """
ALTER TABLE cve_intelligence
    ADD COLUMN IF NOT EXISTS embedding_synced_at TIMESTAMPTZ;
"""


def ensure_schema() -> None:
    """Add ``embedding_synced_at`` column to cve_intelligence if missing."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            session.execute(text(DDL_EMBEDDING_SYNCED_AT))
        logger.info("Schema: embedding_synced_at column ensured on cve_intelligence")
    except Exception as exc:
        logger.warning("Could not apply embedding_synced_at DDL: %s", exc)


# ── Collection bootstrap ────────────────────────────────────────────────────────

def ensure_cve_vectors_collection(vector_size: int = 1536) -> None:
    """Create the Qdrant ``cve_vectors`` collection if it does not exist."""
    try:
        from asteraskills.storage.vector_store import get_vector_store_client

        client = get_vector_store_client()
        raw = getattr(client, "_client", None) or getattr(client, "client", None)
        if raw is None:
            logger.warning("Cannot access raw Qdrant client; skipping collection bootstrap")
            return
        existing = {c.name for c in raw.get_collections().collections}
        if CVE_VECTORS_COLLECTION not in existing:
            from qdrant_client.models import Distance, VectorParams

            raw.create_collection(
                collection_name=CVE_VECTORS_COLLECTION,
                vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
            )
            logger.info("Created Qdrant collection: %s (dim=%d)", CVE_VECTORS_COLLECTION, vector_size)
        else:
            logger.debug("Collection %s already exists", CVE_VECTORS_COLLECTION)
    except Exception as exc:
        logger.warning("ensure_cve_vectors_collection failed: %s", exc)


# ── Fetch unsynced rows ─────────────────────────────────────────────────────────

def _fetch_unsynced(session: object, batch_size: int) -> List[Dict]:
    from sqlalchemy import text

    rows = session.execute(  # type: ignore[union-attr]
        text("""
            SELECT cve_id, description, cvss_score, exploit_maturity
            FROM cve_intelligence
            WHERE embedding_synced_at IS NULL
               OR updated_at > embedding_synced_at
            ORDER BY updated_at ASC
            LIMIT :limit
        """),
        {"limit": batch_size},
    ).fetchall()
    return [
        {
            "cve_id": r[0],
            "description": r[1] or "",
            "cvss_score": float(r[2] or 0),
            "exploit_maturity": r[3] or "none",
        }
        for r in rows
    ]


# ── Embed ───────────────────────────────────────────────────────────────────────

def _embed_texts(texts: List[str]) -> List[List[float]]:
    """Embed a batch of texts using the configured embedding model."""
    try:
        from asteraskills.config.settings import get_settings

        s = get_settings()
        provider = (s.LLM_PROVIDER or "openai").lower()

        if provider == "openai":
            import openai

            client = openai.OpenAI(api_key=s.OPENAI_API_KEY)
            resp = client.embeddings.create(
                input=texts,
                model=getattr(s, "EMBEDDING_MODEL", None) or "text-embedding-3-small",
            )
            return [item.embedding for item in resp.data]

        # Anthropic doesn't expose an embeddings endpoint; fall through to local
        logger.warning("Non-OpenAI provider '%s'; attempting local sentence-transformer", provider)
        from sentence_transformers import SentenceTransformer  # type: ignore

        model_name = getattr(s, "EMBEDDING_MODEL", None) or "all-MiniLM-L6-v2"
        model = SentenceTransformer(model_name)
        return model.encode(texts, show_progress_bar=False).tolist()

    except Exception as exc:
        logger.error("Embedding failed: %s", exc)
        return []


# ── Upsert to Qdrant ────────────────────────────────────────────────────────────

def _upsert_vectors(records: List[Dict], vectors: List[List[float]]) -> None:
    try:
        from asteraskills.storage.vector_store import get_vector_store_client
        from qdrant_client.models import PointStruct

        client = get_vector_store_client()
        raw = getattr(client, "_client", None) or getattr(client, "client", None)
        if raw is None:
            logger.warning("Cannot access raw Qdrant client; skipping upsert")
            return
        points = []
        for rec, vec in zip(records, vectors):
            import hashlib

            uid = int(hashlib.md5(rec["cve_id"].encode()).hexdigest(), 16) % (2**63)
            points.append(
                PointStruct(
                    id=uid,
                    vector=vec,
                    payload={
                        "cve_id": rec["cve_id"],
                        "cvss_score": rec["cvss_score"],
                        "exploit_maturity": rec["exploit_maturity"],
                    },
                )
            )
        raw.upsert(collection_name=CVE_VECTORS_COLLECTION, points=points)
    except Exception as exc:
        logger.error("Qdrant upsert failed: %s", exc)


# ── Mark synced ─────────────────────────────────────────────────────────────────

def _mark_synced(session: object, cve_ids: List[str]) -> None:
    from sqlalchemy import text

    session.execute(  # type: ignore[union-attr]
        text("""
            UPDATE cve_intelligence
            SET embedding_synced_at = NOW()
            WHERE cve_id = ANY(:ids)
        """),
        {"ids": cve_ids},
    )


# ── Public API ──────────────────────────────────────────────────────────────────

def sync_cve_vectors(
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_batches: Optional[int] = None,
) -> Dict[str, int]:
    """
    Embed unsynced CVE descriptions and upsert into Qdrant ``cve_vectors``.

    Returns:
        dict with keys "synced", "skipped", "errors"
    """
    ensure_schema()

    stats = {"synced": 0, "skipped": 0, "errors": 0}
    batches_run = 0

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session

        while True:
            if max_batches is not None and batches_run >= max_batches:
                break

            with get_security_intel_session("cve_attack") as session:
                rows = _fetch_unsynced(session, batch_size)
                if not rows:
                    break

                texts = [r["description"] or r["cve_id"] for r in rows]
                vectors = _embed_texts(texts)

                if not vectors or len(vectors) != len(rows):
                    logger.warning(
                        "Embedding returned %d vectors for %d rows; skipping batch",
                        len(vectors),
                        len(rows),
                    )
                    stats["skipped"] += len(rows)
                    # Avoid infinite loop on persistent embed failure
                    break

                ensure_cve_vectors_collection(vector_size=len(vectors[0]))
                _upsert_vectors(rows, vectors)
                _mark_synced(session, [r["cve_id"] for r in rows])

                stats["synced"] += len(rows)
                batches_run += 1
                logger.info(
                    "cve_vector_sync: batch %d — synced %d (total %d)",
                    batches_run,
                    len(rows),
                    stats["synced"],
                )

                if len(rows) < batch_size:
                    break  # last batch

    except Exception as exc:
        logger.error("sync_cve_vectors failed: %s", exc)
        stats["errors"] += 1

    logger.info("cve_vector_sync complete: %s", stats)
    return stats


# ── CLI entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Sync CVE descriptions to Qdrant cve_vectors")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-batches", type=int, default=None)
    args = parser.parse_args()

    result = sync_cve_vectors(batch_size=args.batch_size, max_batches=args.max_batches)
    print(result)
