"""
Fetch the CISA KEV JSON catalog and upsert into Qdrant and/or Postgres for ``KevClient``.

Source: optional local file (``--from-file`` or env ``CISA_KEV_JSON_PATH``), else official CISA feed,
then cisagov GitHub mirror.

**Qdrant:** each vulnerability is one point (vector + payload with ``cve_id`` and ``raw``).

**Postgres:** table ``cisa_kev`` (``cve_id`` PK, ``raw`` JSONB, catalog metadata). Runs when
``POSTGRES_DB`` and ``POSTGRES_USER`` are set unless ``--skip-postgres``.

Run::

    python -m asteraskills.ingestion.cisa_kev_qdrant_ingest
    python -m asteraskills.ingestion.cisa_kev_qdrant_ingest --recreate
    python -m asteraskills.ingestion.cisa_kev_qdrant_ingest --skip-qdrant --recreate-postgres
    python -m asteraskills.ingestion.cisa_kev_qdrant_ingest --from-file /path/to/known_exploited_vulnerabilities.json

Qdrant requires ``OPENAI_API_KEY`` (embeddings) and a reachable Qdrant. Postgres uses ``POSTGRES_*`` from ``.env``.
"""

from __future__ import annotations

import argparse
import json
import logging
import uuid
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_GITHUB_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/data/known_exploited_vulnerabilities.json"
)


def fetch_kev_catalog() -> Dict[str, Any]:
    """Download KEV JSON; try CISA then GitHub mirror."""
    last_err: Exception | None = None
    for url in (KEV_URL, KEV_GITHUB_URL):
        try:
            log.info("Fetching KEV catalog from %s", url)
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities") or []
            log.info("Loaded %d KEV vulnerabilities (catalogVersion=%s)", len(vulns), data.get("catalogVersion"))
            return data
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_err = exc
            log.warning("KEV fetch failed from %s: %s", url, exc)
    raise RuntimeError(f"Could not fetch KEV catalog: {last_err}")


def load_kev_catalog_from_path(path: str | Path) -> Dict[str, Any]:
    """
    Load CISA KEV JSON from disk (official shape: top-level ``vulnerabilities`` array).

    Accepts e.g. ``cisa_kev.json`` or ``known_exploited_vulnerabilities.json``.
    """
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"KEV catalog file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in KEV file {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"KEV JSON root must be an object, got {type(data).__name__}")
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        raise ValueError(f"KEV JSON has no non-empty 'vulnerabilities' array: {p}")
    log.info(
        "Loaded %d KEV vulnerabilities from %s (catalogVersion=%s)",
        len(vulns),
        p,
        data.get("catalogVersion"),
    )
    return data


def load_kev_catalog(*, local_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load KEV catalog from ``local_path``, else ``CISA_KEV_JSON_PATH`` in settings if the file exists,
    else download from CISA / GitHub mirror.
    """
    if local_path:
        return load_kev_catalog_from_path(local_path)
    try:
        from asteraskills.config.settings import get_settings

        configured = (get_settings().CISA_KEV_JSON_PATH or "").strip()
        if configured:
            pp = Path(configured).expanduser()
            if pp.is_file():
                return load_kev_catalog_from_path(pp)
            log.warning("CISA_KEV_JSON_PATH is set but file is missing (%s); fetching remote catalog", pp)
    except Exception as exc:  # noqa: BLE001
        log.debug("KEV local settings path skipped: %s", exc)
    return fetch_kev_catalog()


def _embedding_text(v: Dict[str, Any]) -> str:
    parts = [
        v.get("cveID") or "",
        v.get("vulnerabilityName") or "",
        v.get("vendorProject") or "",
        v.get("product") or "",
        v.get("shortDescription") or "",
        v.get("requiredAction") or "",
        v.get("notes") or "",
    ]
    return " ".join(p.strip() for p in parts if p and str(p).strip())


def _point_id_for_cve(cve_upper: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "asteraskills.cisa.kev." + cve_upper))


def ingest_cisa_kev_to_qdrant(
    *,
    data: Optional[Dict[str, Any]] = None,
    local_path: Optional[str] = None,
    recreate: bool = False,
    batch_size: int = 64,
) -> Tuple[int, str]:
    """
    Upsert all KEV rows into Qdrant.

    If ``data`` is omitted, loads via ``load_kev_catalog(local_path=...)`` (file or remote).

    Returns (points_upserted, collection_name).
    """
    from langchain_openai import OpenAIEmbeddings
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams

    from asteraskills.config.settings import get_settings

    s = get_settings()
    collection = s.CISA_KEV_COLLECTION
    if data is None:
        data = load_kev_catalog(local_path=local_path)
    vulns: List[Dict[str, Any]] = data.get("vulnerabilities") or []
    if not vulns:
        raise RuntimeError("KEV catalog has no vulnerabilities")

    emb = OpenAIEmbeddings(model=s.EMBEDDING_MODEL, openai_api_key=s.OPENAI_API_KEY)
    probe = emb.embed_query("dimension probe")
    dim = len(probe)

    if s.QDRANT_URL:
        client = QdrantClient(url=s.QDRANT_URL, api_key=s.QDRANT_API_KEY or None)
        hostport = s.QDRANT_URL
    else:
        host = s.QDRANT_HOST or "localhost"
        port = int(s.QDRANT_PORT)
        client = QdrantClient(host=host, port=port, api_key=s.QDRANT_API_KEY or None)
        hostport = f"{host}:{port}"

    if recreate and client.collection_exists(collection):
        client.delete_collection(collection_name=collection)

    if not client.collection_exists(collection):
        client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
        )
        try:
            from qdrant_client.models import PayloadSchemaType

            client.create_payload_index(
                collection_name=collection,
                field_name="cve_id",
                field_schema=PayloadSchemaType.KEYWORD,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("payload index cve_id (optional): %s", exc)

    catalog_version = str(data.get("catalogVersion") or "")
    date_released = str(data.get("dateReleased") or "")

    total = 0
    batch_texts: List[str] = []
    batch_payloads: List[Dict[str, Any]] = []
    batch_ids: List[str] = []

    def flush() -> None:
        nonlocal total, batch_texts, batch_payloads, batch_ids
        if not batch_ids:
            return
        vectors = emb.embed_documents(batch_texts)
        points = [
            PointStruct(id=batch_ids[i], vector=vectors[i], payload=batch_payloads[i])
            for i in range(len(batch_ids))
        ]
        client.upsert(collection_name=collection, points=points)
        total += len(points)
        batch_texts, batch_payloads, batch_ids = [], [], []

    for v in vulns:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        text = _embedding_text(v)
        if not text.strip():
            text = cve
        payload = {
            "cve_id": cve,
            "raw": v,
            "catalog_version": catalog_version,
            "date_released": date_released,
        }
        batch_texts.append(text)
        batch_payloads.append(payload)
        batch_ids.append(_point_id_for_cve(cve))
        if len(batch_ids) >= batch_size:
            flush()

    flush()
    log.info("Upserted %d KEV points into Qdrant collection %r (%s)", total, collection, hostport)
    return total, collection


def ingest_cisa_kev_to_postgres(
    *,
    data: Optional[Dict[str, Any]] = None,
    local_path: Optional[str] = None,
    recreate: bool = False,
) -> int:
    """
    Upsert all KEV rows into Postgres ``cisa_kev``.

    If ``data`` is omitted, loads the catalog (local path or remote). ``recreate`` truncates first.

    Returns number of rows upserted.
    """
    from asteraskills.config.settings import get_settings
    from asteraskills.storage.cisa_kev_postgres import (
        postgres_configured,
        postgres_engine_from_settings,
        upsert_cisa_kev_catalog,
    )

    s = get_settings()
    if not postgres_configured(s):
        raise RuntimeError(
            "Postgres not configured (set POSTGRES_DB and POSTGRES_USER, DATABASE_TYPE=postgres)"
        )
    if data is None:
        data = load_kev_catalog(local_path=local_path)
    engine = postgres_engine_from_settings(s)
    return upsert_cisa_kev_catalog(engine, data, truncate_first=recreate)


def ingest_cisa_kev_all(
    *,
    local_path: Optional[str] = None,
    skip_qdrant: bool = False,
    skip_postgres: bool = False,
    recreate_qdrant: bool = False,
    recreate_postgres: bool = False,
    batch_size: int = 64,
) -> Dict[str, Any]:
    """
    Load catalog once (local file, ``CISA_KEV_JSON_PATH``, or remote); upsert to Qdrant and/or Postgres.

    Postgres runs automatically when configured unless ``skip_postgres``.
    """
    from asteraskills.config.settings import get_settings
    from asteraskills.storage.cisa_kev_postgres import postgres_configured

    data = load_kev_catalog(local_path=local_path)
    out: Dict[str, Any] = {"catalog_version": data.get("catalogVersion")}

    s = get_settings()
    do_pg = not skip_postgres and postgres_configured(s)
    if do_pg:
        out["postgres_rows"] = ingest_cisa_kev_to_postgres(data=data, recreate=recreate_postgres)
    elif not skip_postgres and not postgres_configured(s):
        log.info("Skipping Postgres (POSTGRES_DB / POSTGRES_USER not set); use --skip-postgres to silence")

    if not skip_qdrant:
        n, coll = ingest_cisa_kev_to_qdrant(
            data=data, recreate=recreate_qdrant, batch_size=batch_size
        )
        out["qdrant_points"] = n
        out["qdrant_collection"] = coll
    else:
        log.info("Skipping Qdrant (--skip-qdrant)")

    return out


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="Ingest CISA KEV catalog into Qdrant and/or Postgres")
    p.add_argument(
        "--recreate",
        action="store_true",
        help="Delete Qdrant collection and recreate before upsert",
    )
    p.add_argument(
        "--recreate-postgres",
        action="store_true",
        help="Truncate Postgres cisa_kev table before upsert",
    )
    p.add_argument("--skip-qdrant", action="store_true", help="Only load Postgres (if configured)")
    p.add_argument(
        "--skip-postgres",
        action="store_true",
        help="Only load Qdrant (skip Postgres even if configured)",
    )
    p.add_argument("--batch-size", type=int, default=64, help="Embedding / Qdrant upsert batch size")
    p.add_argument(
        "--from-file",
        metavar="PATH",
        default=None,
        help="Use this KEV JSON file instead of downloading (e.g. known_exploited_vulnerabilities.json)",
    )
    args = p.parse_args()
    summary = ingest_cisa_kev_all(
        local_path=args.from_file,
        skip_qdrant=args.skip_qdrant,
        skip_postgres=args.skip_postgres,
        recreate_qdrant=args.recreate,
        recreate_postgres=args.recreate_postgres,
        batch_size=args.batch_size,
    )
    parts = []
    if "postgres_rows" in summary:
        parts.append(f"postgres={summary['postgres_rows']} rows")
    if "qdrant_points" in summary:
        parts.append(f"qdrant={summary['qdrant_points']} in {summary['qdrant_collection']!r}")
    print("OK: " + "; ".join(parts) if parts else "OK: nothing to do (check flags / config)")


if __name__ == "__main__":
    main()
