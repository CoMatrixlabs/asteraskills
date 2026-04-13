"""
PostgreSQL persistence for the CISA KEV catalog (JSON rows, PK ``cve_id``).

Used by ``python -m asteraskills.ingestion.cisa_kev_qdrant_ingest`` when Postgres
is configured, and optionally by ``risk_scanner`` ``KevClient`` (``KEV_USE_POSTGRES``).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.engine import Engine

from asteraskills.config.settings import DatabaseType, Settings

log = logging.getLogger(__name__)

CISA_KEV_TABLE_NAME = "cisa_kev"

metadata = MetaData()

cisa_kev_table = Table(
    CISA_KEV_TABLE_NAME,
    metadata,
    Column("cve_id", String(32), primary_key=True),
    Column("raw", JSONB, nullable=False),
    Column("catalog_version", Text),
    Column("date_released", Text),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    ),
)


def postgres_configured(s: Settings) -> bool:
    """True when default Postgres settings have database and user."""
    if s.DATABASE_TYPE != DatabaseType.POSTGRES:
        return False
    c = s.get_database_config()
    return bool(c.get("database") and c.get("user"))


def postgres_engine_from_settings(s: Settings) -> Engine:
    """Sync SQLAlchemy engine (psycopg2) from application settings."""
    from urllib.parse import quote_plus

    if s.DATABASE_TYPE != DatabaseType.POSTGRES:
        raise RuntimeError("DATABASE_TYPE is not postgres")
    c = s.get_database_config()
    user = c.get("user") or ""
    password = c.get("password") or ""
    host = c.get("host") or "localhost"
    port = int(c.get("port") or 5432)
    database = c.get("database") or ""
    ssl_mode = str(c.get("ssl_mode") or "prefer")
    if not database or not user:
        raise RuntimeError("POSTGRES_DB and POSTGRES_USER are required for KEV Postgres ingest")

    safe_user = quote_plus(user)
    if password:
        safe_pass = quote_plus(password)
        url = f"postgresql+psycopg2://{safe_user}:{safe_pass}@{host}:{port}/{database}"
    else:
        url = f"postgresql+psycopg2://{safe_user}@{host}:{port}/{database}"
    url = f"{url}?sslmode={quote_plus(ssl_mode)}"
    return create_engine(url, pool_pre_ping=True)


def _patch_cisa_kev_columns(engine: Engine) -> None:
    """
    Add columns missing from an older ``cisa_kev`` table.

    ``metadata.create_all`` does not alter existing tables, so a pre-existing table
    (e.g. from an earlier schema) must be patched with ``ALTER TABLE ... ADD COLUMN``.
    """
    insp = inspect(engine)
    if not insp.has_table(CISA_KEV_TABLE_NAME):
        return
    cols = {c["name"] for c in insp.get_columns(CISA_KEV_TABLE_NAME)}
    if "cve_id" not in cols:
        log.warning(
            "Table %r exists but has no cve_id column; skipping auto-migration",
            CISA_KEV_TABLE_NAME,
        )
        return
    fragments: list[str] = []
    if "raw" not in cols:
        fragments.append("ADD COLUMN IF NOT EXISTS raw JSONB")
    if "catalog_version" not in cols:
        fragments.append("ADD COLUMN IF NOT EXISTS catalog_version TEXT")
    if "date_released" not in cols:
        fragments.append("ADD COLUMN IF NOT EXISTS date_released TEXT")
    if "updated_at" not in cols:
        fragments.append(
            "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        )
    if not fragments:
        return
    ddl = f'ALTER TABLE "{CISA_KEV_TABLE_NAME}" ' + ", ".join(fragments)
    with engine.begin() as conn:
        conn.execute(text(ddl))
    log.info("Patched %r schema: %s", CISA_KEV_TABLE_NAME, "; ".join(fragments))


def ensure_cisa_kev_schema(engine: Engine) -> None:
    metadata.create_all(engine, tables=[cisa_kev_table])
    _patch_cisa_kev_columns(engine)


def upsert_cisa_kev_catalog(
    engine: Engine,
    data: Dict[str, Any],
    *,
    truncate_first: bool = False,
) -> int:
    """
    Upsert all vulnerabilities from a fetched KEV JSON document.

    Returns number of rows written (upserted).
    """
    ensure_cisa_kev_schema(engine)
    vulns: List[Dict[str, Any]] = data.get("vulnerabilities") or []
    if not vulns:
        raise RuntimeError("KEV catalog has no vulnerabilities")

    catalog_version = str(data.get("catalogVersion") or "")
    date_released = str(data.get("dateReleased") or "")
    now = datetime.now(timezone.utc)

    rows: List[Dict[str, Any]] = []
    for v in vulns:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        rows.append(
            {
                "cve_id": cve,
                "raw": v,
                "catalog_version": catalog_version,
                "date_released": date_released,
                "updated_at": now,
            }
        )

    if not rows:
        raise RuntimeError("No valid CVE rows in KEV catalog")

    with engine.begin() as conn:
        if truncate_first:
            conn.execute(cisa_kev_table.delete())

        n = 0
        for row in rows:
            stmt = insert(cisa_kev_table).values(**row)
            stmt = stmt.on_conflict_do_update(
                index_elements=[cisa_kev_table.c.cve_id],
                set_={
                    "raw": stmt.excluded.raw,
                    "catalog_version": stmt.excluded.catalog_version,
                    "date_released": stmt.excluded.date_released,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            conn.execute(stmt)
            n += 1

    log.info("Upserted %d KEV rows into Postgres table %r", n, CISA_KEV_TABLE_NAME)
    return n


def fetch_raw_for_cve(engine: Engine, cve_id: str) -> Optional[Dict[str, Any]]:
    """Return the CISA vulnerability dict for ``cve_id``, or ``None``."""
    cve = cve_id.strip().upper()
    if not cve:
        return None
    try:
        with engine.connect() as conn:
            row = conn.execute(
                select(cisa_kev_table.c.raw).where(cisa_kev_table.c.cve_id == cve)
            ).first()
        if row is None:
            return None
        raw = row[0]
        return raw if isinstance(raw, dict) else None
    except Exception as exc:  # noqa: BLE001
        log.debug("KEV Postgres lookup failed for %s: %s", cve_id, exc)
        return None


def count_rows(engine: Engine) -> Optional[int]:
    """Return row count for ``cisa_kev``, or ``None`` on error."""
    try:
        with engine.connect() as conn:
            n = conn.execute(select(func.count()).select_from(cisa_kev_table)).scalar()
        return int(n) if n is not None else 0
    except Exception as exc:  # noqa: BLE001
        log.debug("KEV Postgres count failed: %s", exc)
        return None
