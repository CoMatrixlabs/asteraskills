"""
Distinct (technique_id, tactic) pairs from security_intel Postgres.
Vendored from complianceskill scenario_attack_control_ingest (DB fetch only).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy import text

from asteraskills.storage.sqlalchemy_session import get_security_intel_session
from asteraskills.tools.attack_tools import _tactics_to_kill_chain_phases

logger = logging.getLogger(__name__)


def fetch_technique_tactic_pairs_from_db() -> List[Dict[str, Any]]:
    """
    Prefer attack_techniques (full metadata). Fallback: DISTINCT from cve_attack_mappings.
    Each dict: technique_id, tactic, technique_name, description, data_sources, platforms.
    """
    pairs: List[Dict[str, Any]] = []
    with get_security_intel_session("cve_attack") as session:
        rows = session.execute(
            text(
                """
                SELECT technique_id, name, description, tactics, data_sources, platforms
                FROM attack_techniques
                ORDER BY technique_id
                """
            )
        ).fetchall()

        if rows:
            for r in rows:
                tid = (r[0] or "").strip().upper()
                name = r[1] or tid
                desc = r[2] or ""
                tactics = r[3] or []
                ds = r[4] or []
                pl = r[5] or []
                phases = _tactics_to_kill_chain_phases(list(tactics) if tactics else [])
                if not phases:
                    phases = ["initial-access"]
                all_tactics = list(phases)
                for tactic in phases:
                    pairs.append({
                        "technique_id": tid,
                        "tactic": tactic,
                        "technique_name": name,
                        "description": desc,
                        "data_sources": list(ds) if isinstance(ds, (list, tuple)) else [],
                        "platforms": list(pl) if isinstance(pl, (list, tuple)) else [],
                        "kill_chain_phases": all_tactics,
                    })
            return pairs

        rows2 = session.execute(
            text(
                """
                SELECT DISTINCT technique_id, tactic
                FROM cve_attack_mappings
                ORDER BY technique_id, tactic
                """
            )
        ).fetchall()

    from asteraskills.tools.attack_tools import ATTACKEnrichmentTool
    from asteraskills.config.settings import get_settings

    cache: Dict[str, Dict[str, Any]] = {}
    for r in rows2:
        tid = (r[0] or "").strip().upper()
        tactic = (r[1] or "").strip().lower().replace(" ", "-")
        if not tid or not tactic:
            continue
        if tid not in cache:
            try:
                settings = get_settings()
                pg_dsn = settings.get_attack_db_dsn() if hasattr(settings, "get_attack_db_dsn") else None
                enricher = ATTACKEnrichmentTool(use_postgres=bool(pg_dsn), pg_dsn=pg_dsn)
                detail = enricher.get_technique(tid)
                cache[tid] = {
                    "name": detail.name,
                    "description": detail.description,
                    "data_sources": list(detail.data_sources or []),
                    "platforms": list(detail.platforms or []),
                    "kill_chain_phases": list(detail.kill_chain_phases or []),
                }
            except Exception as e:  # noqa: BLE001
                logger.debug("ATT&CK enrich fallback for %s: %s", tid, e)
                cache[tid] = {
                    "name": tid,
                    "description": "",
                    "data_sources": [],
                    "platforms": [],
                    "kill_chain_phases": [],
                }
        d = cache[tid]
        kc = d.get("kill_chain_phases") or [tactic]
        pairs.append({
            "technique_id": tid,
            "tactic": tactic,
            "technique_name": d.get("name") or tid,
            "description": d.get("description") or "",
            "data_sources": d.get("data_sources") or [],
            "platforms": d.get("platforms") or [],
            "kill_chain_phases": list(kc),
        })
    return pairs
