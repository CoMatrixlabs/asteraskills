"""
Resolve CVE, ATT&CK technique, and framework control rows for richer markdown reports.

Uses Postgres security-intel DB when available; fails closed (None) when tables are missing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from risk_scanner.core.models import Finding
from risk_scanner.core.pack_client import _normalize_framework_id

log = logging.getLogger(__name__)


def get_cve_detail_for_report(finding: Finding) -> Optional[Dict[str, Any]]:
    """Prefer ``finding.cve_detail``; else read-only cache lookup (no NVD fetch)."""
    if finding.cve_detail:
        return dict(finding.cve_detail)
    try:
        from asteraskills.tools.cve_enrichment import _get_cached_cve_detail

        d = _get_cached_cve_detail(finding.taxonomy_code)
        return dict(d) if d else None
    except Exception as exc:
        log.debug("CVE detail cache lookup failed: %s", exc)
        return None


def lookup_attack_technique_name(technique_id: str) -> Optional[str]:
    tid = (technique_id or "").strip().upper()
    if not tid.startswith("T"):
        return None
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            row = session.execute(
                text("SELECT name FROM attack_techniques WHERE technique_id = :tid LIMIT 1"),
                {"tid": tid},
            ).fetchone()
            if row and row[0]:
                return str(row[0]).strip()
    except Exception as exc:
        if "does not exist" not in str(exc).lower() and "relation" not in str(exc).lower():
            log.debug("attack_techniques lookup failed for %s: %s", tid, exc)
    return None


def _control_lookup_variants(item_id: str) -> List[str]:
    """Possible DB keys for the same logical control (SOC2 CC*, CIS, NIST, etc.)."""
    raw = (item_id or "").strip()
    if not raw:
        return []
    seen: set[str] = set()
    out: List[str] = []
    for v in (raw, raw.upper(), raw.lower()):
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    u = raw.upper()
    # SOC2 Trust Services Criteria often stored as CC6.1, SOC2-CC6.1, or similar.
    if u.startswith("CC") and len(u) >= 4:
        for p in (f"SOC2-{raw}", f"SOC2-{u}", f"SOC2_{u}", f"soc2-{raw.lower()}"):
            if p and p not in seen:
                seen.add(p)
                out.append(p)
    if u.startswith("SOC2-"):
        stripped = raw[5:].lstrip("-_")
        if stripped and stripped not in seen:
            seen.add(stripped)
            out.append(stripped)
    return out


def lookup_framework_item_metadata(framework_slug: str, item_id: str) -> Optional[Dict[str, Any]]:
    """
    Resolve a control/scenario/risk id (e.g. CIS-RISK-013, AC-2, CC6.1) to name + description from DB.
    ``framework_slug`` is user-facing (cis-8, nist-800-53, soc2).
    """
    fid = _normalize_framework_id(framework_slug)
    iid = (item_id or "").strip()
    if not iid:
        return None

    variants = _control_lookup_variants(iid)
    suffix = iid.upper().lstrip("SOC2-").lstrip("SOC2_").strip()

    def _row_from_scenario(row) -> Dict[str, Any]:
        return {
            "source": row[0],
            "name": row[1] or "",
            "description": (row[2] or "")[:4000],
            "trigger": row[3] or "",
            "loss_outcomes": row[4] if row[4] is not None else [],
        }

    def _row_from_risk(row) -> Dict[str, Any]:
        return {
            "source": row[0],
            "name": row[1] or "",
            "description": (row[2] or "")[:4000],
            "trigger": row[3] or "",
            "loss_outcomes": row[4] if row[4] is not None else [],
        }

    def _row_from_control(row) -> Dict[str, Any]:
        return {
            "source": row[0],
            "name": row[1] or "",
            "description": (row[2] or "")[:4000],
            "trigger": "",
            "loss_outcomes": [],
        }

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            for vid in variants:
                row = session.execute(
                    text("""
                        SELECT 'scenario', name, description, trigger, loss_outcomes
                        FROM scenarios
                        WHERE framework_id = :fid
                          AND (id = :vid OR scenario_code = :vid)
                        LIMIT 1
                    """),
                    {"fid": fid, "vid": vid},
                ).fetchone()
                if row:
                    return _row_from_scenario(row)
            for vid in variants:
                row = session.execute(
                    text("""
                        SELECT 'risk', name, description, trigger, loss_outcomes
                        FROM risks
                        WHERE framework_id = :fid
                          AND (id = :vid OR risk_code = :vid)
                        LIMIT 1
                    """),
                    {"fid": fid, "vid": vid},
                ).fetchone()
                if row:
                    return _row_from_risk(row)
            for vid in variants:
                row = session.execute(
                    text("""
                        SELECT 'control', name, description
                        FROM controls
                        WHERE framework_id = :fid
                          AND (id = :vid OR control_code = :vid)
                        LIMIT 1
                    """),
                    {"fid": fid, "vid": vid},
                ).fetchone()
                if row:
                    return _row_from_control(row)
            # Fallback: SOC2-style codes sometimes match control_code with extra prefix/suffix in DB.
            if suffix and len(suffix) >= 3:
                row = session.execute(
                    text("""
                        SELECT 'control', name, description
                        FROM controls
                        WHERE framework_id = :fid
                          AND (
                            UPPER(TRIM(control_code)) LIKE '%' || :suf || '%'
                            OR UPPER(TRIM(name)) LIKE '%' || :suf || '%'
                          )
                        LIMIT 1
                    """),
                    {"fid": fid, "suf": suffix},
                ).fetchone()
                if row:
                    return _row_from_control(row)
            if suffix and len(suffix) >= 3:
                row = session.execute(
                    text("""
                        SELECT 'scenario', name, description, trigger, loss_outcomes
                        FROM scenarios
                        WHERE framework_id = :fid
                          AND (
                            UPPER(TRIM(scenario_code)) LIKE '%' || :suf || '%'
                            OR UPPER(TRIM(name)) LIKE '%' || :suf || '%'
                          )
                        LIMIT 1
                    """),
                    {"fid": fid, "suf": suffix},
                ).fetchone()
                if row:
                    return _row_from_scenario(row)
    except Exception as exc:
        if "does not exist" not in str(exc).lower() and "relation" not in str(exc).lower():
            log.debug("framework item lookup failed for %s / %s: %s", fid, iid, exc)
    return None


def format_loss_outcomes(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(str(x) for x in val[:12])
    return str(val)


def build_enrichment_summary_lines(result: Any) -> List[str]:
    """Short executive summary bullets for the top of the markdown report."""
    from risk_scanner.core.models import Domain, Severity

    findings = getattr(result, "findings", []) or []
    if not findings:
        return ["> **Summary:** No findings in this scan."]

    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == Severity.HIGH)
    cve_ids = [f.taxonomy_code for f in findings if f.domain == Domain.CVE]
    lines: List[str] = [
        f"- **Findings:** {len(findings)} | **Critical:** {crit} | **High:** {hi}",
    ]

    if cve_ids:
        lines.append(f"- **CVEs referenced:** {', '.join(f'`{c}`' for c in cve_ids[:8])}")
    doms = sorted({f.domain.value for f in findings})
    lines.append(f"- **Domains:** {', '.join(doms)}")

    return lines
