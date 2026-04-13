"""
CVEToATTACKMapperTool — Stage 2 of CVE → ATT&CK → Control pipeline.
Maps CVE to ATT&CK techniques via CWE lookup + LLM refinement; persists to cve_attack_mappings.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE → ATT&CK technique crosswalk (MITRE/community mappings)
# Pipeline doc: CWE-77 → T1059, T1190, T1068
# Extend via cwe_technique_mappings table when populated
# ---------------------------------------------------------------------------
DEFAULT_CWE_TECHNIQUE_MAPPINGS: List[Dict[str, str]] = [
    {"cwe_id": "CWE-77", "technique_id": "T1059", "tactic": "execution", "confidence": "high"},
    {"cwe_id": "CWE-77", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-77", "technique_id": "T1068", "tactic": "privilege-escalation", "confidence": "high"},
    {"cwe_id": "CWE-78", "technique_id": "T1059", "tactic": "execution", "confidence": "high"},
    {"cwe_id": "CWE-78", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-79", "technique_id": "T1059.001", "tactic": "execution", "confidence": "high"},
    {"cwe_id": "CWE-79", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-89", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-89", "technique_id": "T1059", "tactic": "execution", "confidence": "medium"},
    {"cwe_id": "CWE-94", "technique_id": "T1059", "tactic": "execution", "confidence": "high"},
    {"cwe_id": "CWE-94", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-352", "technique_id": "T1539", "tactic": "credential-access", "confidence": "high"},
    {"cwe_id": "CWE-352", "technique_id": "T1190", "tactic": "initial-access", "confidence": "medium"},
    {"cwe_id": "CWE-287", "technique_id": "T1078", "tactic": "persistence", "confidence": "high"},
    {"cwe_id": "CWE-287", "technique_id": "T1133", "tactic": "initial-access", "confidence": "medium"},
    {"cwe_id": "CWE-306", "technique_id": "T1078", "tactic": "persistence", "confidence": "high"},
    {"cwe_id": "CWE-306", "technique_id": "T1133", "tactic": "initial-access", "confidence": "medium"},
    {"cwe_id": "CWE-502", "technique_id": "T1059", "tactic": "execution", "confidence": "high"},
    {"cwe_id": "CWE-502", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-918", "technique_id": "T1190", "tactic": "initial-access", "confidence": "high"},
    {"cwe_id": "CWE-918", "technique_id": "T1059", "tactic": "execution", "confidence": "medium"},
]


class CVEATTACKMapping(BaseModel):
    """Single CVE → ATT&CK mapping result."""
    cve_id: str
    technique_id: str
    tactic: str
    confidence: str
    mapping_source: str  # cwe_lookup | llm | cwe_lookup+llm
    rationale: str = ""


class CVEToATTACKMapperInput(BaseModel):
    """Input schema for CVEToATTACKMapperTool."""
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-3400)")
    cve_detail: Dict[str, Any] = Field(
        description="Output of CVEEnrichmentTool (cve_enrich) — description, CVSS, CWE, EPSS, etc."
    )
    frameworks: List[str] = Field(
        default_factory=lambda: ["cis_v8_1", "nist_800_53r5"],
        description="Framework IDs for downstream control mapping (e.g., cis_v8_1, nist_800_53r5)",
    )


def fetch_technique_tactic_pairs_from_security_intel_db() -> List[Dict[str, Any]]:
    """
    Distinct (technique_id, tactic) pairs with names/descriptions for control mapping.
    Delegates to scenario_attack_control_ingest (attack_techniques table, else cve_attack_mappings).
    """
    from asteraskills.ingestion.fetch_technique_pairs import fetch_technique_tactic_pairs_from_db

    return fetch_technique_tactic_pairs_from_db()


def _get_attack_mappings_for_cves(
    cve_ids: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Return {cve_id: [mappings]} from cve_attack_mappings.
    If cve_ids is None, return all CVEs in the table.
    """
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            if cve_ids:
                cids = [c.strip().upper() for c in cve_ids if c]
                if not cids:
                    return {}
                placeholders = ", ".join(f":c{i}" for i in range(len(cids)))
                params = {f"c{i}": c for i, c in enumerate(cids)}
                result = session.execute(
                    text(f"""
                        SELECT cve_id, technique_id, tactic, confidence, mapping_source, rationale
                        FROM cve_attack_mappings
                        WHERE cve_id IN ({placeholders})
                    """),
                    params,
                )
            else:
                result = session.execute(
                    text("""
                        SELECT cve_id, technique_id, tactic, confidence, mapping_source, rationale
                        FROM cve_attack_mappings
                    """),
                )
            rows = result.fetchall()
            out: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                cid = (r[0] or "").strip().upper()
                tid = (r[1] or "").strip().upper()
                tactic = (r[2] or "").strip().lower().replace(" ", "-")
                if not cid or not tid or not tactic:
                    continue
                out.setdefault(cid, []).append({
                    "cve_id": cid,
                    "technique_id": tid,
                    "tactic": tactic,
                    "confidence": (r[3] or "medium").lower(),
                    "mapping_source": (r[4] or "llm").lower(),
                    "rationale": r[5] or "",
                })
            return out
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"_get_attack_mappings_for_cves failed: {e}")
        return {}


def _get_existing_attack_mappings(cve_id: str) -> Optional[List[Dict[str, Any]]]:
    """Return existing CVE→ATT&CK mappings from cve_attack_mappings if any exist."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        cid = cve_id.strip().upper()
        if not cid.startswith("CVE-"):
            cid = f"CVE-{cid}" if not cid.startswith("CVE") else cid

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("""
                    SELECT technique_id, tactic, confidence, mapping_source, rationale
                    FROM cve_attack_mappings
                    WHERE cve_id = :cve_id
                """),
                {"cve_id": cid},
            )
            rows = result.fetchall()
            if not rows:
                return None
            return [
                {
                    "cve_id": cid,
                    "technique_id": (r[0] or "").strip().upper(),
                    "tactic": (r[1] or "").strip().lower().replace(" ", "-"),
                    "confidence": (r[2] or "medium").lower(),
                    "mapping_source": (r[3] or "llm").lower(),
                    "rationale": r[4] or "",
                }
                for r in rows
                if r[0] and r[1]
            ]
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"_get_existing_attack_mappings failed: {e}")
        return None


def _lookup_cwe_techniques(cwe_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Query cwe_technique_mappings for (technique_id, tactic, confidence) matching CWE IDs.
    Returns empty list if table is empty or no match — caller falls through to LLM-only path.
    Populated by cwe_enrich + cwe_capec_attack_mapper (run separately).
    """
    if not cwe_ids:
        return []

    norm = [c.strip().upper() for c in cwe_ids if c and str(c).strip().upper().startswith("CWE-")]
    if not norm:
        return []

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        placeholders = ", ".join(f":c{i}" for i in range(len(norm)))
        params = {f"c{i}": c for i, c in enumerate(norm)}
        with get_security_intel_session("cve_attack") as session:
            rows = session.execute(
                text(f"""
                    SELECT technique_id, tactic, confidence, mapping_source
                    FROM cwe_technique_mappings
                    WHERE cwe_id IN ({placeholders})
                    ORDER BY confidence DESC
                """),
                params,
            ).fetchall()
        seen: set = set()
        results: List[Dict[str, Any]] = []
        for r in rows:
            tid = (r[0] or "").strip().upper()
            tactic = (r[1] or "").strip().lower().replace(" ", "-")
            if not tid or not tactic:
                continue
            key = (tid, tactic)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "technique_id": tid,
                "tactic": tactic,
                "confidence": (r[2] or "high").lower(),
                "mapping_source": (r[3] or "cwe_lookup").lower(),
            })
        return results
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.warning(f"cwe_technique_mappings lookup failed: {e}. Falling back to LLM-only.")
        return []


def _query_cwe_technique_mappings(cwe_ids: List[str]) -> List[Dict[str, Any]]:
    """Alias for _lookup_cwe_techniques (DB-only, no hardcoded fallback)."""
    return _lookup_cwe_techniques(cwe_ids)


def _load_attack_mappings_from_db(cve_id: str) -> List[Dict[str, Any]]:
    """
    Load existing CVE→ATT&CK mappings from cve_attack_mappings.
    Used when --start-stage 3 to skip Stage 2 (NVD + LLM).
    """
    cid = cve_id.strip().upper()
    if not cid.startswith("CVE-"):
        cid = f"CVE-{cid}" if cid.startswith("CVE") else cid

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            rows = session.execute(
                text("""
                    SELECT technique_id, tactic, confidence, mapping_source, rationale
                    FROM cve_attack_mappings
                    WHERE cve_id = :cve_id
                """),
                {"cve_id": cid},
            ).fetchall()
        if not rows:
            return []
        return [
            {
                "cve_id": cid,
                "technique_id": (r[0] or "").strip().upper(),
                "tactic": (r[1] or "").strip().lower().replace(" ", "-"),
                "confidence": (r[2] or "medium").lower(),
                "mapping_source": (r[3] or "llm").lower(),
                "rationale": r[4] or "",
            }
            for r in rows
            if r[0] and r[1]
        ]
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"_load_attack_mappings_from_db failed: {e}")
        return []


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response."""
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            text = match.group(1).strip()
    return json.loads(text)


CVE_TO_ATTACK_LLM_SYSTEM = """You are a cybersecurity analyst mapping CVEs to MITRE ATT&CK techniques.

Given a CVE's description, CVSS, CWE, affected products, and exploit status, you will:
1. Confirm or reject each CWE-derived candidate (technique_id, tactic) based on the specific exploit
2. Add additional techniques the CWE crosswalk may miss (e.g. persistence, defense-evasion)
3. Assign confidence: high (direct match), medium (plausible), low (tangential)
4. Set mapping_source: "cwe_lookup+llm" if confirming CWE candidate, "llm" if adding new

Return ONLY a JSON array. No markdown, no preamble.
[
  {"technique_id": "T1190", "tactic": "initial-access", "confidence": "high", "mapping_source": "cwe_lookup+llm", "rationale": "..."},
  ...
]
"""


def _llm_refine_mappings(
    cve_id: str,
    cve_detail: Dict[str, Any],
    cwe_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Call LLM to refine and augment CWE-derived mappings."""
    from asteraskills.core.llm import get_llm
    from langchain_core.messages import SystemMessage, HumanMessage

    desc = cve_detail.get("description", "")[:1200]
    cvss = cve_detail.get("cvss_score", 0)
    cwe_ids = cve_detail.get("cwe_ids", [])
    products = cve_detail.get("affected_products", [])[:10]
    epss = cve_detail.get("epss_score", 0)
    exploit = cve_detail.get("exploit_available", False)
    maturity = cve_detail.get("exploit_maturity", "none")

    user = f"""CVE: {cve_id}
Description: {desc}
CVSS: {cvss} | EPSS: {epss} | Exploit: {exploit} ({maturity})
CWE: {', '.join(cwe_ids)}
Affected: {', '.join(products) if products else 'unknown'}

CWE-derived candidates:
{json.dumps(cwe_candidates, indent=2)}

Refine and augment. Return JSON array of mappings. Include rationale for each."""

    llm = get_llm(temperature=0.2)
    response = llm.invoke([
        SystemMessage(content=CVE_TO_ATTACK_LLM_SYSTEM),
        HumanMessage(content=user),
    ])
    content = response.content if hasattr(response, "content") else str(response)
    try:
        mappings = _extract_json(content)
        if not isinstance(mappings, list):
            return cwe_candidates
        return mappings
    except json.JSONDecodeError:
        logger.warning(f"LLM CVE→ATT&CK returned invalid JSON: {content[:200]}")
        return cwe_candidates


def _ensure_technique_exists(
    session,
    technique_id: str,
    tactic: str,
) -> None:
    """Ensure technique exists in attack_techniques; create with tactic if missing (for reuse)."""
    from sqlalchemy import text

    result = session.execute(
        text("SELECT 1 FROM attack_techniques WHERE technique_id = :tid"),
        {"tid": technique_id},
    )
    if result.fetchone():
        return

    # Fetch from ATT&CK STIX if available for proper name/description
    try:
        from asteraskills.tools.attack_tools import ATTACKEnrichmentTool

        tool = ATTACKEnrichmentTool()
        detail = tool.get_technique(technique_id)
        name = detail.name or f"Technique {technique_id}"
        description = detail.description or ""
        tactics_list = list(detail.tactics) if detail.tactics else [tactic]
        if tactic not in [t.lower().replace(" ", "-") for t in tactics_list]:
            tactics_list.append(tactic)
    except Exception:
        name = f"Technique {technique_id}"
        description = ""
        tactics_list = [tactic]

    session.execute(
        text("""
            INSERT INTO attack_techniques (technique_id, name, description, tactics, platforms, data_sources, detection, mitigations, url)
            VALUES (:technique_id, :name, :description, :tactics, '{}', '{}', '', '[]'::jsonb, '')
            ON CONFLICT (technique_id) DO UPDATE SET
                tactics = (
                    SELECT array_agg(DISTINCT x)
                    FROM unnest(COALESCE(attack_techniques.tactics, '{}') || EXCLUDED.tactics) AS x
                )
        """),
        {
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "tactics": tactics_list,
        },
    )
    logger.info(f"Created technique {technique_id} in attack_techniques for reuse")


def _persist_cve_attack_mappings(
    cve_id: str,
    cve_detail: Dict[str, Any],
    mappings: List[Dict[str, Any]],
    mapping_run_id: Optional[str] = None,
) -> None:
    """Write to cve_attack_mappings table. Creates technique in attack_techniques if missing (for reuse)."""
    run_id = mapping_run_id or str(uuid.uuid4())
    cvss = cve_detail.get("cvss_score")
    epss = cve_detail.get("epss_score")
    attack_vector = cve_detail.get("attack_vector", "")
    cwe_ids = cve_detail.get("cwe_ids", [])
    affected = cve_detail.get("affected_products", [])
    exploit_avail = cve_detail.get("exploit_available", False)
    maturity = cve_detail.get("exploit_maturity", "none")

    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            for m in mappings:
                technique_id = (m.get("technique_id") or "").strip().upper()
                tactic = (m.get("tactic") or "").strip().lower().replace(" ", "-")
                confidence = (m.get("confidence") or "medium").lower()
                source = (m.get("mapping_source") or "llm").lower()
                rationale = m.get("rationale", "")

                if not technique_id or not tactic:
                    continue

                try:
                    _ensure_technique_exists(session, technique_id, tactic)
                    session.execute(
                        text("""
                        INSERT INTO cve_attack_mappings (
                            cve_id, technique_id, tactic,
                            cvss_score, epss_score, attack_vector, cwe_ids, affected_products,
                            exploit_available, exploit_maturity,
                            confidence, mapping_source, rationale, mapping_run_id
                        ) VALUES (
                            :cve_id, :technique_id, :tactic,
                            :cvss_score, :epss_score, :attack_vector, :cwe_ids, :affected_products,
                            :exploit_available, :exploit_maturity,
                            :confidence, :mapping_source, :rationale, :mapping_run_id
                        )
                        ON CONFLICT (cve_id, technique_id, tactic) DO UPDATE SET
                            cvss_score = EXCLUDED.cvss_score,
                            epss_score = EXCLUDED.epss_score,
                            attack_vector = EXCLUDED.attack_vector,
                            cwe_ids = EXCLUDED.cwe_ids,
                            affected_products = EXCLUDED.affected_products,
                            exploit_available = EXCLUDED.exploit_available,
                            exploit_maturity = EXCLUDED.exploit_maturity,
                            confidence = EXCLUDED.confidence,
                            mapping_source = EXCLUDED.mapping_source,
                            rationale = EXCLUDED.rationale,
                            mapping_run_id = EXCLUDED.mapping_run_id
                        """),
                        {
                            "cve_id": cve_id,
                            "technique_id": technique_id,
                            "tactic": tactic,
                            "cvss_score": cvss,
                            "epss_score": epss,
                            "attack_vector": attack_vector,
                            "cwe_ids": cwe_ids,
                            "affected_products": affected,
                            "exploit_available": exploit_avail,
                            "exploit_maturity": maturity,
                            "confidence": confidence,
                            "mapping_source": source,
                            "rationale": rationale,
                            "mapping_run_id": run_id,
                        },
                    )
                except Exception as row_err:
                    err_str = str(row_err).lower()
                    if "does not exist" in err_str or "relation" in err_str:
                        logger.debug(f"attack_techniques table may not exist: {row_err}")
                    else:
                        logger.warning(f"Failed to persist mapping for {technique_id}: {row_err}")
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.warning(f"Failed to persist cve_attack_mappings: {e}")


def _execute_cve_to_attack_map(
    cve_id: str,
    cve_detail: Dict[str, Any],
    frameworks: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Execute CVEToATTACKMapperTool."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}" if not cve_id.startswith("CVE") else cve_id

    # 1. CWE → technique lookup (DB only; empty = LLM-only path)
    cwe_ids = cve_detail.get("cwe_ids", [])
    cwe_candidates = _lookup_cwe_techniques(cwe_ids)

    # 2. LLM refinement
    if cve_detail.get("description"):
        refined = _llm_refine_mappings(cve_id, cve_detail, cwe_candidates)
    else:
        refined = cwe_candidates
        for r in refined:
            r.setdefault("rationale", "")
            r.setdefault("mapping_source", "cwe_lookup")

    # 3. Normalize and dedupe
    seen: set = set()
    final: List[Dict[str, Any]] = []
    for m in refined:
        tid = (m.get("technique_id") or "").strip().upper()
        tactic = (m.get("tactic") or "").strip().lower().replace(" ", "-")
        if not tid or not tactic:
            continue
        key = (tid, tactic)
        if key in seen:
            continue
        seen.add(key)
        final.append({
            "cve_id": cve_id,
            "technique_id": tid,
            "tactic": tactic,
            "confidence": (m.get("confidence") or "medium").lower(),
            "mapping_source": (m.get("mapping_source") or "llm").lower(),
            "rationale": m.get("rationale", ""),
        })

    # 4. Persist
    _persist_cve_attack_mappings(cve_id, cve_detail, final)

    return final


def run_cve_pipeline(
    cve_id: str,
    frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run the full CVE → ATT&CK → Control pipeline.
    Returns enriched CVE, technique-tactic mappings, and control mappings per framework.
    """
    from asteraskills.tools.cve_enrichment import _execute_cve_enrich
    from asteraskills.tools.attack_control_mapping import _execute_attack_control_map

    frameworks = frameworks or ["cis_v8_1", "nist_800_53r5"]
    cve_detail = _execute_cve_enrich(cve_id)
    mappings = _execute_cve_to_attack_map(cve_id, cve_detail, frameworks)

    control_results: List[Dict[str, Any]] = []
    for m in mappings:
        for fw in frameworks:
            try:
                results = _execute_attack_control_map(
                    technique_id=m["technique_id"],
                    tactic=m["tactic"],
                    framework_id=fw,
                    cve_id=cve_id,
                    cve_context=cve_detail,
                    persist=True,
                )
                control_results.extend(results)
            except Exception as e:
                logger.warning(f"Control mapping failed for {m['technique_id']}/{m['tactic']}/{fw}: {e}")

    return {
        "cve_id": cve_id,
        "cve_detail": cve_detail,
        "technique_tactic_mappings": mappings,
        "control_mappings": control_results,
    }


def create_cve_to_attack_mapper_tool() -> StructuredTool:
    """Create LangChain tool for CVE → ATT&CK mapping (Stage 2 of pipeline)."""
    return StructuredTool.from_function(
        func=_execute_cve_to_attack_map,
        name="cve_to_attack_map",
        description="Map a CVE to ATT&CK techniques using CWE lookup + LLM. Requires cve_detail from cve_enrich. Call cve_enrich first, then pass its output here. Returns list of (technique_id, tactic) for Stage 3 control mapping.",
        args_schema=CVEToATTACKMapperInput,
    )
