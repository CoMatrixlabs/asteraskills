"""
CVEEnrichmentTool — Stage 1 of CVE → ATT&CK → Control pipeline.

**Default:** fetch from **NVD first** (authoritative, reflects CVE record updates), merge EPSS/KEV,
then **upsert** into ``cve_intelligence`` for faster/offline reuse.

**Fallback:** if NVD and CIRCL are unavailable (offline, rate limits, network errors), use
``cve_intelligence`` / ``cve_cache`` when present.

**Offline-only:** pass ``skip_nvd_fetch=True`` to read DB/cache only (no HTTP).
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import requests
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult, SecurityTool

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
CIRCL_BASE_URL = "https://cve.circl.lu/api/cve"


class CVEDetail(BaseModel):
    """Output schema for CVEEnrichmentTool per pipeline spec."""
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    attack_vector: str = ""  # network | adjacent | local | physical
    attack_complexity: str = ""
    privileges_required: str = ""
    cwe_ids: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    epss_score: float = 0.0
    exploit_available: bool = False
    exploit_maturity: str = ""  # none | poc | weaponised
    published_date: str = ""
    last_modified: str = ""


def _normalize_attack_vector(av: str) -> str:
    """Map CVSS attack vector to pipeline enum."""
    if not av:
        return "network"
    v = av.lower()
    if "network" in v:
        return "network"
    if "adjacent" in v:
        return "adjacent"
    if "local" in v:
        return "local"
    if "physical" in v:
        return "physical"
    return "network"


def _infer_exploit_maturity(kev: bool, epss: float) -> str:
    """Infer exploit maturity from KEV + EPSS."""
    if kev:
        return "weaponised"
    if epss >= 0.7:
        return "weaponised"
    if epss >= 0.3:
        return "poc"
    return "none"


def _load_cve_detail_from_db(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Load CVE detail from cve_intelligence. Used when --start-stage 2 or 3.
    Returns None if not found (caller should warn and skip).
    """
    cid = cve_id.strip().upper()
    if not cid.startswith("CVE-"):
        cid = f"CVE-{cid}" if cid.startswith("CVE") else cid
    return _query_cve_intelligence_cache(cid)


def _query_cve_intelligence_cache(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query Postgres cve_intelligence table if it exists."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("""
                    SELECT cve_id, description, cvss_score, cvss_vector, attack_vector,
                           attack_complexity, privileges_required, cwe_ids, affected_products,
                           epss_score, exploit_available, exploit_maturity,
                           published_date, last_modified
                    FROM cve_intelligence
                    WHERE cve_id = :cve_id
                """),
                {"cve_id": cve_id},
            )
            row = result.fetchone()
            if row:
                return {
                    "cve_id": row[0],
                    "description": row[1] or "",
                    "cvss_score": float(row[2]) if row[2] is not None else 0.0,
                    "cvss_vector": row[3] or "",
                    "attack_vector": row[4] or "network",
                    "attack_complexity": row[5] or "",
                    "privileges_required": row[6] or "",
                    "cwe_ids": row[7] or [],
                    "affected_products": row[8] or [],
                    "epss_score": float(row[9]) if row[9] is not None else 0.0,
                    "exploit_available": bool(row[10]) if row[10] is not None else False,
                    "exploit_maturity": row[11] or "none",
                    "published_date": str(row[12]) if row[12] else "",
                    "last_modified": str(row[13]) if row[13] else "",
                }
    except Exception as e:
        if "does not exist" not in str(e).lower() and "relation" not in str(e).lower():
            logger.debug(f"cve_intelligence cache lookup failed: {e}")
    return None


def _query_cve_cache_fallback(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query cve_cache table (Phase 1 schema) as fallback."""
    try:
        import json
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("SELECT nvd_data, epss_data, kev_data FROM cve_cache WHERE cve_id = :cve_id"),
                {"cve_id": cve_id},
            )
            row = result.fetchone()
            if row and row[0]:
                nvd = row[0] if isinstance(row[0], dict) else json.loads(row[0] or "{}")
                epss = row[1] if isinstance(row[1], dict) else (json.loads(row[1] or "{}") if row[1] else {})
                kev = bool(row[2]) if row[2] is not None else False
                return _parse_nvd_to_detail(cve_id, nvd, epss, kev)
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"cve_cache lookup failed: {e}")
    return None


def _parse_nvd_to_detail(
    cve_id: str,
    nvd_data: Dict[str, Any],
    epss_data: Optional[Dict] = None,
    kev: bool = False,
) -> Dict[str, Any]:
    """Parse NVD/EPSS/KEV response into CVEDetail shape."""
    vuln = {}
    if isinstance(nvd_data, dict):
        vulns = nvd_data.get("vulnerabilities", [])
        if vulns:
            vuln = vulns[0].get("cve", vulns[0])
        else:
            vuln = nvd_data

    desc = ""
    if "descriptions" in vuln:
        for d in vuln["descriptions"]:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and vuln["descriptions"]:
            desc = vuln["descriptions"][0].get("value", "")
    elif "description" in vuln:
        desc = vuln["description"]

    cvss_score = 0.0
    cvss_vector = ""
    attack_vector = "network"
    attack_complexity = ""
    privileges_required = ""

    metrics = vuln.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            cvss_score = float(cvss_data.get("baseScore", 0))
            cvss_vector = cvss_data.get("vectorString", "")
            attack_vector = _normalize_attack_vector(cvss_data.get("attackVector", ""))
            attack_complexity = cvss_data.get("attackComplexity", "")
            privileges_required = cvss_data.get("privilegesRequired", "")
            break

    cwe_ids = []
    for w in vuln.get("weaknesses", []):
        for desc_list in w.get("description", []):
            if desc_list.get("value", "").startswith("CWE-"):
                cwe_ids.append(desc_list["value"])

    affected_products = []
    for cfg in vuln.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if ":" in criteria:
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        affected_products.append(f"{parts[3]}:{parts[4]}")

    epss_score = 0.0
    if epss_data and isinstance(epss_data, dict):
        data = epss_data.get("data", [epss_data])
        if data:
            epss_score = float(data[0].get("epss", 0))
    elif isinstance(epss_data, list) and epss_data:
        epss_score = float(epss_data[0].get("epss", 0))

    exploit_available = kev
    exploit_maturity = _infer_exploit_maturity(kev, epss_score)

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "cwe_ids": list(set(cwe_ids)),
        "affected_products": list(set(affected_products))[:20],
        "epss_score": epss_score,
        "exploit_available": exploit_available,
        "exploit_maturity": exploit_maturity,
        "published_date": vuln.get("published", ""),
        "last_modified": vuln.get("lastModified", ""),
    }


def _fetch_nvd(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE from NVD API 2.0."""
    try:
        from asteraskills.config.settings import get_settings

        headers = {}
        api_key = get_settings().NVD_API_KEY or os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        resp = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"NVD fetch failed for {cve_id}: {e}")
        return {}


def _get_cached_cve_detail(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return cached CVE detail from cve_intelligence or cve_cache, or None if not cached."""
    cached = _query_cve_intelligence_cache(cve_id)
    if cached:
        return cached
    return _query_cve_cache_fallback(cve_id)


def _prefetch_nvd_batch(
    cve_ids: List[str],
    batch_size: int = 10,
) -> Dict[str, Dict[str, Any]]:
    """
    Pre-fetch NVD data for multiple CVEs using concurrent requests.
    Returns {cve_id: raw_nvd_response}. Respects NVD rate limits:
    - With API key: 50 req/30s -> batch_size 10, 6s delay between batches
    - Without API key: 5 req/30s -> batch_size 5, 6s delay
    """
    if not cve_ids:
        return {}
    api_key: Optional[str] = None
    try:
        from asteraskills.config.settings import get_settings

        api_key = get_settings().NVD_API_KEY or os.getenv("NVD_API_KEY")
    except Exception:
        pass
    size = batch_size if api_key else min(5, batch_size)
    delay = 6.0  # Stay under 50/30s (with key) or 5/30s (without)

    headers: Dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    result: Dict[str, Dict[str, Any]] = {}

    def fetch_one(cid: str) -> tuple[str, Dict[str, Any]]:
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params={"cveId": cid},
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            return (cid, resp.json())
        except Exception as e:
            logger.warning(f"NVD fetch failed for {cid}: {e}")
            return (cid, {})

    def _norm(c: str) -> str:
        c = (c or "").strip().upper()
        if not c:
            return ""
        if not c.startswith("CVE-"):
            c = f"CVE-{c}" if not c.startswith("CVE") else c
        return c

    ids = [c for c in (_norm(x) for x in cve_ids) if c]
    for i in range(0, len(ids), size):
        batch = ids[i : i + size]
        with ThreadPoolExecutor(max_workers=size) as ex:
            futures = {ex.submit(fetch_one, cid): cid for cid in batch}
            for fut in as_completed(futures):
                cid, data = fut.result()
                result[cid] = data
        if i + size < len(ids):
            time.sleep(delay)

    logger.info(f"NVD pre-fetch: {len(result)} CVEs fetched in batches of {size}")
    return result


def _fetch_epss(cve_id: str) -> Dict[str, Any]:
    """Fetch EPSS from FIRST API."""
    try:
        resp = requests.get(
            EPSS_BASE_URL,
            params={"cve": cve_id},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.debug(f"EPSS fetch failed for {cve_id}: {e}")
        return {}


def _check_kev(cve_id: str) -> bool:
    """Check if CVE is in CISA KEV. Uses DB (cisa_kev) if populated, else API."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("SELECT 1 FROM cisa_kev WHERE cve_id = :cve_id"),
                {"cve_id": cve_id},
            )
            if result.fetchone():
                return True
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"KEV DB lookup failed: {e}")

    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        for v in data.get("vulnerabilities", []):
            if v.get("cveID") == cve_id:
                return True
    except Exception as e:
        logger.debug(f"KEV check failed: {e}")
    return False


def _fetch_circl(
    cve_id: str,
    epss_lookup: Optional[Dict[str, float]] = None,
    kev_lookup: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Fallback: fetch from CIRCL CVE-Search."""
    try:
        resp = requests.get(f"{CIRCL_BASE_URL}/{cve_id}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return _parse_circl_to_detail(cve_id, data, epss_lookup=epss_lookup, kev_lookup=kev_lookup)
    except Exception as e:
        logger.debug(f"CIRCL fetch failed for {cve_id}: {e}")
    return None


def _parse_circl_to_detail(
    cve_id: str,
    data: Dict,
    epss_lookup: Optional[Dict[str, float]] = None,
    kev_lookup: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Parse CIRCL response into CVEDetail shape."""
    cwe_ids = []
    for ref in data.get("references", []):
        if "cwe.mitre.org" in str(ref):
            cwe_ids.append(ref.split("/")[-1] if "/" in ref else ref)
    for cwe in data.get("cwe", []):
        if cwe.startswith("CWE-"):
            cwe_ids.append(cwe)

    cvss = data.get("cvss") or 0.0
    if isinstance(cvss, str):
        try:
            cvss = float(cvss)
        except ValueError:
            cvss = 0.0

    if epss_lookup is not None:
        epss_score = epss_lookup.get(cve_id, 0.0)
    else:
        epss_data = _fetch_epss(cve_id)
        epss_score = 0.0
        if epss_data.get("data"):
            epss_score = float(epss_data["data"][0].get("epss", 0))
    if kev_lookup is not None:
        kev = cve_id in kev_lookup
    else:
        kev = _check_kev(cve_id)

    return {
        "cve_id": cve_id,
        "description": data.get("summary", data.get("description", "")),
        "cvss_score": float(cvss),
        "cvss_vector": data.get("cvss-vector", ""),
        "attack_vector": "network",
        "attack_complexity": "",
        "privileges_required": "",
        "cwe_ids": list(set(cwe_ids)),
        "affected_products": data.get("vulnerable_configuration", [])[:20] if isinstance(data.get("vulnerable_configuration"), list) else [],
        "epss_score": epss_score,
        "exploit_available": kev,
        "exploit_maturity": _infer_exploit_maturity(kev, epss_score),
        "published_date": data.get("Published", ""),
        "last_modified": data.get("Modified", ""),
    }


def _upsert_cve_intelligence(detail: Dict[str, Any]) -> None:
    """Upsert into cve_intelligence table if it exists."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            session.execute(
                text("""
                    INSERT INTO cve_intelligence (
                        cve_id, description, cvss_score, cvss_vector, attack_vector,
                        attack_complexity, privileges_required, cwe_ids, affected_products,
                        epss_score, exploit_available, exploit_maturity,
                        published_date, last_modified, updated_at
                    ) VALUES (
                        :cve_id, :description, :cvss_score, :cvss_vector, :attack_vector,
                        :attack_complexity, :privileges_required, :cwe_ids, :affected_products,
                        :epss_score, :exploit_available, :exploit_maturity,
                        :published_date, :last_modified, NOW()
                    )
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        cvss_score = EXCLUDED.cvss_score,
                        cvss_vector = EXCLUDED.cvss_vector,
                        attack_vector = EXCLUDED.attack_vector,
                        attack_complexity = EXCLUDED.attack_complexity,
                        privileges_required = EXCLUDED.privileges_required,
                        cwe_ids = EXCLUDED.cwe_ids,
                        affected_products = EXCLUDED.affected_products,
                        epss_score = EXCLUDED.epss_score,
                        exploit_available = EXCLUDED.exploit_available,
                        exploit_maturity = EXCLUDED.exploit_maturity,
                        published_date = EXCLUDED.published_date,
                        last_modified = EXCLUDED.last_modified,
                        updated_at = NOW()
                """),
                {
                    "cve_id": detail["cve_id"],
                    "description": detail["description"],
                    "cvss_score": detail["cvss_score"],
                    "cvss_vector": detail["cvss_vector"],
                    "attack_vector": detail["attack_vector"],
                    "attack_complexity": detail["attack_complexity"],
                    "privileges_required": detail["privileges_required"],
                    "cwe_ids": detail["cwe_ids"],
                    "affected_products": detail["affected_products"],
                    "epss_score": detail["epss_score"],
                    "exploit_available": detail["exploit_available"],
                    "exploit_maturity": detail["exploit_maturity"],
                    "published_date": detail["published_date"],
                    "last_modified": detail["last_modified"],
                },
            )
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"cve_intelligence upsert failed: {e}")


def _empty_cve_detail(cve_id: str) -> Dict[str, Any]:
    """Placeholder when no CVE data is available from any source."""
    return {
        "cve_id": cve_id,
        "description": "",
        "cvss_score": 0.0,
        "cvss_vector": "",
        "attack_vector": "network",
        "attack_complexity": "",
        "privileges_required": "",
        "cwe_ids": [],
        "affected_products": [],
        "epss_score": 0.0,
        "exploit_available": False,
        "exploit_maturity": "none",
        "published_date": "",
        "last_modified": "",
    }


def _execute_cve_enrich(
    cve_id: str,
    epss_lookup: Optional[Dict[str, float]] = None,
    kev_lookup: Optional[Set[str]] = None,
    nvd_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    skip_nvd_fetch: bool = False,
) -> Dict[str, Any]:
    """Execute CVEEnrichmentTool.

    **Live mode (default, ``skip_nvd_fetch=False``):** NVD first → upsert ``cve_intelligence``;
    then CIRCL if NVD has no record; **then** DB cache if both APIs fail or return nothing.

    **Batch runs:** pass ``nvd_lookup`` / ``epss_lookup`` / ``kev_lookup`` to avoid duplicate HTTP.

    **Offline / CI:** ``skip_nvd_fetch=True`` reads ``cve_intelligence`` / ``cve_cache`` only.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}" if not cve_id.startswith("CVE") else cve_id

    # ------------------------------------------------------------------
    # Offline / cache-only: no NVD, EPSS, CIRCL, or KEV HTTP
    # ------------------------------------------------------------------
    if skip_nvd_fetch:
        cached = _query_cve_intelligence_cache(cve_id)
        if cached:
            return cached
        cached = _query_cve_cache_fallback(cve_id)
        if cached:
            _upsert_cve_intelligence(cached)
            return cached
        return _empty_cve_detail(cve_id)

    # ------------------------------------------------------------------
    # 1) NVD first (authoritative; upsert DB for future reads / vectors)
    # ------------------------------------------------------------------
    nvd = (nvd_lookup or {}).get(cve_id) if nvd_lookup is not None else None
    if nvd is None:
        nvd = _fetch_nvd(cve_id)
    if nvd.get("vulnerabilities"):
        if epss_lookup is not None:
            epss_score = epss_lookup.get(cve_id, 0.0)
            epss = {"data": [{"epss": epss_score}]} if epss_score else {}
        else:
            epss = _fetch_epss(cve_id)
        if kev_lookup is not None:
            kev = cve_id in kev_lookup
        else:
            kev = _check_kev(cve_id)
        detail = _parse_nvd_to_detail(cve_id, nvd, epss, kev)
        _upsert_cve_intelligence(detail)
        return detail

    # ------------------------------------------------------------------
    # 2) CIRCL when NVD returns empty (transient / not yet in NVD)
    # ------------------------------------------------------------------
    circl = _fetch_circl(cve_id, epss_lookup=epss_lookup, kev_lookup=kev_lookup)
    if circl:
        _upsert_cve_intelligence(circl)
        return circl

    # ------------------------------------------------------------------
    # 3) Stale DB copy when both APIs failed or returned nothing
    # ------------------------------------------------------------------
    cached = _query_cve_intelligence_cache(cve_id)
    if cached:
        logger.info(
            "CVE %s: using cve_intelligence cache (NVD/CIRCL unavailable or empty)",
            cve_id,
        )
        return cached

    cached = _query_cve_cache_fallback(cve_id)
    if cached:
        logger.info("CVE %s: using cve_cache fallback (NVD/CIRCL unavailable)", cve_id)
        _upsert_cve_intelligence(cached)
        return cached

    return _empty_cve_detail(cve_id)


class CVEEnrichmentInput(BaseModel):
    """Input schema for CVEEnrichmentTool."""
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-3400)")


def create_cve_enrichment_tool() -> StructuredTool:
    """Create LangChain tool for CVE enrichment (Stage 1 of pipeline)."""
    return StructuredTool.from_function(
        func=_execute_cve_enrich,
        name="cve_enrich",
        description="Enrich a CVE with NVD, EPSS, and exploit data. Returns description, CVSS, CWE, affected products, EPSS score, exploit maturity. Use as Stage 1 before CVE→ATT&CK mapping.",
        args_schema=CVEEnrichmentInput,
    )
