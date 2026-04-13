"""
PackClient — dual-mode licensed intelligence client.

Local mode (no license token):
  - retrieve_attack_mappings() delegates to asteraskills tools directly
  - retrieve_control_mappings() delegates to asteraskills tools directly
  - fetch_rules() returns empty dicts (no server-side rule packs)
  - retrieve_domain_signals() returns empty list (no pack index)

Remote mode (license token provided):
  - All methods call the licensed intelligence server REST API
  - JWT capability manifest enforces tenant/framework/tier claims
  - Etag-based caching for rule packs (stored in data/packs/)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_PACKS_DIR = Path(__file__).parent.parent / "data" / "packs"

# Local control mapping runs one heavy LLM pipeline per (technique × framework); cap to avoid hangs.
_MAX_LOCAL_CONTROL_TECHNIQUES = 5


class PackClient:
    def __init__(
        self,
        license_token: Optional[str] = None,
        server_url: str = "https://api.risk-scanner.io",
    ) -> None:
        self.license_token = license_token or os.environ.get("RISK_SCANNER_LICENSE_TOKEN")
        self.server_url = server_url.rstrip("/")
        self.local_mode = self.license_token is None
        self._session: Any = None  # requests.Session, lazy-init in remote mode

    # ------------------------------------------------------------------
    # Public API — used by classifier, analyzers, enrichment
    # ------------------------------------------------------------------

    def retrieve_domain_signals(self, artifact_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return embedding-matched domain signals for the domain classifier.

        Local mode: returns empty list (classifier falls back to keyword heuristics).
        Remote mode: POST /v1/classify/retrieve
        """
        if self.local_mode:
            return []
        return self._post("/v1/classify/retrieve", {
            "artifact_metadata": artifact_metadata,
            "top_k": 5,
        }).get("domain_signals", [])

    def fetch_rules(self, domain: str) -> Dict[str, Any]:
        """Fetch rule pack for a domain (with etag caching).

        Local mode: returns empty dict (static analyzers use built-in rules).
        Remote mode: GET /v1/packs/{domain}/rules with If-None-Match caching.
        """
        if self.local_mode:
            return {}
        cache_file = _PACKS_DIR / f"{domain}.json"
        etag_file = _PACKS_DIR / f"{domain}.etag"
        cached_etag = etag_file.read_text().strip() if etag_file.exists() else None
        headers = {}
        if cached_etag:
            headers["If-None-Match"] = cached_etag
        try:
            resp = self._get(f"/v1/packs/{domain}/rules", headers=headers)
            if resp.get("_status") == 304 and cache_file.exists():
                return json.loads(cache_file.read_text())
            etag = resp.get("etag")
            if etag:
                _PACKS_DIR.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(resp))
                etag_file.write_text(etag)
            return resp
        except Exception as exc:
            log.warning("Failed to fetch rules for domain %s: %s", domain, exc)
            return {}

    def retrieve_attack_mappings(
        self,
        source_domain: str,
        taxonomy_code: str,
        metadata: Optional[Dict[str, Any]] = None,
        top_k: int = 10,
    ) -> List[Dict[str, Any]]:
        """Retrieve CVE/CWE/Policy → ATT&CK technique mappings.

        Local mode: delegates to asteraskills tools.
        Remote mode: POST /v1/enrich/attack
        """
        if self.local_mode:
            return self._local_attack_mappings(source_domain, taxonomy_code, metadata or {})
        return self._post("/v1/enrich/attack", {
            "source_domain": source_domain,
            "taxonomy_code": taxonomy_code,
            "metadata": metadata or {},
            "top_k": top_k,
        }).get("mappings", [])

    def retrieve_control_mappings(
        self,
        technique_ids: List[str],
        frameworks: List[str],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Retrieve ATT&CK technique → framework control mappings.

        Local mode: delegates to asteraskills tools.
        Remote mode: POST /v1/enrich/controls
        """
        if self.local_mode:
            return self._local_control_mappings(technique_ids, frameworks)
        return self._post("/v1/enrich/controls", {
            "technique_ids": technique_ids,
            "frameworks": frameworks,
            "top_k": top_k,
        }).get("control_mappings", [])

    def llm_inference(
        self,
        prompt_id: str,
        variables: Dict[str, Any],
        retrieved_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call server-side LLM inference (licensed tier only).

        Local mode: returns empty dict (callers must use local get_llm()).
        Remote mode: POST /v1/inference
        """
        if self.local_mode:
            return {}
        return self._post("/v1/inference", {
            "prompt_id": prompt_id,
            "variables": variables,
            "retrieved_context": retrieved_context or {},
        }).get("result", {})

    # ------------------------------------------------------------------
    # Local-mode delegators (use asteraskills tools directly)
    # ------------------------------------------------------------------

    def _local_attack_mappings(
        self,
        source_domain: str,
        taxonomy_code: str,
        metadata: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Delegate to asteraskills CVE/CWE attack mapping tools."""
        try:
            if source_domain == "cve":
                from asteraskills.tools.cve_attack_mapper import _execute_cve_to_attack_map
                cve_detail = metadata.get("cve_detail", {"description": "", "cwe_ids": []})
                mappings = _execute_cve_to_attack_map(taxonomy_code, cve_detail)
                return [
                    {
                        "technique_id": m.get("technique_id", ""),
                        "similarity_score": 0.9 if m.get("confidence") == "high" else 0.7,
                        "source_taxonomy": taxonomy_code,
                        "mapping_type": "exact" if m.get("mapping_source") == "cwe_lookup" else "inferred",
                    }
                    for m in (mappings or [])
                ]
            elif source_domain == "cwe":
                from asteraskills.tools.cwe_capec_cis_tools import create_cwe_to_attack_intel_tool
                tool = create_cwe_to_attack_intel_tool()
                result = tool.invoke({"cwe_id": taxonomy_code})
                if isinstance(result, list):
                    return [
                        {"technique_id": r.get("technique_id", ""), "similarity_score": 0.8,
                         "source_taxonomy": taxonomy_code, "mapping_type": "exact"}
                        for r in result
                    ]
        except Exception as exc:
            log.warning("Local attack mapping failed for %s %s: %s", source_domain, taxonomy_code, exc)
        return []

    def _local_control_mappings(
        self,
        technique_ids: List[str],
        frameworks: List[str],
    ) -> List[Dict[str, Any]]:
        """Delegate to asteraskills ATT&CK→control mapping tools."""
        results = []
        for technique_id in technique_ids[:_MAX_LOCAL_CONTROL_TECHNIQUES]:
            for framework in frameworks:
                fw_id = _normalize_framework_id(framework)
                try:
                    from asteraskills.tools.attack_control_mapping import _execute_attack_control_map
                    mappings = _execute_attack_control_map(
                        technique_id=technique_id,
                        tactic="",
                        framework_id=fw_id,
                        top_k=5,
                        persist=False,
                    )
                    for m in (mappings or []):
                        title = (
                            (m.get("title") or "").strip()
                            or (m.get("control_objective") or "").strip()
                            or (m.get("risk_description") or "").strip()[:200]
                        )
                        results.append({
                            "technique_id": technique_id,
                            "control_id": m.get("item_id", ""),
                            "control_name": title,
                            "framework": framework,
                            "mapping_confidence": m.get("relevance_score", 0.7),
                            "rationale": m.get("rationale", ""),
                            "blast_radius": m.get("blast_radius", ""),
                            "gap_narrative": m.get("rationale", ""),
                        })
                except Exception as exc:
                    log.warning("Local control mapping failed for %s / %s: %s", technique_id, framework, exc)
        return results

    # ------------------------------------------------------------------
    # HTTP helpers (remote mode only)
    # ------------------------------------------------------------------

    def _get_session(self) -> Any:
        if self._session is None:
            import requests
            s = requests.Session()
            s.headers.update({
                "Authorization": f"Bearer {self.license_token}",
                "Content-Type": "application/json",
                "User-Agent": "risk-scanner/0.1.0",
            })
            self._session = s
        return self._session

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        try:
            resp = self._get_session().post(f"{self.server_url}{path}", json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.error("POST %s failed: %s", path, exc)
            return {}

    def _get(self, path: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        import requests
        try:
            resp = self._get_session().get(
                f"{self.server_url}{path}",
                headers=headers or {},
                timeout=30,
            )
            if resp.status_code == 304:
                return {"_status": 304}
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.error("GET %s failed: %s", path, exc)
            return {}


def _normalize_framework_id(framework: str) -> str:
    """Map user-facing framework names to asteraskills internal IDs."""
    mapping = {
        "cis-8": "cis_v8_1",
        "cis-8.1": "cis_v8_1",
        "cis": "cis_v8_1",
        "nist-800-53": "nist_800_53r5",
        "nist": "nist_800_53r5",
        "soc2": "soc2_2017",
        "iso27001": "iso_27001_2022",
        "iso-27001": "iso_27001_2022",
    }
    return mapping.get(framework.lower(), framework)
