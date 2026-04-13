"""
MITRE ATT&CK framework tools.
These tools query ATT&CK technique data and mappings.

Fetches and parses MITRE ATT&CK STIX data for technique IDs.
Production path:
  1. Download enterprise-attack.json once → ingest into Postgres (attack_techniques table)
  2. All lookups query Postgres; GitHub fetch is the cold-start fallback.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import ToolResult, SecurityTool

logger = logging.getLogger(__name__)


# ============================================================================
# STIX source
# ============================================================================

STIX_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack-14.1.json"
)


# ============================================================================
# Input schemas
# ============================================================================

class ATTACKEnrichInput(BaseModel):
    technique_id: str = Field(
        description=(
            "MITRE ATT&CK technique or sub-technique ID, e.g. 'T1059' or 'T1059.001'."
        )
    )


class ATTACKTechniqueInput(BaseModel):
    """Input schema for ATT&CK technique lookup tool."""
    technique_id: str = Field(description="ATT&CK technique ID (e.g., T1003.001)")


# ============================================================================
# Result dataclass
# ============================================================================

def _tactics_to_kill_chain_phases(tactics: List[str]) -> List[str]:
    """Convert title-cased tactic labels to kill_chain_phases slugs (lowercase, hyphens)."""
    return [
        t.lower().replace(" ", "-")
        for t in (tactics or [])
        if t
    ]


class ATTACKTechniqueDetail(BaseModel):
    """Enriched detail from MITRE ATT&CK STIX data."""
    technique_id: str
    name: str
    description: str
    tactics: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    mitigations: List[Dict[str, str]] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    detection: str = ""
    kill_chain_phases: List[str] = Field(default_factory=list)
    tactic_contexts: Dict[str, str] = Field(default_factory=dict)  # tactic slug -> tactic_risk_lens
    url: str = ""


# ============================================================================
# In-process STIX cache (avoids repeated large JSON downloads)
# ============================================================================

_STIX_BUNDLE_CACHE: Optional[Dict[str, Any]] = None


def _load_stix_bundle() -> Dict[str, Any]:
    global _STIX_BUNDLE_CACHE
    if _STIX_BUNDLE_CACHE is not None:
        return _STIX_BUNDLE_CACHE

    logger.info("Downloading ATT&CK STIX bundle …")
    resp = requests.get(STIX_ENTERPRISE_URL, timeout=60)
    resp.raise_for_status()
    _STIX_BUNDLE_CACHE = resp.json()
    logger.info(f"Loaded {len(_STIX_BUNDLE_CACHE.get('objects', []))} STIX objects")
    return _STIX_BUNDLE_CACHE


def _extract_attack_id(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Pull the T-number from external_references."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_url(stix_obj: Dict[str, Any]) -> str:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


# ============================================================================
# Core enrichment logic
# ============================================================================

class ATTACKEnrichmentTool:
    """Fetches full ATT&CK technique metadata from STIX bundle."""

    def __init__(self, use_postgres: bool = False, pg_dsn: Optional[str] = None):
        self.use_postgres = use_postgres
        self.pg_dsn = pg_dsn
        self._local_cache: Dict[str, ATTACKTechniqueDetail] = {}

    def get_technique(self, technique_id: str) -> ATTACKTechniqueDetail:
        tid = technique_id.strip().upper()

        # 1. Hot cache
        if tid in self._local_cache:
            return self._local_cache[tid]

        # 2. Postgres (if configured)
        if self.use_postgres:
            result = self._query_postgres(tid)
            if result:
                self._local_cache[tid] = result
                return result

        # 3. STIX bundle
        result = self._parse_from_stix(tid)
        self._local_cache[tid] = result
        return result

    def _parse_from_stix(self, technique_id: str) -> ATTACKTechniqueDetail:
        bundle = _load_stix_bundle()
        objects = bundle.get("objects", [])

        technique_map: Dict[str, Dict] = {}
        mitigation_map: Dict[str, str] = {}
        relationship_list: List[Dict] = []

        for obj in objects:
            obj_type = obj.get("type", "")
            aid = _extract_attack_id(obj)

            if obj_type == "attack-pattern" and aid:
                technique_map[aid] = obj
            elif obj_type == "course-of-action" and aid:
                mitigation_map[obj["id"]] = obj.get("name", aid)
            elif obj_type == "relationship":
                relationship_list.append(obj)

        if technique_id not in technique_map:
            return ATTACKTechniqueDetail(
                technique_id=technique_id,
                name=f"Unknown technique {technique_id}",
                description="Technique not found in ATT&CK bundle.",
            )

        obj = technique_map[technique_id]

        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        detection = obj.get("x_mitre_detection", "")

        mitigations: List[Dict[str, str]] = []
        for rel in relationship_list:
            if (
                rel.get("relationship_type") == "mitigates"
                and rel.get("target_ref") == obj["id"]
            ):
                src_id = rel.get("source_ref", "")
                mit_name = mitigation_map.get(src_id, src_id)
                mit_attack_id = _extract_attack_id(
                    next((o for o in objects if o.get("id") == src_id), {})
                ) or ""
                mitigations.append({"id": mit_attack_id, "name": mit_name})

        return ATTACKTechniqueDetail(
            technique_id=technique_id,
            name=obj.get("name", technique_id),
            description=obj.get("description", ""),
            tactics=tactics,
            platforms=platforms,
            mitigations=mitigations,
            data_sources=data_sources,
            detection=detection,
            kill_chain_phases=[p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            url=_extract_url(obj),
        )

    def _query_postgres(self, technique_id: str) -> Optional[ATTACKTechniqueDetail]:
        """Query pre-ingested ATT&CK table."""
        try:
            import psycopg2
            import psycopg2.extras

            conn = psycopg2.connect(self.pg_dsn)
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT * FROM attack_techniques WHERE technique_id = %s",
                (technique_id,),
            )
            row = cur.fetchone()
            conn.close()

            if row:
                tactics = row["tactics"] or []
                kill_chain_phases = _tactics_to_kill_chain_phases(tactics)
                return ATTACKTechniqueDetail(
                    technique_id=row["technique_id"],
                    name=row["name"],
                    description=row["description"],
                    tactics=tactics,
                    platforms=row["platforms"] or [],
                    data_sources=row["data_sources"] or [],
                    detection=row["detection"] or "",
                    mitigations=row["mitigations"] or [],
                    kill_chain_phases=kill_chain_phases,
                    url=row["url"] or "",
                )
        except Exception as e:
            logger.warning(f"Postgres ATT&CK lookup failed: {e}")
        return None


# ============================================================================
# SecurityTool wrapper (for agent registry)
# ============================================================================

class ATTACKTechniqueTool(SecurityTool):
    """
    Lookup MITRE ATT&CK technique details.
    Uses ATTACKEnrichmentTool for full STIX-based enrichment.
    """

    def __init__(self, use_postgres: bool = False, pg_dsn: Optional[str] = None):
        self._enricher = ATTACKEnrichmentTool(use_postgres=use_postgres, pg_dsn=pg_dsn)

    @property
    def tool_name(self) -> str:
        return "attack_technique_lookup"

    def cache_key(self, **kwargs) -> str:
        technique_id = kwargs.get("technique_id", "")
        return f"attack_technique:{technique_id}"

    def execute(self, technique_id: str) -> ToolResult:
        """Execute ATT&CK technique lookup."""
        try:
            detail = self._enricher.get_technique(technique_id)
            return ToolResult(
                success=True,
                data=detail.model_dump(),
                source="attack_stix",
                timestamp=datetime.utcnow().isoformat(),
            )
        except Exception as e:
            logger.error(f"Error in ATT&CK technique lookup: {e}")
            return ToolResult(
                success=False,
                data=None,
                source="attack_stix",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e),
            )


# ============================================================================
# LangChain tool factories
# ============================================================================

def create_attack_technique_tool() -> StructuredTool:
    """Create LangChain tool for ATT&CK technique lookup."""
    tool_instance = ATTACKTechniqueTool()

    def _execute(technique_id: str) -> Dict[str, Any]:
        result = tool_instance.execute(technique_id)
        return result.to_dict()

    return StructuredTool.from_function(
        func=_execute,
        name="attack_technique_lookup",
        description="Lookup MITRE ATT&CK technique details including description, tactics, platforms, and mitigations. Returns comprehensive information about the attack technique.",
        args_schema=ATTACKTechniqueInput,
    )


def create_attack_enrichment_tool(
    use_postgres: bool = False,
    pg_dsn: Optional[str] = None,
) -> StructuredTool:
    """
    Returns a LangChain StructuredTool for ATT&CK technique enrichment.
    Wire `use_postgres=True` + `pg_dsn` to avoid GitHub fetches in production.
    """
    tool_instance = ATTACKEnrichmentTool(use_postgres=use_postgres, pg_dsn=pg_dsn)

    def _execute(technique_id: str) -> Dict[str, Any]:
        try:
            detail = tool_instance.get_technique(technique_id)
            return detail.model_dump()
        except Exception as exc:
            logger.error(f"ATTACKEnrichmentTool error: {exc}")
            return {"error": str(exc), "technique_id": technique_id}

    return StructuredTool.from_function(
        func=_execute,
        name="attack_technique_enrich",
        description=(
            "Fetch full MITRE ATT&CK technique metadata (name, description, tactics, "
            "platforms, data sources, mitigations, detection notes) for a given "
            "technique or sub-technique ID such as 'T1059.001'."
        ),
        args_schema=ATTACKEnrichInput,
    )


# ============================================================================
# One-shot STIX → Postgres ingestor
# ============================================================================

def ingest_stix_to_postgres(
    pg_dsn: str,
    vector_store_config: Optional[Any] = None,
) -> int:
    """
    Download ATT&CK STIX bundle and upsert all techniques into Postgres.
    Optionally ingest into vector store for semantic search.

    When vector_store_config is provided:
    - Ingests to both Postgres and vector store
    - Uses enricher for each technique (ensures full metadata including description)
    - If description is empty from STIX, the enricher provides best available data

    Call once during bootstrapping. Returns number of rows upserted to Postgres.
    """
    import psycopg2

    tool = ATTACKEnrichmentTool()
    bundle = _load_stix_bundle()
    objects = bundle.get("objects", [])

    rows = 0
    techniques_for_vs: List[Dict[str, Any]] = []

    conn = psycopg2.connect(pg_dsn)
    cur = conn.cursor()

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        aid = _extract_attack_id(obj)
        if not aid:
            continue
        detail = tool._parse_from_stix(aid)
        # Use enricher to ensure we have best available description
        if not (detail.description or "").strip():
            enriched = tool.get_technique(aid)
            detail = enriched
        cur.execute(
            """
            INSERT INTO attack_techniques
              (technique_id, name, description, tactics, platforms,
               data_sources, detection, mitigations, url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (technique_id) DO UPDATE SET
              name        = EXCLUDED.name,
              description = EXCLUDED.description,
              tactics     = EXCLUDED.tactics,
              platforms   = EXCLUDED.platforms,
              data_sources = EXCLUDED.data_sources,
              detection   = EXCLUDED.detection,
              mitigations = EXCLUDED.mitigations,
              url         = EXCLUDED.url
            """,
            (
                detail.technique_id,
                detail.name,
                detail.description,
                detail.tactics,
                detail.platforms,
                detail.data_sources,
                detail.detection,
                json.dumps(detail.mitigations),
                detail.url,
            ),
        )
        rows += 1

        if vector_store_config:
            techniques_for_vs.append({
                "technique_id": detail.technique_id,
                "name": detail.name,
                "description": detail.description or "",
                "tactics": detail.tactics,
                "platforms": detail.platforms,
                "data_sources": detail.data_sources,
                "detection": detail.detection or "",
                "url": detail.url or "",
            })

    conn.commit()
    conn.close()
    logger.info(f"Ingested {rows} ATT&CK techniques into Postgres")

    if vector_store_config and techniques_for_vs:
        from asteraskills.ingestion.attack_vector_ingest import ingest_attack_techniques

        vs_count = ingest_attack_techniques(techniques_for_vs, vector_store_config)
        logger.info(
            "Ingested %s ATT&CK techniques into vector store [%s] (stub returns 0 unless overridden)",
            vs_count,
            getattr(vector_store_config, "collection", vector_store_config),
        )

    return rows
