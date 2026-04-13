"""
Default framework IDs for the CVE → ATT&CK → control pipeline.

Aligned with `data/.../risk_control_yaml` folder names (same scope as
`control_taxonomy_enriched` / enrich_control_taxonomy) and ingestion adapters
(`app.ingestion.frameworks.ADAPTER_REGISTRY` metadata `framework_id`).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

# risk_control_yaml directory name -> framework_id on framework_items / retrieval
YAML_FOLDER_TO_PIPELINE_FRAMEWORK_ID: dict[str, str] = {
    "cis_controls_v8_1": "cis_v8_1",
    "nist_csf_2_0": "nist_csf_2_0",
    "hipaa": "hipaa",
    "soc2": "soc2",
    "iso27001_2022": "iso27001",
    "iso27001_2013": "iso27001",
}


def yaml_folders_for_pipeline_framework_id(framework_id: str) -> List[str]:
    """
    Map pipeline framework_id (e.g. cis_v8_1, stored in Qdrant/metadata) to
    risk_control_yaml directory name(s) under framework_helper.DEFAULT_BASE_PATH.
    """
    folders = [folder for folder, fid in YAML_FOLDER_TO_PIPELINE_FRAMEWORK_ID.items() if fid == framework_id]
    if not folders:
        if framework_id in YAML_FOLDER_TO_PIPELINE_FRAMEWORK_ID:
            return [framework_id]
        return []
    if framework_id == "iso27001":
        for pref in ("iso27001_2022", "iso27001_2013"):
            if pref in folders:
                return [pref]
    return [folders[0]]

# Stable default order when multiple folders map to the same pipeline id (e.g. ISO 2013 + 2022)
_PREFERRED_ORDER: List[str] = [
    "cis_v8_1",
    "nist_csf_2_0",
    "hipaa",
    "soc2",
    "iso27001",
]


def default_pipeline_framework_ids(base_path: Optional[Union[Path, str]] = None) -> List[str]:
    """
    Return framework IDs to use for Stage 3 when the user does not pass --frameworks.

    Discovers folders under risk_control_yaml (via framework_helper) and maps them
    to the IDs stored during framework item ingestion. Falls back to the full
    preferred set if the YAML tree is missing (e.g. CI).
    """
    try:
        from app.ingestion.attacktocve.framework_helper import list_frameworks
    except Exception:
        return list(_PREFERRED_ORDER)

    try:
        discovered = set(list_frameworks(base_path))
    except Exception:
        discovered = set()

    mapped: set[str] = set()
    for folder, fid in YAML_FOLDER_TO_PIPELINE_FRAMEWORK_ID.items():
        if folder in discovered:
            mapped.add(fid)

    if not mapped:
        return list(_PREFERRED_ORDER)

    ordered = [fid for fid in _PREFERRED_ORDER if fid in mapped]
    extras = sorted(mapped - set(ordered))
    return ordered + extras
