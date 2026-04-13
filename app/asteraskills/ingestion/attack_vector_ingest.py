"""
Optional hook for bulk ATT&CK → vector ingest.

The full ``vectorstore_retrieval`` pipeline lives in complianceskill; this stub keeps
``attack_tools.bulk_ingest_attack_techniques_to_postgres`` importable without that tree.
Replace with a real implementation if you need server-side vector upserts from the CLI.
"""

from __future__ import annotations

from typing import Any, Dict, List


def ingest_attack_techniques(
    techniques: List[Dict[str, Any]],
    vector_store_config: Any,
) -> int:
    return 0
