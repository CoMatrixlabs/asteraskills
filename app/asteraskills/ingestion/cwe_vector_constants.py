"""Constants for CWE→CAPEC→ATT&CK vector search (replaces cwe_capec_attack_vector_ingest import)."""

from __future__ import annotations

ENTITY_TYPE = "cwe_capec_attack"


def cwe_capec_attack_collection_name() -> str:
    from asteraskills.storage.collections import vector_collection

    return vector_collection("threat_intel_cwe_capec_attack_mappings")
