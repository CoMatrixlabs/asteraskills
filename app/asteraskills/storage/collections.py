"""
Consolidated collections registry (aligned with complianceskill ``app/storage/collections.py``,
minus MDL/LEEN/CSOD collections — not used in asteraskills).

Security-intel call sites use ``vector_collection()`` / ``*.items()``, ``*.techniques()``, etc., so
``ATTACK_TECHNIQUES_COLLECTION``, ``ATTACK_CONTROL_MAPPINGS_COLLECTION``, and
``THREAT_INTEL_CWE_CAPEC_ATTACK_COLLECTION`` from settings can override the default names.
"""

from __future__ import annotations

from typing import Any, Dict, List


def vector_collection(canonical: str) -> str:
    """
    Resolve the live vector-store name for a canonical base string.

    Only ``attack_techniques``, ``attack_control_mappings``, and
    ``threat_intel_cwe_capec_attack_mappings`` consult settings; all other inputs are returned
    unchanged.
    """
    from asteraskills.config.settings import get_settings

    s = get_settings()
    if canonical == "attack_techniques":
        return s.ATTACK_TECHNIQUES_COLLECTION
    if canonical == "attack_control_mappings":
        return s.ATTACK_CONTROL_MAPPINGS_COLLECTION
    if canonical == "threat_intel_cwe_capec_attack_mappings":
        return s.THREAT_INTEL_CWE_CAPEC_ATTACK_COLLECTION
    if canonical == "security_ontology":
        return s.SECURITY_ONTOLOGY_COLLECTION
    return canonical


def _resolved_map(names: List[str]) -> Dict[str, str]:
    """Build ``{resolved: resolved}`` for active-collection registries."""
    return {vector_collection(n): vector_collection(n) for n in names}


class FrameworkCollections:
    """Framework knowledge base collections (Qdrant) — same names as complianceskill."""

    CONTROLS = "framework_controls"
    REQUIREMENTS = "framework_requirements"
    RISKS = "framework_risks"
    TEST_CASES = "framework_test_cases"
    SCENARIOS = "framework_scenarios"
    ITEMS = "framework_items"
    USER_POLICIES = "user_policies"

    ALL = [
        CONTROLS,
        REQUIREMENTS,
        RISKS,
        TEST_CASES,
        SCENARIOS,
        ITEMS,
        USER_POLICIES,
    ]
    ALL_FRAMEWORK = [
        CONTROLS,
        REQUIREMENTS,
        RISKS,
        TEST_CASES,
        SCENARIOS,
        ITEMS,
    ]

    @staticmethod
    def controls() -> str:
        return vector_collection(FrameworkCollections.CONTROLS)

    @staticmethod
    def requirements() -> str:
        return vector_collection(FrameworkCollections.REQUIREMENTS)

    @staticmethod
    def risks() -> str:
        return vector_collection(FrameworkCollections.RISKS)

    @staticmethod
    def test_cases() -> str:
        return vector_collection(FrameworkCollections.TEST_CASES)

    @staticmethod
    def scenarios() -> str:
        return vector_collection(FrameworkCollections.SCENARIOS)

    @staticmethod
    def items() -> str:
        return vector_collection(FrameworkCollections.ITEMS)

    @staticmethod
    def user_policies() -> str:
        return vector_collection(FrameworkCollections.USER_POLICIES)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in FrameworkCollections.ALL]

    @staticmethod
    def all_framework_names() -> list[str]:
        return [vector_collection(n) for n in FrameworkCollections.ALL_FRAMEWORK]


class KevCollections:
    """CISA Known Exploited Vulnerabilities catalog (Qdrant), populated by ``cisa_kev_qdrant_ingest``."""

    CISA_CATALOG = "cisa_kev"


class XSOARCollections:
    """XSOAR enriched collections (Qdrant/ChromaDB) — complianceskill registry."""

    ENRICHED = "xsoar_enriched"

    ALL = [ENRICHED]

    class EntityType:
        PLAYBOOK = "playbook"
        DASHBOARD = "dashboard"
        SCRIPT = "script"
        INTEGRATION = "integration"
        INDICATOR = "indicator"


class AttackCollections:
    """ATT&CK security intelligence collections — complianceskill names + resolved helpers."""

    TECHNIQUES = "attack_techniques"
    TACTIC_CONTEXTS = "attack_tactic_contexts"
    CONTROL_MAPPINGS = "attack_control_mappings"

    ALL = [TECHNIQUES, TACTIC_CONTEXTS, CONTROL_MAPPINGS]

    @staticmethod
    def techniques() -> str:
        return vector_collection(AttackCollections.TECHNIQUES)

    @staticmethod
    def tactic_contexts() -> str:
        return vector_collection(AttackCollections.TACTIC_CONTEXTS)

    @staticmethod
    def control_mappings() -> str:
        return vector_collection(AttackCollections.CONTROL_MAPPINGS)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in AttackCollections.ALL]


class ThreatIntelCollections:
    """CWE/CAPEC threat intelligence — complianceskill names + resolved helpers."""

    CWE_CAPEC = "threat_intel_cwe_capec"
    CWE_CAPEC_ATTACK_MAPPINGS = "threat_intel_cwe_capec_attack_mappings"

    ALL = [CWE_CAPEC, CWE_CAPEC_ATTACK_MAPPINGS]

    @staticmethod
    def cwe_capec() -> str:
        return vector_collection(ThreatIntelCollections.CWE_CAPEC)

    @staticmethod
    def cwe_capec_attack_mappings() -> str:
        return vector_collection(ThreatIntelCollections.CWE_CAPEC_ATTACK_MAPPINGS)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in ThreatIntelCollections.ALL]


class CveVectorCollections:
    """
    CVE description embeddings (Qdrant) — populated by ``cve_vector_sync``.
    Required for Capability 3 full composite scoring (description similarity).
    """

    CVE_VECTORS = "cve_vectors"
    CPE_NAMES = "cpe_names"

    ALL = [CVE_VECTORS, CPE_NAMES]

    @staticmethod
    def cve_vectors() -> str:
        return vector_collection(CveVectorCollections.CVE_VECTORS)

    @staticmethod
    def cpe_names() -> str:
        return vector_collection(CveVectorCollections.CPE_NAMES)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in CveVectorCollections.ALL]


class LLMSafetyCollections:
    """LLM safety collections (Qdrant) — complianceskill registry."""

    SAFETY = "llm_safety"

    ALL = [SAFETY]

    class EntityType:
        TECHNIQUE = "technique"
        MITIGATION = "mitigation"
        DETECTION_RULE = "detection_rule"


class ComprehensiveIndexingCollections:
    """
    Comprehensive indexing collections — complianceskill registry
    (contextual graph / workforce assistants; schema subsets unprefixed when prefixed elsewhere).
    """

    DOMAIN_KNOWLEDGE = "domain_knowledge"

    COMPLIANCE_CONTROLS = "compliance_controls"
    ENTITIES = "entities"
    EVIDENCE = "evidence"
    FIELDS = "fields"
    CONTROLS = "controls"

    POLICY_DOCUMENTS = "policy_documents"

    TABLE_DEFINITIONS = "table_definitions"
    TABLE_DESCRIPTIONS = "table_descriptions"
    COLUMN_DEFINITIONS = "column_definitions"
    SCHEMA_DESCRIPTIONS = "schema_descriptions"

    FEATURES = "features"

    CONTEXTUAL_EDGES = "contextual_edges"

    UNPREFIXED_SCHEMA_COLLECTIONS = {
        TABLE_DEFINITIONS,
        TABLE_DESCRIPTIONS,
        COLUMN_DEFINITIONS,
        SCHEMA_DESCRIPTIONS,
        "db_schema",
        "column_metadata",
    }

    ALL = [
        DOMAIN_KNOWLEDGE,
        COMPLIANCE_CONTROLS,
        ENTITIES,
        EVIDENCE,
        FIELDS,
        CONTROLS,
        POLICY_DOCUMENTS,
        TABLE_DEFINITIONS,
        TABLE_DESCRIPTIONS,
        COLUMN_DEFINITIONS,
        SCHEMA_DESCRIPTIONS,
        FEATURES,
        CONTEXTUAL_EDGES,
    ]


class ComplianceSkillCollections:
    """
    Consolidated view of complianceskill collection groups.

    ``ACTIVE_COLLECTIONS`` values are **resolved** (settings overrides apply to ATT&CK / mapping
    collection names). Keys match values for stable lookup.
    """

    ACTIVE_COLLECTIONS = {
        **_resolved_map(FrameworkCollections.ALL),
        **_resolved_map(XSOARCollections.ALL),
        **_resolved_map(AttackCollections.ALL),
        **_resolved_map(ThreatIntelCollections.ALL),
        **_resolved_map(LLMSafetyCollections.ALL),
    }

    @staticmethod
    def get_all_active_collections() -> List[str]:
        return list(ComplianceSkillCollections.ACTIVE_COLLECTIONS.keys())

    @staticmethod
    def get_framework_collections() -> List[str]:
        return list(FrameworkCollections.ALL)

    @staticmethod
    def get_xsoar_collections() -> List[str]:
        return list(XSOARCollections.ALL)

    @staticmethod
    def get_llm_safety_collections() -> List[str]:
        return list(LLMSafetyCollections.ALL)

    @staticmethod
    def get_comprehensive_indexing_collections() -> List[str]:
        return list(ComprehensiveIndexingCollections.ALL)

    @staticmethod
    def is_collection_active(collection_name: str) -> bool:
        return collection_name in ComplianceSkillCollections.ACTIVE_COLLECTIONS

    @staticmethod
    def get_collection_info() -> Dict[str, Any]:
        return {
            "framework_kb": {
                "collections": FrameworkCollections.ALL,
                "description": "Framework Knowledge Base collections (Qdrant)",
                "accessed_via": "RetrievalService",
                "count": len(FrameworkCollections.ALL),
            },
            "xsoar": {
                "collections": XSOARCollections.ALL,
                "description": "XSOAR enriched collections (Qdrant/ChromaDB)",
                "accessed_via": "XSOARRetrievalService",
                "count": len(XSOARCollections.ALL),
            },
            "llm_safety": {
                "collections": LLMSafetyCollections.ALL,
                "description": (
                    "LLM Safety collections (Qdrant) - SAFE-MCP techniques and mitigations"
                ),
                "accessed_via": "LLMSafetyRetrievalService",
                "count": len(LLMSafetyCollections.ALL),
            },
            "comprehensive_indexing": {
                "collections": ComprehensiveIndexingCollections.ALL,
                "description": "Comprehensive indexing collections (used by workforce assistants)",
                "accessed_via": "CollectionFactory",
                "count": len(ComprehensiveIndexingCollections.ALL),
                "note": "May have collection_prefix applied (schema collections are unprefixed)",
            },
            "attack_mapping": {
                "collections": AttackCollections.ALL,
                "description": (
                    "ATT&CK techniques, tactic contexts, and technique→control mapping vectors "
                    "for semantic search"
                ),
                "accessed_via": (
                    "TacticContextualiserTool, FrameworkItemRetrievalTool, scenario ingest"
                ),
                "count": len(AttackCollections.ALL),
            },
            "threat_intel": {
                "collections": ThreatIntelCollections.ALL,
                "description": (
                    "CWE/CAPEC threat intelligence and CWE→CAPEC→ATT&CK mapping vectors "
                    "for semantic search"
                ),
                "accessed_via": (
                    "cwe_csv_ingest, capec_csv_ingest, cwe_enrich --vector-store, "
                    "indexing_cli.cwe_capec_attack_vector_ingest"
                ),
                "count": len(ThreatIntelCollections.ALL),
            },
            "summary": {
                "total_active": len(ComplianceSkillCollections.get_all_active_collections()),
                "total_comprehensive": len(ComprehensiveIndexingCollections.ALL),
                "total_all": (
                    len(FrameworkCollections.ALL)
                    + len(XSOARCollections.ALL)
                    + len(LLMSafetyCollections.ALL)
                    + len(ThreatIntelCollections.ALL)
                    + len(ComprehensiveIndexingCollections.ALL)
                ),
            },
        }


class OntologyCollections:
    """
    Security graph ontology schema (node types, edge types, enum members) in Qdrant.

    Ingest: ``python -m app.ingestion.security_ontology_ingest`` from the **complianceskill** repo.
    Runtime usage here should be **read-only** (semantic search only).
    """

    SECURITY_ONTOLOGY = "security_ontology"

    ALL = [SECURITY_ONTOLOGY]

    @staticmethod
    def security_ontology() -> str:
        return vector_collection(OntologyCollections.SECURITY_ONTOLOGY)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in OntologyCollections.ALL]


class DetectionCollections:
    """
    CVE detection scenario knowledge base (Qdrant).

    Populated by ``detection_scenarios_ingest`` from:
      - cve_detection_scenarios.md   (7 scenarios, CVE-2024-26855 worked example)
      - other_detection_usecases.md  (7 scenarios, Sentinel/KQL/CISA KEV automation)

    Two collections:
      SCENARIOS  — one document per Q&A pair, semantic search by question
      PLAYBOOKS  — structured procedure cards (decision trees, checklists, KQL templates)
    """

    SCENARIOS = "detection_scenarios"
    PLAYBOOKS = "detection_playbooks"

    ALL = [SCENARIOS, PLAYBOOKS]

    @staticmethod
    def scenarios() -> str:
        return vector_collection(DetectionCollections.SCENARIOS)

    @staticmethod
    def playbooks() -> str:
        return vector_collection(DetectionCollections.PLAYBOOKS)

    @staticmethod
    def all_names() -> list[str]:
        return [vector_collection(n) for n in DetectionCollections.ALL]

    class Domain:
        SECOPS = "secops"
        APPSEC = "appsec"
        VM = "vm"
        DETECTION_ENG = "detection_eng"
        ALL = [SECOPS, APPSEC, VM, DETECTION_ENG]

    class RoleLevel:
        JUNIOR = "junior"
        MID = "mid"
        SENIOR = "senior"


__all__ = [
    "vector_collection",
    "OntologyCollections",
    "FrameworkCollections",
    "KevCollections",
    "XSOARCollections",
    "AttackCollections",
    "ThreatIntelCollections",
    "CveVectorCollections",
    "LLMSafetyCollections",
    "ComprehensiveIndexingCollections",
    "ComplianceSkillCollections",
    "DetectionCollections",
]
