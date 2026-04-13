"""
Standalone security intelligence LangChain tools (vendored from complianceskill).

Full ``TOOL_REGISTRY`` parity with ``app.agents.tools`` in complianceskill.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List

from langchain_core.tools import BaseTool

from asteraskills.tools.analysis_tools import (
    create_attack_path_builder_tool,
    create_remediation_prioritizer_tool,
    create_risk_calculator_tool,
)
from asteraskills.tools.api_tools import (
    create_cisa_kev_tool,
    create_cpe_lookup_tool,
    create_cve_intelligence_tool,
    create_epss_lookup_tool,
    create_github_advisory_tool,
)
from asteraskills.tools.attack_control_mapping import create_attack_control_mapping_tool
from asteraskills.tools.attack_tools import create_attack_technique_tool
from asteraskills.tools.base import SecurityTool, ToolResult
from asteraskills.tools.compliance_tools import (
    create_cis_benchmark_tool,
    create_framework_control_tool,
    create_gap_analysis_tool,
)
from asteraskills.tools.cve_attack_mapper import create_cve_to_attack_mapper_tool
from asteraskills.tools.cve_enrichment import create_cve_enrichment_tool
from asteraskills.tools.cwe_capec_cis_tools import (
    create_attack_stored_control_risk_tool,
    create_capec_lookup_tool,
    create_cis_controls_search_tool,
    create_cwe_lookup_tool,
    create_cwe_to_attack_intel_tool,
)
from asteraskills.tools.db_tools import create_cpe_resolver_tool, create_cve_to_attack_tool
from asteraskills.tools.exploit_tools import (
    create_exploit_db_tool,
    create_metasploit_module_tool,
    create_nuclei_template_tool,
)
from asteraskills.tools.framework_item_retrieval import create_framework_item_retrieval_tool
from asteraskills.tools.tactic_contextualiser import create_tactic_contextualiser_tool
from asteraskills.tools.tavily_tool import create_tavily_search_tool
from asteraskills.tools.threat_intel_data_tools import (
    create_attack_enterprise_technique_db_tool,
    create_cisa_kev_db_tool,
    create_cwe_capec_attack_mappings_db_tool,
    create_nvd_cves_by_cwe_db_tool,
    create_semantic_attack_control_mapping_search_tool,
    create_semantic_attack_technique_search_tool,
    create_semantic_cwe_capec_attack_search_tool,
)
from asteraskills.tools.threat_intel_tools import create_otx_pulse_tool, create_virustotal_tool
from asteraskills.tools.cpe_enrichment import create_cpe_enrichment_tool
from asteraskills.tools.sbom_cve_context import create_sbom_cve_context_tool
from asteraskills.tools.related_cves_skill import create_related_cves_tool
from asteraskills.tools.security_ontology_tools import (
    SECURITY_ONTOLOGY_TOOL_REGISTRY,
    make_security_ontology_search as create_security_ontology_search_tool,
)
from asteraskills.tools.detection_tools import (
    DETECTION_TOOL_REGISTRY,
    make_detection_scenario_search as create_detection_scenario_search_tool,
    make_kill_chain_builder as create_kill_chain_builder_tool,
    make_priority_score_calculator as create_priority_score_calculator_tool,
    make_cpe_investigation_guide as create_cpe_investigation_guide_tool,
    make_detection_query_builder as create_detection_query_builder_tool,
    make_cvss_vector_explainer as create_cvss_vector_explainer_tool,
    make_detection_playbook_search as create_detection_playbook_search_tool,
    make_list_playbook_data_sources as create_list_playbook_data_sources_tool,
    make_synthesize_playbook as create_synthesize_playbook_tool,
)

__all__ = [
    "ToolResult",
    "SecurityTool",
    "create_cpe_enrichment_tool",
    "create_sbom_cve_context_tool",
    "create_related_cves_tool",
    "create_cve_intelligence_tool",
    "create_epss_lookup_tool",
    "create_cisa_kev_tool",
    "create_github_advisory_tool",
    "create_cpe_lookup_tool",
    "create_cve_to_attack_tool",
    "create_attack_control_mapping_tool",
    "create_cpe_resolver_tool",
    "create_exploit_db_tool",
    "create_metasploit_module_tool",
    "create_nuclei_template_tool",
    "create_attack_technique_tool",
    "create_framework_control_tool",
    "create_cis_benchmark_tool",
    "create_gap_analysis_tool",
    "create_otx_pulse_tool",
    "create_virustotal_tool",
    "create_attack_path_builder_tool",
    "create_risk_calculator_tool",
    "create_remediation_prioritizer_tool",
    "create_tavily_search_tool",
    "create_tactic_contextualiser_tool",
    "create_framework_item_retrieval_tool",
    "create_cve_enrichment_tool",
    "create_cve_to_attack_mapper_tool",
    "create_cwe_lookup_tool",
    "create_capec_lookup_tool",
    "create_cis_controls_search_tool",
    "create_cwe_to_attack_intel_tool",
    "create_attack_stored_control_risk_tool",
    "create_nvd_cves_by_cwe_db_tool",
    "create_cisa_kev_db_tool",
    "create_attack_enterprise_technique_db_tool",
    "create_semantic_attack_technique_search_tool",
    "create_semantic_attack_control_mapping_search_tool",
    "create_cwe_capec_attack_mappings_db_tool",
    "create_semantic_cwe_capec_attack_search_tool",
    "get_all_tools",
    "get_tools_by_category",
    "TOOL_REGISTRY",
    "DETECTION_TOOL_REGISTRY",
    "create_detection_scenario_search_tool",
    "create_kill_chain_builder_tool",
    "create_priority_score_calculator_tool",
    "create_cpe_investigation_guide_tool",
    "create_detection_query_builder_tool",
    "create_cvss_vector_explainer_tool",
    "create_detection_playbook_search_tool",
    "create_list_playbook_data_sources_tool",
    "create_synthesize_playbook_tool",
    "create_security_ontology_search_tool",
]

TOOL_REGISTRY: Dict[str, Callable[[], BaseTool]] = {
    "cve_details": create_cve_intelligence_tool,
    "cve_intelligence": create_cve_intelligence_tool,
    "epss_lookup": create_epss_lookup_tool,
    "cisa_kev_check": create_cisa_kev_tool,
    "github_advisory_search": create_github_advisory_tool,
    "cpe_lookup": create_cpe_lookup_tool,
    "exploit_db_search": create_exploit_db_tool,
    "metasploit_module_search": create_metasploit_module_tool,
    "nuclei_template_search": create_nuclei_template_tool,
    "attack_technique_lookup": create_attack_technique_tool,
    "cve_to_attack_mapper": create_cve_to_attack_tool,
    "attack_to_control_mapper": create_attack_control_mapping_tool,
    "attack_control_map": create_attack_control_mapping_tool,
    "attack_tactic_contextualise": create_tactic_contextualiser_tool,
    "framework_item_retrieval": create_framework_item_retrieval_tool,
    "cve_enrich": create_cve_enrichment_tool,
    "cve_to_attack_map": create_cve_to_attack_mapper_tool,
    "cpe_resolver": create_cpe_resolver_tool,
    "framework_control_search": create_framework_control_tool,
    "cis_benchmark_lookup": create_cis_benchmark_tool,
    "gap_analysis": create_gap_analysis_tool,
    "otx_pulse_search": create_otx_pulse_tool,
    "virustotal_lookup": create_virustotal_tool,
    "cwe_lookup": create_cwe_lookup_tool,
    "capec_lookup": create_capec_lookup_tool,
    "cwe_to_attack_intel": create_cwe_to_attack_intel_tool,
    "cis_controls_search": create_cis_controls_search_tool,
    "attack_stored_control_risk": create_attack_stored_control_risk_tool,
    "nvd_cves_by_cwe_db": create_nvd_cves_by_cwe_db_tool,
    "cisa_kev_db": create_cisa_kev_db_tool,
    "attack_enterprise_technique_db": create_attack_enterprise_technique_db_tool,
    "semantic_attack_technique_search": create_semantic_attack_technique_search_tool,
    "semantic_attack_control_mapping_search": create_semantic_attack_control_mapping_search_tool,
    "cwe_capec_attack_mappings_db": create_cwe_capec_attack_mappings_db_tool,
    "semantic_cwe_capec_attack_search": create_semantic_cwe_capec_attack_search_tool,
    "attack_path_builder": create_attack_path_builder_tool,
    "risk_calculator": create_risk_calculator_tool,
    "remediation_prioritizer": create_remediation_prioritizer_tool,
    "tavily_search": create_tavily_search_tool,
    # Capability 1: CPE enrichment (Stage 1.5)
    "cpe_enrich_stage15": create_cpe_enrichment_tool,
    # Capability 2: SBOM CVE attribution
    "sbom_cve_context": create_sbom_cve_context_tool,
    # Capability 3: intent-routed related CVEs
    "related_cves": create_related_cves_tool,
    # Detection analysis tools (CVE alert investigation)
    **DETECTION_TOOL_REGISTRY,
    **SECURITY_ONTOLOGY_TOOL_REGISTRY,
}


def get_all_tools() -> List[BaseTool]:
    tools: List[BaseTool] = []
    log = logging.getLogger(__name__)
    for name, factory in TOOL_REGISTRY.items():
        try:
            tools.append(factory())
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to load tool %s: %s", name, exc)
    return tools


def get_tools_by_category(category: str) -> List[BaseTool]:
    category_map = {
        "api": [
            "cve_intelligence",
            "epss_lookup",
            "cisa_kev_check",
            "github_advisory_search",
            "cpe_lookup",
        ],
        "database": [
            "cve_to_attack_mapper",
            "attack_to_control_mapper",
            "cpe_resolver",
            "framework_control_search",
            "cwe_lookup",
            "capec_lookup",
            "cwe_to_attack_intel",
            "attack_stored_control_risk",
            "nvd_cves_by_cwe_db",
            "cisa_kev_db",
            "attack_enterprise_technique_db",
            "cwe_capec_attack_mappings_db",
        ],
        "exploit": [
            "exploit_db_search",
            "metasploit_module_search",
            "nuclei_template_search",
        ],
        "compliance": [
            "framework_control_search",
            "cis_benchmark_lookup",
            "gap_analysis",
            "cis_controls_search",
        ],
        "threat_intel": [
            "otx_pulse_search",
            "virustotal_lookup",
            "cwe_lookup",
            "capec_lookup",
            "cwe_to_attack_intel",
            "nvd_cves_by_cwe_db",
            "cisa_kev_db",
            "attack_enterprise_technique_db",
            "semantic_attack_technique_search",
            "semantic_attack_control_mapping_search",
            "cwe_capec_attack_mappings_db",
            "semantic_cwe_capec_attack_search",
        ],
        "attack": [
            "attack_technique_lookup",
            "cve_to_attack_mapper",
            "attack_to_control_mapper",
            "attack_stored_control_risk",
            "cwe_to_attack_intel",
            "attack_enterprise_technique_db",
            "semantic_attack_technique_search",
            "semantic_attack_control_mapping_search",
            "semantic_cwe_capec_attack_search",
        ],
        "analysis": [
            "attack_path_builder",
            "risk_calculator",
            "remediation_prioritizer",
        ],
        "search": [
            "tavily_search",
            "semantic_attack_technique_search",
            "semantic_attack_control_mapping_search",
            "semantic_cwe_capec_attack_search",
        ],
    }
    names = category_map.get(category, [])
    out: List[BaseTool] = []
    log = logging.getLogger(__name__)
    for name in names:
        if name not in TOOL_REGISTRY:
            continue
        try:
            out.append(TOOL_REGISTRY[name]())
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to load tool %s: %s", name, exc)
    return out
