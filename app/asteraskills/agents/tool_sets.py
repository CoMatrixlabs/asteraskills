"""
Map specialist domains to ``TOOL_REGISTRY`` keys (Astera security intelligence).
"""

from __future__ import annotations

from typing import Dict, List

# Keys must exist in ``asteraskills.tools.TOOL_REGISTRY``.
CVE_TOOL_KEYS: List[str] = [
    "cve_intelligence",
    "epss_lookup",
    "cisa_kev_check",
    "github_advisory_search",
    "cpe_lookup",
    "cve_enrich",
    "cve_to_attack_map",
    "cve_to_attack_mapper",
    "cpe_resolver",
    "exploit_db_search",
    "metasploit_module_search",
    "nuclei_template_search",
    "nvd_cves_by_cwe_db",
    "cisa_kev_db",
    "tavily_search",
    # Capability 1 — CPE enrichment (Stage 1.5)
    "cpe_enrich_stage15",
    # Capability 2 — SBOM CVE attribution
    "sbom_cve_context",
    # Capability 3 — intent-routed related CVEs
    "related_cves",
]

CWE_TOOL_KEYS: List[str] = [
    "cwe_lookup",
    "capec_lookup",
    "cwe_to_attack_intel",
    "cwe_capec_attack_mappings_db",
    "semantic_cwe_capec_attack_search",
    "nvd_cves_by_cwe_db",
    "cve_enrich",
    "tavily_search",
]

ATTACK_TOOL_KEYS: List[str] = [
    "attack_technique_lookup",
    "attack_enterprise_technique_db",
    "semantic_attack_technique_search",
    "cve_to_attack_mapper",
    "attack_to_control_mapper",
    "attack_tactic_contextualise",
    "framework_item_retrieval",
    "attack_stored_control_risk",
    "semantic_attack_control_mapping_search",
    "cve_to_attack_map",
    "cve_enrich",
    "tavily_search",
]

# Detection investigation tools (CVE alert agent)
CVE_ALERT_TOOL_KEYS: List[str] = [
    "cve_intelligence",
    "epss_lookup",
    "cisa_kev_check",
    "detection_scenario_search",
    "kill_chain_builder",
    "priority_score_calculator",
    "cpe_investigation_guide",
    "detection_query_builder",
    "cvss_vector_explainer",
    "detection_playbook_search",
    "list_playbook_data_sources",
    "synthesize_playbook",
    "cve_to_attack_mapper",
    "attack_to_control_mapper",
    "cwe_capec_attack_mappings_db",
]

# Broad catch-all: threat intel + compliance stubs + analysis helpers + web.
GENERAL_TOOL_KEYS: List[str] = [
    "otx_pulse_search",
    "virustotal_lookup",
    "tavily_search",
    "cve_intelligence",
    "cwe_lookup",
    "attack_technique_lookup",
    "framework_control_search",
    "risk_calculator",
]

DOMAIN_TOOL_KEYS: Dict[str, List[str]] = {
    "cve": CVE_TOOL_KEYS,
    "cwe": CWE_TOOL_KEYS,
    "attack": ATTACK_TOOL_KEYS,
    "general": GENERAL_TOOL_KEYS,
    "cve_alert": CVE_ALERT_TOOL_KEYS,
}
