"""
Prompt templates for the ATT&CK → Control Framework mapping pipeline.

All templates are framework-agnostic.  Every call site injects two variables
that carry the framework identity:

    {framework_name}   – human label, e.g. "CIS Controls v8.1", "NIST SP 800-53 Rev 5",
                         "ISO 27001:2022", "SOC 2 TSC", "PCI-DSS v4.0"
    {control_id_label} – how this framework labels its controls, e.g. "CIS-RISK-NNN",
                         "AC-2", "A.8.1", "CC6.1", "Req-8.3"

Pass these from graph state so the same compiled graph works across frameworks
without any prompt edits.  Default values below match the original CIS build.

Templates (loaded from prompts/*.md — edit those files to change prompt behavior):
---------
ATTACK_QUERY_BUILDER              – Build a semantic search query from technique metadata
CONTROL_MAPPING_SYSTEM            – System prompt for the core mapping LLM call
CONTROL_MAPPING_USER              – User turn: technique + candidate controls → JSON mappings
CONTROL_MAPPING_SYSTEM_NO_CANDIDATES – Fallback system prompt when vector store yields nothing
CONTROL_MAPPING_USER_NO_CANDIDATES   – Fallback user turn
VALIDATION_SYSTEM                 – Validate and score a set of mappings
VALIDATION_USER                   – Validation user turn
SUMMARY_SYSTEM                    – Summarise final mappings for human consumption
SUMMARY_USER                      – Summary user turn

Framework presets (pass directly as {framework_name} / {control_id_label}):
    FRAMEWORKS["cis"]      FRAMEWORKS["nist_800_53"]   FRAMEWORKS["iso_27001"]
    FRAMEWORKS["soc2"]     FRAMEWORKS["pci_dss"]        FRAMEWORKS["hipaa"]
"""

from pathlib import Path as _Path

_PROMPTS_DIR = _Path(__file__).resolve().parent / "prompts"


def _load_md(stem: str) -> str:
    """Load a prompt .md file, stripping YAML frontmatter and DOCS_START section."""
    path = _PROMPTS_DIR / f"{stem}.md"
    if not path.is_file():
        raise FileNotFoundError(f"Missing prompt file: {path}")
    content = path.read_text(encoding="utf-8")
    # Strip YAML frontmatter
    if content.startswith("---"):
        end = content.index("---", 3)
        content = content[end + 3:].lstrip("\n")
    # Strip docs/examples section
    marker = "<!-- DOCS_START -->"
    if marker in content:
        content = content[: content.index(marker)]
    return content.strip()

# ---------------------------------------------------------------------------
# Framework presets – import and unpack into node kwargs
# ---------------------------------------------------------------------------

# Framework name mappings (for backward compatibility and fallback)
FRAMEWORK_NAMES: dict = {
    "cis_controls_v8_1": "CIS Controls v8.1",
    "nist_csf_2_0": "NIST CSF 2.0",
    "hipaa": "HIPAA",
    "soc2": "SOC 2",
    "iso27001_2013": "ISO 27001:2013",
    "iso27001_2022": "ISO 27001:2022",
}

# Prompt presets for control_id_label formatting
FRAMEWORKS: dict = {
    "cis": {
        "framework_name": "CIS Controls v8.1",
        "control_id_label": "CIS-RISK-NNN",
    },
    "nist_800_53": {
        "framework_name": "NIST SP 800-53 Rev 5",
        "control_id_label": "Control family + ID (e.g. AC-2, SI-3)",
    },
    "iso_27001": {
        "framework_name": "ISO/IEC 27001:2022",
        "control_id_label": "Annex A control ID (e.g. A.8.1, A.5.23)",
    },
    "soc2": {
        "framework_name": "SOC 2 Trust Services Criteria (2017)",
        "control_id_label": "TSC reference (e.g. CC6.1, A1.2)",
    },
    "pci_dss": {
        "framework_name": "PCI-DSS v4.0",
        "control_id_label": "Requirement ID (e.g. Req-8.3, Req-10.2)",
    },
    "hipaa": {
        "framework_name": "HIPAA Security Rule",
        "control_id_label": "Safeguard reference (e.g. §164.312(a)(1))",
    },
}

# Default – preserved for backward-compat with existing CIS call sites
_DEFAULT_FRAMEWORK = FRAMEWORKS["cis"]


def get_framework_preset(framework_id: str) -> dict:
    """
    Get framework preset from framework identifier.
    
    Maps framework identifiers (e.g., "cis_controls_v8_1", "nist_csf_2_0")
    to prompt presets (e.g., "cis", "nist_800_53").
    
    Args:
        framework_id: Framework identifier from framework_helper
        
    Returns:
        Dict with framework_name and control_id_label
    """
    # Try to get framework name from framework_helper first
    try:
        from .framework_helper import get_framework_info
        framework_info = get_framework_info(framework_id)
        framework_name = framework_info.get("name", framework_id.replace("_", " ").title())
    except (ImportError, ValueError):
        # Fallback to hardcoded mapping
        framework_name = FRAMEWORK_NAMES.get(framework_id, framework_id.replace("_", " ").title())
    
    # Map framework identifiers to prompt preset keys for control_id_label
    framework_map = {
        "cis_controls_v8_1": "cis",
        "cis_v8_1": "cis",  # CVE pipeline alias
        "nist_csf_2_0": "nist_800_53",  # Using NIST 800-53 preset for CSF
        "nist_800_53r5": "nist_800_53",  # CVE pipeline alias
        "hipaa": "hipaa",
        "soc2": "soc2",
        "iso27001": "iso_27001",  # ingestion / framework_items id (2022 adapter)
        "iso27001_2013": "iso_27001",
        "iso27001_2022": "iso_27001",
    }
    
    preset_key = framework_map.get(framework_id, "cis")
    preset = FRAMEWORKS.get(preset_key, _DEFAULT_FRAMEWORK)
    
    # Override framework_name with the discovered name
    return {
        "framework_name": framework_name,
        "control_id_label": preset["control_id_label"],
    }


def get_framework_info_from_yaml_path(yaml_path: str) -> dict:
    """
    Extract framework identifier from YAML path and return framework preset.
    
    Args:
        yaml_path: Path to framework YAML file
        
    Returns:
        Dict with framework_name and control_id_label
    """
    from pathlib import Path
    
    path = Path(yaml_path)
    # Try to extract framework from path (e.g., .../cis_controls_v8_1/...)
    for part in path.parts:
        if part in FRAMEWORKS or any(fw in part for fw in ["cis", "nist", "hipaa", "soc2", "iso27001"]):
            # Try to match framework identifier
            for fw_id in ["cis_controls_v8_1", "nist_csf_2_0", "hipaa", "soc2", "iso27001_2013", "iso27001_2022"]:
                if fw_id in part or fw_id in str(path):
                    return get_framework_preset(fw_id)
    
    # Default to CIS if can't determine
    return _DEFAULT_FRAMEWORK


# ---------------------------------------------------------------------------
# Prompt constants — loaded from prompts/*.md files
# Edit the .md files to change prompt behavior; this module re-exports them
# with the same names so all existing call sites continue to work unchanged.
# ---------------------------------------------------------------------------

ATTACK_QUERY_BUILDER = _load_md("attack-query-builder")
CONTROL_MAPPING_SYSTEM = _load_md("control-mapping-system")
CONTROL_MAPPING_USER = _load_md("control-mapping-user")
CONTROL_MAPPING_SYSTEM_NO_CANDIDATES = _load_md("control-mapping-system-no-candidates")
CONTROL_MAPPING_USER_NO_CANDIDATES = _load_md("control-mapping-user-no-candidates")
VALIDATION_SYSTEM = _load_md("validation-system")
VALIDATION_USER = _load_md("validation-user")
SUMMARY_SYSTEM = _load_md("summary-system")
SUMMARY_USER = _load_md("summary-user")