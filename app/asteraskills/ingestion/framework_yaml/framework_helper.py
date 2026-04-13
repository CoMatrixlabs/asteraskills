"""
Framework Helper
================
Utilities for working with multiple compliance frameworks from risk_control_yaml.

Auto-discovers frameworks and file types from the directory structure.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def _default_risk_control_yaml_base() -> Path:
    """Resolve risk_control_yaml root (CVE_DATA_DIR or data/cvedata next to repo)."""
    env = os.getenv("CVE_DATA_DIR")
    if env:
        root = Path(env).expanduser().resolve()
        child = root / "risk_control_yaml"
        return child if child.is_dir() else root
    try:
        from asteraskills.config.settings import get_settings

        base = get_settings().BASE_DIR.resolve()
        for candidate in (
            base.parent / "data" / "cvedata" / "risk_control_yaml",
            base / "data" / "cvedata" / "risk_control_yaml",
        ):
            if candidate.is_dir():
                return candidate
        return base / "data" / "cvedata" / "risk_control_yaml"
    except Exception:  # noqa: BLE001
        return Path(__file__).resolve().parents[6] / "data" / "cvedata" / "risk_control_yaml"



# Framework name mappings (folder name -> display name)
FRAMEWORK_NAMES: Dict[str, str] = {
    "cis_controls_v8_1": "CIS Controls v8.1",
    "nist_csf_2_0": "NIST CSF 2.0",
    "hipaa": "HIPAA",
    "soc2": "SOC 2",
    "iso27001_2013": "ISO 27001:2013",
    "iso27001_2022": "ISO 27001:2022",
}

# File type patterns (order matters - more specific patterns first)
FILE_TYPE_PATTERNS = {
    "risk_controls": [
        "*_risk_controls.yaml",
        "*risk_controls.yaml",
        "risk_controls.yaml",
    ],
    "scenarios": [
        "scenarios_*.yaml",
        "*_scenarios.yaml",
    ],
    "controls": [
        "controls_*.yaml",
        "*_controls.yaml",
    ],
    "requirements": [
        "requirements_*.yaml",
        "*_requirements.yaml",
    ],
    "test_cases": [
        "*_test_cases.yaml",
        "test_cases_*.yaml",
    ],
}

# Framework cache (populated on first access)
_FRAMEWORKS_CACHE: Optional[Dict[str, Dict[str, any]]] = None


def _discover_frameworks(base_path: Optional[Path] = None) -> Dict[str, Dict[str, any]]:
    """
    Auto-discover frameworks and their file types from the directory structure.
    
    Args:
        base_path: Base path to risk_control_yaml directory
        
    Returns:
        Dict mapping framework_id -> framework_info
    """
    base = base_path or _default_risk_control_yaml_base()
    
    if not base.exists():
        logger.warning(f"Base path does not exist: {base}")
        return {}
    
    frameworks: Dict[str, Dict[str, any]] = {}
    
    # Scan for framework directories
    for item in base.iterdir():
        if not item.is_dir() or item.name.startswith(".") or item.name == "common":
            continue
        
        framework_id = item.name
        framework_dir = item
        
        # Get display name
        framework_name = FRAMEWORK_NAMES.get(framework_id, framework_id.replace("_", " ").title())
        
        # Discover files in this framework directory
        framework_info: Dict[str, any] = {
            "name": framework_name,
            "folder": framework_id,
            "base_path": str(framework_dir),
        }
        
        # Find files matching each file type pattern
        yaml_files = list(framework_dir.glob("*.yaml"))
        
        for file_type, patterns in FILE_TYPE_PATTERNS.items():
            for pattern in patterns:
                # Try to match pattern
                matched_files = []
                for yaml_file in yaml_files:
                    if yaml_file.match(pattern):
                        matched_files.append(yaml_file.name)
                
                if matched_files:
                    # Use the first match (or prefer exact match if available)
                    if len(matched_files) == 1:
                        framework_info[file_type] = matched_files[0]
                    else:
                        # Prefer files that start with framework_id
                        prefixed = [f for f in matched_files if f.startswith(framework_id)]
                        if prefixed:
                            framework_info[file_type] = prefixed[0]
                        else:
                            framework_info[file_type] = matched_files[0]
                    break
        
        if framework_info:
            frameworks[framework_id] = framework_info
            logger.debug(f"Discovered framework: {framework_id} with files: {list(framework_info.keys())}")
    
    return frameworks


def get_frameworks(base_path: Optional[Path] = None, force_refresh: bool = False) -> Dict[str, Dict[str, any]]:
    """
    Get all discovered frameworks (cached).
    
    Args:
        base_path: Optional base path (defaults to DEFAULT_BASE_PATH)
        force_refresh: Force re-discovery even if cache exists
        
    Returns:
        Dict mapping framework_id -> framework_info
    """
    global _FRAMEWORKS_CACHE
    
    if _FRAMEWORKS_CACHE is None or force_refresh:
        _FRAMEWORKS_CACHE = _discover_frameworks(base_path)
    
    return _FRAMEWORKS_CACHE.copy()


def get_framework_path(
    framework: str,
    file_type: str = "risk_controls",
    base_path: Optional[Path] = None,
) -> Path:
    """
    Get the path to a framework YAML file.
    
    Args:
        framework: Framework identifier (e.g., "cis_controls_v8_1")
        file_type: Type of file ("risk_controls", "scenarios", "controls", "requirements", "test_cases")
        base_path: Optional base path (defaults to DEFAULT_BASE_PATH)
        
    Returns:
        Path to the YAML file
        
    Raises:
        ValueError: If framework or file_type is not found
        FileNotFoundError: If the file doesn't exist
    """
    frameworks = get_frameworks(base_path)
    
    if framework not in frameworks:
        available = list(frameworks.keys())
        raise ValueError(
            f"Unknown framework: {framework}. "
            f"Available: {available}"
        )
    
    framework_info = frameworks[framework]
    
    if file_type not in framework_info:
        available_types = [k for k in framework_info.keys() if k not in ["name", "folder", "base_path"]]
        raise ValueError(
            f"File type '{file_type}' not found for framework {framework}. "
            f"Available types: {available_types}"
        )
    
    filename = framework_info[file_type]
    framework_dir = Path(framework_info["base_path"])
    file_path = framework_dir / filename
    
    if not file_path.exists():
        raise FileNotFoundError(
            f"Framework file not found: {file_path}\n"
            f"Framework: {framework}, Type: {file_type}, Expected: {filename}"
        )
    
    return file_path


def list_frameworks(base_path: Optional[Path] = None) -> List[str]:
    """
    List all available framework identifiers.
    
    Args:
        base_path: Optional base path (defaults to DEFAULT_BASE_PATH)
        
    Returns:
        List of framework identifiers
    """
    frameworks = get_frameworks(base_path)
    return sorted(frameworks.keys())


def get_framework_info(framework: str, base_path: Optional[Path] = None) -> Dict[str, any]:
    """
    Get information about a framework.
    
    Args:
        framework: Framework identifier
        base_path: Optional base path (defaults to DEFAULT_BASE_PATH)
        
    Returns:
        Framework information dictionary
    """
    frameworks = get_frameworks(base_path)
    
    if framework not in frameworks:
        available = list(frameworks.keys())
        raise ValueError(
            f"Unknown framework: {framework}. "
            f"Available: {available}"
        )
    
    return frameworks[framework].copy()


def find_framework_yaml(
    framework: str,
    file_type: str = "risk_controls",
    base_path: Optional[Path] = None,
) -> Optional[Path]:
    """
    Find a framework YAML file (graceful fallback).
    
    Args:
        framework: Framework identifier
        file_type: Type of file to find
        base_path: Optional base path
        
    Returns:
        Path to the file, or None if not found
    """
    try:
        return get_framework_path(framework, file_type, base_path)
    except (ValueError, FileNotFoundError) as e:
        logger.debug(f"Could not find {file_type} for {framework}: {e}")
        return None


def get_framework_file_types(framework: str, base_path: Optional[Path] = None) -> List[str]:
    """
    Get list of available file types for a framework.
    
    Args:
        framework: Framework identifier
        base_path: Optional base path
        
    Returns:
        List of available file types (excluding metadata keys)
    """
    framework_info = get_framework_info(framework, base_path)
    return [
        k for k in framework_info.keys()
        if k not in ["name", "folder", "base_path"]
    ]


def validate_framework_structure(framework: str, base_path: Optional[Path] = None) -> Dict[str, bool]:
    """
    Validate that a framework has the expected file structure.
    
    Args:
        framework: Framework identifier
        base_path: Optional base path
        
    Returns:
        Dict mapping file_type -> exists (bool)
    """
    frameworks = get_frameworks(base_path)
    
    if framework not in frameworks:
        return {}
    
    framework_info = frameworks[framework]
    framework_dir = Path(framework_info["base_path"])
    
    validation = {}
    for file_type in ["risk_controls", "scenarios", "controls", "requirements", "test_cases"]:
        if file_type in framework_info:
            file_path = framework_dir / framework_info[file_type]
            validation[file_type] = file_path.exists()
        else:
            validation[file_type] = False
    
    return validation


def get_all_framework_files(framework: str, base_path: Optional[Path] = None) -> Dict[str, Path]:
    """
    Get all available files for a framework.
    
    Args:
        framework: Framework identifier
        base_path: Optional base path
        
    Returns:
        Dict mapping file_type -> Path
    """
    frameworks = get_frameworks(base_path)
    
    if framework not in frameworks:
        return {}
    
    framework_info = frameworks[framework]
    framework_dir = Path(framework_info["base_path"])
    
    files = {}
    for file_type in ["risk_controls", "scenarios", "controls", "requirements", "test_cases"]:
        if file_type in framework_info:
            file_path = framework_dir / framework_info[file_type]
            if file_path.exists():
                files[file_type] = file_path
    
    return files
