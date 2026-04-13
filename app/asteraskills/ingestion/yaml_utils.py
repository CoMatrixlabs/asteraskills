"""YAML helpers for optional framework YAML fallback (no LLM enrichment deps)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)


def load_yaml_file(file_path: Path) -> List[Dict[str, Any]]:
    """Load and parse a YAML file, returning a list of items."""
    if not file_path.exists():
        logger.warning("File not found: %s", file_path)
        return []
    try:
        with open(file_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data is None:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return list(data.values()) if data else []
        return []
    except yaml.YAMLError as e:
        logger.error("YAML parse error in %s: %s", file_path, e)
        return []
    except OSError as e:
        logger.error("Error reading %s: %s", file_path, e)
        return []
