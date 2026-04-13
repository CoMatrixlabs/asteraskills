"""Instantiate LangChain tools from ``TOOL_REGISTRY`` by key."""

from __future__ import annotations

import logging
from typing import Iterable, List

from langchain_core.tools import BaseTool

from asteraskills.tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)


def tools_for_keys(keys: Iterable[str]) -> List[BaseTool]:
    """Deduplicate registry keys and LangChain tool ``name`` while preserving order."""
    seen_keys: set[str] = set()
    seen_tool_names: set[str] = set()
    out: List[BaseTool] = []
    for name in keys:
        if name in seen_keys:
            continue
        seen_keys.add(name)
        factory = TOOL_REGISTRY.get(name)
        if not factory:
            logger.warning("Unknown tool key %r — skipped", name)
            continue
        try:
            tool = factory()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to instantiate tool %r: %s", name, exc)
            continue
        tname = getattr(tool, "name", None) or name
        if tname in seen_tool_names:
            continue
        seen_tool_names.add(tname)
        out.append(tool)
    return out
