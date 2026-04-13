"""
Bootstrap asteraskills: load repo ``.env`` and expose the vendored ``TOOL_REGISTRY``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _repo_root() -> Path:
    # .../asteraskills/app/asteraskills/bridge.py → repo root is parents[2]
    return Path(__file__).resolve().parents[2]


def bootstrap(repo_root: Optional[Path] = None) -> Path:
    """
    Load environment files and return the repository root (``Lexy/asteraskills``).
    """
    root = repo_root or _repo_root()
    try:
        from dotenv import load_dotenv

        env_main = root / ".env"
        if env_main.is_file():
            load_dotenv(env_main, override=False)
        extra = os.getenv("ASTERASKILLS_ENV_FILE")
        if extra:
            p = Path(extra).expanduser()
            if p.is_file():
                load_dotenv(p, override=False)
    except ImportError:
        pass
    return root


def load_tool_registry():
    from asteraskills.tools import TOOL_REGISTRY

    if not isinstance(TOOL_REGISTRY, dict):
        raise RuntimeError("asteraskills.tools.TOOL_REGISTRY missing or invalid")
    import asteraskills.tools as mod

    return mod, TOOL_REGISTRY, getattr(mod, "get_all_tools", None)


def list_tools(registry: Dict[str, Callable[..., Any]]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for name in sorted(registry.keys()):
        try:
            tool = registry[name]()
            desc = getattr(tool, "description", "") or ""
            out.append((name, desc.strip()))
        except Exception as exc:  # noqa: BLE001
            out.append((name, f"<failed to instantiate: {exc}>"))
    return out


def run_tool(registry: Dict[str, Callable[..., Any]], name: str, args: Dict[str, Any]) -> Any:
    if name not in registry:
        raise KeyError(f"Unknown tool {name!r}. Use `asteraskills list`.")
    tool = registry[name]()
    invoke = getattr(tool, "invoke", None)
    if not callable(invoke):
        raise TypeError(f"Tool {name!r} has no invoke()")
    return invoke(args)
