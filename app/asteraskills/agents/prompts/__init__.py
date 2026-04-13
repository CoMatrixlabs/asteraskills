"""System prompts for router and domain ReAct agents (loaded from ``*.md`` in this package)."""

from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent


def _load_prompt(stem: str) -> str:
    path = _DIR / f"{stem}.md"
    if not path.is_file():
        msg = f"Missing prompt file: {path}"
        raise FileNotFoundError(msg)
    return path.read_text(encoding="utf-8").strip()


ROUTER_SYSTEM = _load_prompt("router")

SPECIALIST_PROMPTS = {
    "cve": _load_prompt("cve"),
    "cwe": _load_prompt("cwe"),
    "attack": _load_prompt("attack"),
    "general": _load_prompt("general"),
}

__all__ = ["ROUTER_SYSTEM", "SPECIALIST_PROMPTS"]
