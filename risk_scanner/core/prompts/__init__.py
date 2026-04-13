"""
Risk Scanner prompt library — loads all 16 prompts from .md files in this directory.

Usage:
    from risk_scanner.core.prompts import format_prompt
    rendered = format_prompt("PROMPT-07", cve_id="CVE-2024-3400", ...)

Prompt files use {variable} placeholders (Python str.format syntax).
JSON schema examples inside prompts use {{ and }} for literal braces.

Each .md file structure:
  - YAML frontmatter (metadata, not sent to LLM)
  - Prompt text (everything after frontmatter up to <!-- DOCS_START -->)
  - <!-- DOCS_START --> section (examples + customization, not sent to LLM)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_DIR = Path(__file__).resolve().parent

# Mapping from prompt ID to .md filename stem
_PROMPT_FILES: dict[str, str] = {
    "PROMPT-01": "prompt-01-domain-classifier",
    "PROMPT-02": "prompt-02-cve-detect",
    "PROMPT-03": "prompt-03-cwe-detect",
    "PROMPT-04": "prompt-04-policy-detect",
    "PROMPT-05": "prompt-05-attack-detect",
    "PROMPT-06": "prompt-06-framework-detect",
    "PROMPT-07": "prompt-07-cve-to-attack",
    "PROMPT-08": "prompt-08-cwe-to-attack",
    "PROMPT-09": "prompt-09-policy-to-attack",
    "PROMPT-10": "prompt-10-attack-to-controls",
    "PROMPT-11": "prompt-11-severity-contextualization",
    "PROMPT-12": "prompt-12-meta-analyzer",
    "PROMPT-13": "prompt-13-finding-summary",
    "PROMPT-14": "prompt-14-remediation-ticket",
    "PROMPT-15": "prompt-15-cross-finding-correlation",
    "PROMPT-16": "prompt-16-kill-chain-narrative",
    "PROMPT-17": "prompt-17-kev-context",
}


def _load_prompt_file(stem: str) -> str:
    """Load a prompt .md file and return only the template text.

    Strips YAML frontmatter (between the first two --- delimiters) and
    strips everything from <!-- DOCS_START --> onwards (examples + customization).
    """
    path = _DIR / f"{stem}.md"
    if not path.is_file():
        raise FileNotFoundError(f"Missing prompt file: {path}")

    content = path.read_text(encoding="utf-8")

    # Strip YAML frontmatter: content between first --- and second ---
    if content.startswith("---"):
        end = content.index("---", 3)  # find closing ---
        content = content[end + 3:].lstrip("\n")

    # Strip docs section (examples + customization) — not sent to the LLM
    docs_marker = "<!-- DOCS_START -->"
    if docs_marker in content:
        content = content[: content.index(docs_marker)]

    return content.strip()


# Lazy-loaded cache: prompt ID → template string
_cache: dict[str, str] = {}


def _get_template(prompt_id: str) -> str:
    if prompt_id not in _cache:
        stem = _PROMPT_FILES.get(prompt_id)
        if stem is None:
            raise KeyError(
                f"Unknown prompt: {prompt_id!r}. Available: {list(_PROMPT_FILES)}"
            )
        _cache[prompt_id] = _load_prompt_file(stem)
    return _cache[prompt_id]


def format_prompt(prompt_id: str, **variables: Any) -> str:
    """Render a prompt template with the given variables.

    Prompt templates use {var_name} placeholders. Double braces {{ }} in the
    template represent literal braces in the output (standard Python format_map).
    """
    template = _get_template(prompt_id)
    try:
        return template.format(**variables)
    except KeyError as exc:
        raise ValueError(f"Missing variable {exc} for {prompt_id}") from exc


def get_prompt_ids() -> list[str]:
    """Return all available prompt IDs."""
    return list(_PROMPT_FILES.keys())


def get_prompt_template(prompt_id: str) -> str:
    """Return the raw (un-rendered) template string for a prompt."""
    return _get_template(prompt_id)


__all__ = ["format_prompt", "get_prompt_ids", "get_prompt_template"]
