"""
Static mapping from Lockheed Martin / Unified Kill Chain phases to MITRE ATT&CK tactic IDs.
"""

from __future__ import annotations

from typing import Dict, List

# Lockheed Martin Cyber Kill Chain + Unified Kill Chain → ATT&CK tactic clusters
KILL_CHAIN_TO_TACTIC_MAP: Dict[str, List[str]] = {
    # Lockheed Martin
    "reconnaissance": ["TA0043"],
    "weaponization": ["TA0001", "TA0002"],
    "delivery": ["TA0001"],
    "exploitation": ["TA0002", "TA0004"],
    "installation": ["TA0003", "TA0005"],
    "command_control": ["TA0011"],
    "command and control": ["TA0011"],
    "actions_on_objectives": ["TA0007", "TA0008", "TA0009", "TA0010"],
    "actions on objectives": ["TA0007", "TA0008", "TA0009", "TA0010"],
    # Unified Kill Chain phases
    "in": ["TA0043", "TA0001", "TA0002"],
    "through": ["TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008"],
    "out": ["TA0009", "TA0010", "TA0011"],
    # Common free-text aliases
    "initial access": ["TA0001"],
    "execution": ["TA0002"],
    "persistence": ["TA0003"],
    "privilege escalation": ["TA0004"],
    "defense evasion": ["TA0005"],
    "credential access": ["TA0006"],
    "discovery": ["TA0007"],
    "lateral movement": ["TA0008"],
    "collection": ["TA0009"],
    "exfiltration": ["TA0010"],
    "impact": ["TA0040"],
    "resource development": ["TA0042"],
    "pre-attack": ["TA0043"],
}

# Normalise phase strings before lookup
_STRIP_CHARS = " _-"


def resolve_kill_chain_phase(phase: str) -> List[str]:
    """
    Return the list of ATT&CK tactic IDs for *phase*.

    Matching is case-insensitive and strips leading/trailing spaces, dashes, underscores.
    Returns an empty list if the phase is not recognised.
    """
    key = phase.lower().strip(_STRIP_CHARS)
    # Try exact key first
    if key in KILL_CHAIN_TO_TACTIC_MAP:
        return KILL_CHAIN_TO_TACTIC_MAP[key]
    # Try with underscores normalised to spaces
    key_spaces = key.replace("_", " ")
    if key_spaces in KILL_CHAIN_TO_TACTIC_MAP:
        return KILL_CHAIN_TO_TACTIC_MAP[key_spaces]
    # Partial prefix match (e.g. "exploitation phase" → "exploitation")
    for known_phase, tactics in KILL_CHAIN_TO_TACTIC_MAP.items():
        if key.startswith(known_phase) or known_phase.startswith(key):
            return tactics
    return []
