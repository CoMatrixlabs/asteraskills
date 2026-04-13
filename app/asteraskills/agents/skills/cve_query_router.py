"""
Intent classifier for CVE / ATT&CK queries.

Rule-based first (covers ~90 % of structured inputs); LLM fallback for
fully ambiguous free-text. All paths return a ``QueryIntent``.
"""

from __future__ import annotations

import re
import logging
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from asteraskills.agents.skills.kill_chain_tactic_map import resolve_kill_chain_phase

logger = logging.getLogger(__name__)

# ── ATT&CK tactic name → tactic ID (subset; extended at runtime via DB) ────────
_TACTIC_NAME_TO_ID: dict[str, str] = {
    "initial access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004",
    "defense evasion": "TA0005",
    "credential access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command and control": "TA0011",
    "impact": "TA0040",
    "resource development": "TA0042",
    "reconnaissance": "TA0043",
}

_KILL_CHAIN_PHASE_HINTS = {
    "delivery", "exploitation", "weaponization", "installation",
    "command_control", "actions_on_objectives", "actions on objectives",
    "in", "through", "out",
}

# ── regex patterns ──────────────────────────────────────────────────────────────
_T_CODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TA_CODE_RE = re.compile(r"\bTA\d{4}\b")
_SBOM_RE = re.compile(r"sbom|cyclonedx|spdx|\.json$|\.xml$", re.IGNORECASE)
_PURL_RE = re.compile(r"pkg:[a-z]+/[^\s@]+@[^\s]+", re.IGNORECASE)
_SEMVER_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")


class QueryIntent(BaseModel):
    """Parsed intent from a CVE-related query."""
    intent_type: Literal["software", "technique", "tactic", "kill_chain", "sbom"]
    resolved_terms: List[str] = Field(default_factory=list)
    raw_input: str
    confidence: float = Field(ge=0.0, le=1.0)


def _fuzzy_tactic_match(query_lower: str) -> Optional[str]:
    """Return a TA-code if the query closely matches a known tactic name."""
    for name, tactic_id in _TACTIC_NAME_TO_ID.items():
        if name in query_lower:
            return tactic_id
    return None


def _qdrant_attack_classify(query: str) -> Optional[QueryIntent]:
    """
    Semantic fallback: embed query → cosine search attack_techniques (Qdrant).
    Returns None if Qdrant is unavailable or confidence < 0.7.
    """
    try:
        from asteraskills.storage.vector_store import get_vector_store_client
        from asteraskills.storage.collections import AttackCollections

        client = get_vector_store_client()
        hits = client.similarity_search_with_score(
            query=query,
            collection_name=AttackCollections.techniques(),
            top_k=3,
        )
        if not hits:
            return None
        top_doc, top_score = hits[0]
        if top_score < 0.7:
            return None
        payload = top_doc.metadata if hasattr(top_doc, "metadata") else {}
        tactic_id = payload.get("tactic_id") or payload.get("tactic")
        technique_id = payload.get("technique_id") or payload.get("id", "")
        if technique_id and re.match(r"^T\d{4}", technique_id):
            return QueryIntent(
                intent_type="technique",
                resolved_terms=[technique_id],
                raw_input=query,
                confidence=float(top_score),
            )
        if tactic_id and re.match(r"^TA\d{4}", tactic_id):
            return QueryIntent(
                intent_type="tactic",
                resolved_terms=[tactic_id],
                raw_input=query,
                confidence=float(top_score),
            )
    except Exception as exc:
        logger.debug("Qdrant ATT&CK classify failed: %s", exc)
    return None


def classify_cve_query(query: str) -> QueryIntent:
    """
    Classify a free-text or structured CVE/ATT&CK query.

    Rules (checked in order):
      1. SBOM marker (file path / keywords)
      2. T-code pattern  → technique
      3. TA-code pattern → tactic
      4. Tactic label fuzzy match
      5. Kill chain phase string match
      6. Qdrant semantic fallback on attack_techniques
      7. Score < 0.7 or Qdrant unavailable → software / product lookup
    """
    q = query.strip()
    q_lower = q.lower()

    # Rule 1 — SBOM
    if _SBOM_RE.search(q) or _PURL_RE.search(q):
        # For purls / sbom paths the resolved term IS the query string
        return QueryIntent(
            intent_type="sbom",
            resolved_terms=[q],
            raw_input=q,
            confidence=0.99,
        )

    # Rule 2 — T-code
    t_codes = _T_CODE_RE.findall(q)
    if t_codes:
        return QueryIntent(
            intent_type="technique",
            resolved_terms=list(dict.fromkeys(t_codes)),  # preserve order, dedupe
            raw_input=q,
            confidence=0.99,
        )

    # Rule 3 — TA-code
    ta_codes = _TA_CODE_RE.findall(q)
    if ta_codes:
        return QueryIntent(
            intent_type="tactic",
            resolved_terms=list(dict.fromkeys(ta_codes)),
            raw_input=q,
            confidence=0.99,
        )

    # Rule 4 — Tactic label (fuzzy name match)
    tactic_id = _fuzzy_tactic_match(q_lower)
    if tactic_id:
        return QueryIntent(
            intent_type="tactic",
            resolved_terms=[tactic_id],
            raw_input=q,
            confidence=0.90,
        )

    # Rule 5 — Kill chain phase
    kc_tactics = resolve_kill_chain_phase(q_lower)
    if kc_tactics:
        return QueryIntent(
            intent_type="kill_chain",
            resolved_terms=kc_tactics,
            raw_input=q,
            confidence=0.90,
        )

    # Rule 6 — Qdrant semantic ATT&CK search
    qdrant_result = _qdrant_attack_classify(q)
    if qdrant_result:
        return qdrant_result

    # Rule 7 — Default: software / package lookup
    return QueryIntent(
        intent_type="software",
        resolved_terms=[q],
        raw_input=q,
        confidence=0.60,
    )
