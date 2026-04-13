"""
Meta-analyzer — deduplication, false positive filter, consensus scoring.

Phase 4: LLM-assisted FP filtering via PROMPT-12.
         Deterministic dedup runs regardless of LLM availability.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from risk_scanner.core.models import Finding, Severity
from risk_scanner.core.prompts import format_prompt

log = logging.getLogger(__name__)

_FP_THRESHOLD = 0.7
_DEDUP_LINE_TOLERANCE = 10


class MetaAnalyzer:
    """Deduplicate findings and filter false positives."""

    def __init__(self, llm: Optional[object] = None) -> None:
        self.llm = llm

    def process(self, findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Return (accepted_findings, suppressed_findings).

        Steps:
          1. Deterministic dedup (same taxonomy + file + overlapping lines)
          2. Consensus scoring (multi-analyzer agreement)
          3. LLM FP filter (if LLM available)
        """
        if not findings:
            return [], []

        # Step 1: dedup
        deduplicated, dedup_suppressed = self._dedup(findings)

        # Step 2: consensus scoring
        for f in deduplicated:
            f.false_positive_score = self._consensus_fp_score(f)

        # Step 3: LLM FP filter (optional)
        if self.llm:
            deduplicated, llm_suppressed = self._llm_filter(deduplicated)
        else:
            llm_suppressed = [f for f in deduplicated if f.false_positive_score > _FP_THRESHOLD]
            deduplicated = [f for f in deduplicated if f.false_positive_score <= _FP_THRESHOLD]

        all_suppressed = dedup_suppressed + llm_suppressed
        return deduplicated, all_suppressed

    # ------------------------------------------------------------------
    # Deterministic dedup
    # ------------------------------------------------------------------

    def _dedup(
        self, findings: List[Finding]
    ) -> Tuple[List[Finding], List[Finding]]:
        seen: Dict[str, Finding] = {}  # key → canonical finding
        suppressed: List[Finding] = []

        for finding in findings:
            key = self._dedup_key(finding)
            if key in seen:
                existing = seen[key]
                # Keep the higher-confidence one
                if finding.confidence > existing.confidence:
                    seen[key] = finding
                    # Merge analyzer sources
                    seen[key].analyzer_sources = list(
                        set(finding.analyzer_sources + existing.analyzer_sources)
                    )
                    suppressed.append(existing)
                else:
                    existing.analyzer_sources = list(
                        set(finding.analyzer_sources + existing.analyzer_sources)
                    )
                    suppressed.append(finding)
            else:
                seen[key] = finding

        return list(seen.values()), suppressed

    def _dedup_key(self, finding: Finding) -> str:
        file_path = finding.evidence.file_path or ""
        line = finding.evidence.line_start or 0
        # Round line to nearest DEDUP_LINE_TOLERANCE bucket
        line_bucket = (line // _DEDUP_LINE_TOLERANCE) * _DEDUP_LINE_TOLERANCE
        return f"{finding.taxonomy_code}::{file_path}::{line_bucket}"

    # ------------------------------------------------------------------
    # Consensus scoring
    # ------------------------------------------------------------------

    def _consensus_fp_score(self, finding: Finding) -> float:
        """0.0 = definitely real, 1.0 = definitely FP."""
        sources = finding.analyzer_sources
        n_sources = len(set(sources))
        confidence = finding.confidence

        # Multi-source agreement significantly reduces FP probability
        if n_sources >= 2:
            base_fp = max(0.0, 1.0 - confidence - 0.3)
        elif confidence >= 0.85:
            base_fp = max(0.0, 1.0 - confidence - 0.1)
        elif confidence < 0.6:
            base_fp = 0.5
        else:
            base_fp = max(0.0, 1.0 - confidence)

        # CRITICAL findings get bonus reduction
        if finding.severity == Severity.CRITICAL:
            base_fp = base_fp * 0.5

        return round(min(1.0, base_fp), 3)

    # ------------------------------------------------------------------
    # LLM FP filter (PROMPT-12)
    # ------------------------------------------------------------------

    def _llm_filter(
        self, findings: List[Finding]
    ) -> Tuple[List[Finding], List[Finding]]:
        try:
            findings_json = json.dumps(
                [f.model_dump(mode="json") for f in findings],
                default=str,
                indent=2,
            )
            prompt = format_prompt("PROMPT-12", all_findings_json=findings_json)

            from langchain_core.messages import HumanMessage
            import re
            resp = self.llm.invoke([HumanMessage(content=prompt)])  # type: ignore[union-attr]
            raw = resp.content if hasattr(resp, "content") else str(resp)
            raw = re.sub(r'^```(?:json)?\n?', '', raw.strip(), flags=re.MULTILINE)
            raw = re.sub(r'\n?```$', '', raw.strip(), flags=re.MULTILINE)
            result = json.loads(raw)

            accepted_ids = {a["finding_id"] for a in result.get("accepted_findings", [])}
            suppressed_ids = {s["finding_id"] for s in result.get("suppressed_findings", [])}

            # Update FP scores from LLM result
            fp_map = {a["finding_id"]: a["false_positive_score"]
                      for a in result.get("accepted_findings", [])}

            accepted = []
            suppressed = []
            for f in findings:
                if f.id in suppressed_ids and f.severity != Severity.CRITICAL:
                    f.false_positive_score = 0.9
                    suppressed.append(f)
                else:
                    if f.id in fp_map:
                        f.false_positive_score = fp_map[f.id]
                    accepted.append(f)

            return accepted, suppressed

        except Exception as exc:
            log.warning("LLM meta-analysis failed: %s", exc)
            # Fallback: threshold-based suppression
            accepted = [f for f in findings if f.false_positive_score <= _FP_THRESHOLD
                        or f.severity == Severity.CRITICAL]
            suppressed = [f for f in findings if f.false_positive_score > _FP_THRESHOLD
                          and f.severity != Severity.CRITICAL]
            return accepted, suppressed
