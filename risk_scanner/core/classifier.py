"""
LLM domain classifier — routes artifacts to Domain(s).

If a license token is set and pack_client has signals, uses PROMPT-01 via LLM.
Otherwise falls back to keyword heuristics (no LLM required).
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from risk_scanner.core.models import Domain, LoadedArtifact
from risk_scanner.core.pack_client import PackClient
from risk_scanner.core.prompts import format_prompt

log = logging.getLogger(__name__)


class DomainClassifier:
    def __init__(self, pack_client: PackClient, llm: Optional[object] = None) -> None:
        self.pack_client = pack_client
        self.llm = llm  # LangChain chat model (get_llm())

    def classify(self, artifact: LoadedArtifact) -> List[Domain]:
        """Return ordered list of domains for this artifact (primary first)."""
        # Try server-side retrieval + LLM classification
        if not self.pack_client.local_mode and self.llm is not None:
            domains = self._llm_classify(artifact)
            if domains:
                return domains

        # Fallback: keyword/extension heuristics
        return self._heuristic_classify(artifact)

    # ------------------------------------------------------------------
    # LLM path (PROMPT-01)
    # ------------------------------------------------------------------

    def _llm_classify(self, artifact: LoadedArtifact) -> List[Domain]:
        try:
            signals = self.pack_client.retrieve_domain_signals({
                "file_type": artifact.file_type,
                "mime_type": artifact.mime_type,
                "detected_keywords": artifact.detected_keywords[:20],
                "manifest_keys": artifact.manifest_keys[:20],
                "size_bytes": artifact.size_bytes,
            })
            prompt = format_prompt(
                "PROMPT-01",
                retrieved_signals=json.dumps(signals, indent=2),
                file_type=artifact.file_type,
                mime_type=artifact.mime_type,
                keywords=artifact.detected_keywords[:20],
                manifest_keys=artifact.manifest_keys[:20],
                size_bytes=artifact.size_bytes,
            )
            from langchain_core.messages import HumanMessage
            resp = self.llm.invoke([HumanMessage(content=prompt)])
            raw = resp.content if hasattr(resp, "content") else str(resp)
            data = json.loads(raw)
            domains: List[Domain] = []
            # Sort: primary first, then by confidence desc
            items = sorted(data.get("domains", []), key=lambda x: (not x.get("primary"), -x.get("confidence", 0)))
            for item in items:
                try:
                    domains.append(Domain(item["domain"]))
                except ValueError:
                    pass
            return domains
        except Exception as exc:
            log.debug("LLM classify failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Heuristic path (no LLM)
    # ------------------------------------------------------------------

    def _heuristic_classify(self, artifact: LoadedArtifact) -> List[Domain]:
        ft = artifact.file_type
        kws = set(artifact.detected_keywords)

        # SBOM → CVE
        if ft in ("sbom-cyclonedx", "sbom-spdx"):
            return [Domain.CVE]

        # IaC → POLICY (may also have CVE if provider pinning)
        if ft in ("terraform", "cloudformation", "kubernetes"):
            domains = [Domain.POLICY]
            if any(k in kws for k in {"provider", "aws_", "google_"}):
                pass  # pure policy
            return domains

        # Source code → CWE
        if ft in ("python", "javascript", "typescript", "go", "bash", "rust"):
            return [Domain.CWE]

        # Logs/alerts → ATT&CK
        if ft in ("siem-logs",):
            return [Domain.ATTACK]

        # Evidence docs → FRAMEWORK
        if ft in ("evidence-pdf", "evidence-csv", "evidence-xlsx"):
            return [Domain.FRAMEWORK]

        # Unknown YAML/JSON — try to infer from keywords
        if any(k in kws for k in {"bomFormat", "SPDXID", "components", "purl"}):
            return [Domain.CVE]
        if any(k in kws for k in {"resource", "provider", "apiVersion"}):
            return [Domain.POLICY]
        if any(k in kws for k in {"technique", "tactic", "ioc", "T1"}):
            return [Domain.ATTACK]
        if any(k in kws for k in {"control", "compliance", "soc2", "nist"}):
            return [Domain.FRAMEWORK]
        if any(k in kws for k in {"def ", "import ", "eval(", "subprocess"}):
            return [Domain.CWE]

        log.debug("No domain detected for %s, defaulting to CVE", artifact.file_type)
        return [Domain.CVE]
