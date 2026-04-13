"""
Scanner orchestrator — dispatches analyzers, enriches findings, builds ScanResult.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from risk_scanner.core.classifier import DomainClassifier
from risk_scanner.core.loader import ArtifactLoader
from risk_scanner.core.models import Domain, Finding, LoadedArtifact, ScanResult, Severity
from risk_scanner.core.pack_client import PackClient
from risk_scanner.core.scan_policy import ScanPolicy

log = logging.getLogger(__name__)


class Scanner:
    """Main scan orchestrator.

    Usage:
        from risk_scanner.core.scanner import Scanner
        result = Scanner().scan("/path/to/sbom.json")
    """

    def __init__(
        self,
        policy: Optional[ScanPolicy] = None,
        license_token: Optional[str] = None,
        server_url: str = "https://api.risk-scanner.io",
        frameworks: Optional[List[str]] = None,
        kev_enabled: bool = True,
        _kev_client: Optional[Any] = None,  # injectable for testing
        enrich_cpe: bool = False,
        max_related_cves: int = 0,
    ) -> None:
        self.policy = policy or ScanPolicy.default()
        if license_token:
            self.policy.license_token = license_token
        self.pack_client = PackClient(
            license_token=self.policy.license_token,
            server_url=server_url,
        )
        self.frameworks = frameworks or self.policy.enabled_frameworks
        self.loader = ArtifactLoader()
        self._llm: Optional[Any] = None
        # KEV client — created lazily; injectable for testing
        self._kev_client: Optional[Any] = _kev_client
        self._kev_enabled = kev_enabled
        # CPE & related CVE options (Capabilities 1–3)
        self.enrich_cpe = enrich_cpe
        self.max_related_cves = max_related_cves

    def scan(
        self,
        path: str,
        domain_override: Optional[str] = None,
        frameworks_override: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan a single file or directory. Returns a fully enriched ScanResult."""
        t0 = time.monotonic()
        frameworks = frameworks_override or self.frameworks
        scan_id = f"RS-{uuid.uuid4().hex[:8].upper()}"

        log.info("Starting scan %s: %s", scan_id, path)

        # Load artifact(s)
        try:
            artifacts = self.loader.load(path)
        except FileNotFoundError as exc:
            return ScanResult(
                scan_id=scan_id,
                artifact_path=path,
                artifact_type="unknown",
                domains_run=[],
                error=str(exc),
            )

        all_findings: List[Finding] = []
        all_suppressed: List[Finding] = []
        domains_run: set = set()
        artifact_type = artifacts[0].file_type if artifacts else "unknown"
        combined_source_map: Dict[str, Any] = {}

        llm = self._get_llm() if self.policy.enrichment_enabled else None
        classifier = DomainClassifier(self.pack_client, llm)

        # Import analyzers lazily
        from risk_scanner.core.analyzers.static import StaticAnalyzer
        from risk_scanner.core.analyzers.behavioral import BehavioralAnalyzer
        from risk_scanner.core.analyzers.enrichment import EnrichmentAnalyzer
        from risk_scanner.core.analyzers.meta import MetaAnalyzer

        static_analyzer = StaticAnalyzer()
        behavioral_analyzer = BehavioralAnalyzer()
        kev_client = self._get_kev_client() if self._kev_enabled else None
        enrichment_analyzer = EnrichmentAnalyzer(
            self.pack_client, llm, frameworks,
            kev_client=kev_client,
            enrich_cpe=self.enrich_cpe,
            max_related_cves=self.max_related_cves,
        )
        meta_analyzer = MetaAnalyzer(llm if self.policy.meta_analysis_enabled else None)

        for artifact in artifacts:
            # Domain classification
            if domain_override:
                try:
                    detected_domains = [Domain(domain_override)]
                except ValueError:
                    detected_domains = classifier.classify(artifact)
            else:
                detected_domains = classifier.classify(artifact)

            domains_run.update(d.value for d in detected_domains)

            # Filter by policy
            active_domains = [
                d for d in detected_domains
                if self.policy.is_domain_enabled(d.value)
            ]
            if not active_domains:
                log.debug("No active domains for %s, skipping", artifact.path)
                continue

            # Run analyzers
            raw_findings: List[Finding] = []
            if static_analyzer.can_handle(artifact):
                raw_findings.extend(static_analyzer.analyze(artifact))
                # Collect per-component source_map built during SBOM analysis
                source_map = getattr(static_analyzer, "_last_source_map", {})
                combined_source_map.update(source_map)
            if behavioral_analyzer.can_handle(artifact):
                raw_findings.extend(behavioral_analyzer.analyze(artifact))

            # Filter by severity threshold and domain
            filtered = [
                f for f in raw_findings
                if self.policy.is_above_threshold(f.severity)
                and f.domain in active_domains
            ]

            # Enrichment
            findings_to_enrich = [
                f for f in filtered
                if self.policy.should_enrich(f.severity)
            ]
            skip_enrich = [f for f in filtered if f not in findings_to_enrich]

            if findings_to_enrich and self.policy.enrichment_enabled:
                enriched = enrichment_analyzer.enrich(findings_to_enrich)
            else:
                enriched = findings_to_enrich

            artifact_findings = enriched + skip_enrich

            # Cross-reference within this artifact
            artifact_findings = _compute_cross_refs(artifact_findings)

            all_findings.extend(artifact_findings)

        # Meta-analysis (dedup + FP filter across all artifacts)
        if self.policy.meta_analysis_enabled and all_findings:
            all_findings, suppressed = meta_analyzer.process(all_findings)
            all_suppressed.extend(suppressed)

        # Enforce max findings per domain
        if self.policy.max_findings_per_domain > 0:
            all_findings = _cap_findings(all_findings, self.policy.max_findings_per_domain)

        duration_ms = int((time.monotonic() - t0) * 1000)

        result = ScanResult(
            scan_id=scan_id,
            artifact_path=path,
            artifact_type=artifact_type,
            domains_run=[Domain(d) for d in sorted(domains_run)],
            findings=all_findings,
            suppressed=all_suppressed,
            scan_policy=self.policy.model_dump(mode="json"),
            duration_ms=duration_ms,
            pack_versions={d: "local" for d in domains_run},
            source_map=combined_source_map,
        )

        log.info(
            "Scan %s complete: %d findings (%d suppressed) in %dms",
            scan_id, len(all_findings), len(all_suppressed), duration_ms,
        )
        return result

    def scan_all(
        self,
        directory: str,
        domain_override: Optional[str] = None,
        frameworks_override: Optional[List[str]] = None,
    ) -> List[ScanResult]:
        """Scan all recognized files in a directory recursively."""
        from pathlib import Path
        results = []
        directory_path = Path(directory).expanduser().resolve()
        for fp in sorted(directory_path.rglob("*")):
            if fp.is_file():
                try:
                    result = self.scan(
                        str(fp),
                        domain_override=domain_override,
                        frameworks_override=frameworks_override,
                    )
                    if result.findings:
                        results.append(result)
                except Exception as exc:
                    log.warning("Scan failed for %s: %s", fp, exc)
        return results

    def _get_llm(self) -> Optional[Any]:
        if self._llm is None:
            try:
                from asteraskills.core.llm import get_llm
                self._llm = get_llm(temperature=0.1)
            except Exception as exc:
                log.debug("LLM not available (enrichment will use static rules): %s", exc)
        return self._llm

    def _get_kev_client(self) -> Any:
        if self._kev_client is None:
            from risk_scanner.core.kev_client import KevClient
            self._kev_client = KevClient()
        return self._kev_client


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _compute_cross_refs(findings: List[Finding]) -> List[Finding]:
    """Add cross_refs between findings that share a technique or component."""
    from collections import defaultdict
    technique_to_findings: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        for atk in f.attack_chain:
            technique_to_findings[atk.technique_id].append(f.id)

    for f in findings:
        refs: set = set()
        for atk in f.attack_chain:
            for other_id in technique_to_findings[atk.technique_id]:
                if other_id != f.id:
                    refs.add(other_id)
        f.cross_refs = list(refs)
    return findings


def _cap_findings(findings: List[Finding], max_per_domain: int) -> List[Finding]:
    from collections import defaultdict
    domain_counts: Dict[str, int] = defaultdict(int)
    result = []
    # Sort by severity desc first
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    sorted_findings = sorted(findings, key=lambda f: order.index(f.severity))
    for f in sorted_findings:
        domain_key = f.domain.value
        if domain_counts[domain_key] < max_per_domain:
            result.append(f)
            domain_counts[domain_key] += 1
    return result


from typing import Dict  # noqa: E402 — needed at module level for _cap_findings
