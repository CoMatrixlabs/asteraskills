"""
ScanPolicy — configurable thresholds and feature flags for a scan run.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from risk_scanner.core.models import Domain, Severity

_ALL_DOMAINS = [d.value for d in Domain]
_ALL_FRAMEWORKS = ["soc2", "nist-800-53", "cis-8", "iso27001"]


class ScanPolicy(BaseModel):
    """Controls which domains, frameworks, and severity levels are active."""

    # Which domains to run (default: all)
    enabled_domains: List[str] = Field(default_factory=lambda: list(_ALL_DOMAINS))

    # Which compliance frameworks to map controls to (default: all)
    enabled_frameworks: List[str] = Field(default_factory=lambda: list(_ALL_FRAMEWORKS))

    # Minimum severity to emit a finding (below this is suppressed)
    severity_threshold: Severity = Severity.LOW

    # Whether to run ATT&CK and control enrichment (requires LLM)
    enrichment_enabled: bool = True

    # Whether to run the meta-analyzer (FP filter + dedup)
    meta_analysis_enabled: bool = True

    # License token for the intelligence server (None = local mode)
    license_token: Optional[str] = None

    # Intelligence server URL
    server_url: str = "https://api.risk-scanner.io"

    # Maximum findings per domain before stopping (0 = unlimited)
    max_findings_per_domain: int = 0

    # Enrichment only runs when severity meets this minimum
    enrichment_min_severity: Severity = Severity.MEDIUM

    def is_domain_enabled(self, domain: str) -> bool:
        return domain in self.enabled_domains

    def is_above_threshold(self, severity: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(severity) >= order.index(self.severity_threshold)

    def should_enrich(self, severity: Severity) -> bool:
        if not self.enrichment_enabled:
            return False
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(severity) >= order.index(self.enrichment_min_severity)

    @classmethod
    def default(cls) -> "ScanPolicy":
        return cls()

    @classmethod
    def from_yaml(cls, path: str) -> "ScanPolicy":
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: str) -> None:
        import yaml
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
