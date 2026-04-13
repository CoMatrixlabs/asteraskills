"""
Analyzer base class and registry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from risk_scanner.core.models import Finding, LoadedArtifact


class BaseAnalyzer(ABC):
    """Abstract base for all domain analyzers."""

    @abstractmethod
    def can_handle(self, artifact: "LoadedArtifact") -> bool:
        """Return True if this analyzer can process the artifact."""

    @abstractmethod
    def analyze(self, artifact: "LoadedArtifact") -> List[Finding]:
        """Run analysis and return raw (pre-enrichment) findings."""
