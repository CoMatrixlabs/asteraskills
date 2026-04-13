"""
Finding assertion schema for eval runner.

An assertion file is a YAML list of expected findings for a given fixture artifact.
Each entry specifies the fields that must match in the scan result.

Example YAML:
  - taxonomy_code: CVE-2024-3400
    domain: cve
    severity_min: HIGH
    has_technique: T1190
    control_framework: nist-800-53
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel


class FindingAssertion(BaseModel):
    """A single finding assertion to verify against a scan result."""

    # Required: must match exactly
    taxonomy_code: str

    # Optional: must match if specified
    domain: Optional[str] = None
    severity: Optional[str] = None         # exact severity
    severity_min: Optional[str] = None     # minimum severity (>= this level)
    confidence_min: Optional[float] = None

    # ATT&CK enrichment assertions
    has_technique: Optional[str] = None    # must include this technique ID
    has_tactic: Optional[str] = None       # must include this tactic

    # Control enrichment assertions
    control_framework: Optional[str] = None   # must have controls from this framework
    control_id: Optional[str] = None          # must include this specific control ID

    # Meta assertions
    not_suppressed: bool = True            # must appear in accepted (not suppressed) findings
    min_analyzer_sources: int = 1


class AssertionFile(BaseModel):
    """Top-level assertion file structure."""
    fixture_path: str
    description: Optional[str] = None
    domain_override: Optional[str] = None
    assertions: List[FindingAssertion]
