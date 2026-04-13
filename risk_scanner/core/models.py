"""
Risk Scanner core data models.

Every field maps directly to the design plan §4 schema.
"""

from __future__ import annotations

import hashlib
from datetime import date
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Domain(str, Enum):
    CVE       = "cve"
    CWE       = "cwe"
    ATTACK    = "attack"
    POLICY    = "policy"
    FRAMEWORK = "framework"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class SatisfactionStatus(str, Enum):
    SATISFIED = "satisfied"
    PARTIAL   = "partial"
    MISSING   = "missing"
    UNKNOWN   = "unknown"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class KevEntry(BaseModel):
    """CISA Known Exploited Vulnerabilities catalog entry for a CVE.

    Populated by KevClient.lookup() during CVE enrichment.
    ``in_kev=False`` means the CVE is not in the CISA catalog.
    """
    in_kev:                  bool

    # Catalog metadata — None when in_kev=False
    kev_date_added:          Optional[date] = None
    kev_due_date:            Optional[date] = None   # 14-day BOD 22-01 window
    days_until_due:          Optional[int]  = None   # negative = overdue

    # Risk signals
    ransomware_campaign_use: bool           = False
    ransomware_group:        Optional[str]  = None   # e.g. "Cl0p", "LockBit 3.0"
    required_action:         Optional[str]  = None   # CISA's required action text
    kev_notes:               Optional[str]  = None   # CISA additional context

    # Audit trail — filled in by EnrichmentAnalyzer after applying severity override
    severity_was_upgraded:   bool           = False
    pre_kev_severity:        Optional[str]  = None   # Severity enum value before override


class Evidence(BaseModel):
    file_path:       Optional[str] = None
    line_start:      Optional[int] = None
    line_end:        Optional[int] = None
    snippet:         Optional[str] = None
    matched_rule_id: str
    matched_pattern: Optional[str] = None


class AttackEnrichment(BaseModel):
    technique_id:   str           # e.g. T1190
    technique_name: str
    tactic:         str           # e.g. initial-access
    tactic_id:      Optional[str] = None  # e.g. TA-0001
    kill_chain_pos: int           # 1-indexed stage in kill chain
    confidence:     float = Field(ge=0.0, le=1.0)
    rationale:      str           # LLM-generated


class ControlEnrichment(BaseModel):
    control_id:        str        # e.g. SOC2-CC6.1, NIST-AC-2, CIS-1.4
    framework:         str        # soc2 | nist-800-53 | cis-8 | iso27001
    framework_version: str
    control_name:      str
    control_type:      Optional[str] = None   # preventive | detective | corrective
    satisfaction:      SatisfactionStatus
    gap_narrative:     Optional[str] = None   # LLM-generated; None if satisfied
    remediation:       str                    # LLM-generated
    priority:          Optional[str] = None   # immediate | 30-days | 90-days


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    # Identity
    id:                 str = ""
    domain:             Domain
    taxonomy_code:      str    # CVE-2024-1234 | CWE-89 | T1190 | CIS-1.4 | SOC2-CC6.1
    severity:           Severity
    severity_rationale: str    # LLM-generated

    # Detection
    evidence:             Evidence
    pack_version:         str = "local"
    confidence:           float = Field(default=0.8, ge=0.0, le=1.0)

    # Enrichment
    attack_chain:  List[AttackEnrichment] = Field(default_factory=list)
    control_gaps:  List[ControlEnrichment] = Field(default_factory=list)

    # Narrative (agent skill output)
    summary:     str = ""
    remediation: str = ""
    cross_refs:  List[str] = Field(default_factory=list)

    # KEV context — populated for CVE domain findings; None for all other domains
    kev_entry: Optional[KevEntry] = None
    # Structured KEV signals for reporting / PROMPT-11 (set when ``in_kev`` after lookup)
    kev_context: Optional[Dict[str, Any]] = None
    # CVE intelligence (NVD/EPSS shape from ``_execute_cve_enrich``) for rich markdown/JSON reports
    cve_detail: Optional[Dict[str, Any]] = None

    # CPE / SBOM source attribution (Capability 1 & 2)
    source_component: Optional[str] = None   # e.g. "openssl@3.0.7"
    source_cpe_uri:   Optional[str] = None   # canonical CPE URI resolved for this component
    cpe_matches:      List[Dict[str, Any]] = Field(default_factory=list)  # Stage 1.5 CPE match records
    cpe_enrichment_attempted: bool = False   # True when --cpe was passed (even if no matches found)

    # Related CVEs (Capability 3) — ranked sibling CVEs sharing ATT&CK techniques
    related_cves: List[Dict[str, Any]] = Field(default_factory=list)

    # Meta
    analyzer_sources:    List[str] = Field(default_factory=list)
    false_positive_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _compute_id(self) -> "Finding":
        if not self.id:
            raw = (
                f"{self.domain.value}"
                f"{self.taxonomy_code}"
                f"{self.evidence.file_path or ''}"
                f"{self.evidence.line_start or ''}"
            )
            self.id = "RS-" + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
        return self


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    scan_id:       str
    artifact_path: str
    artifact_type: str
    domains_run:   List[Domain]
    findings:      List[Finding] = Field(default_factory=list)
    suppressed:    List[Finding] = Field(default_factory=list)
    scan_policy:   Dict[str, Any] = Field(default_factory=dict)
    duration_ms:   Optional[int] = None
    pack_versions: Dict[str, str] = Field(default_factory=dict)
    error:         Optional[str] = None
    # SBOM per-component source map (Capability 2) — keyed by "name@version"
    source_map:    Dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None


class Report(BaseModel):
    title:        str
    generated_at: str
    scan_result:  ScanResult
    format:       str = "json"
    content:      str = ""


# ---------------------------------------------------------------------------
# Artifact (internal loader output — not exported from package)
# ---------------------------------------------------------------------------

class LoadedArtifact(BaseModel):
    """Internal model: output of the artifact loader."""
    path:              str
    raw_content:       bytes = b""
    text_content:      Optional[str] = None
    file_type:         str = "unknown"   # sbom-cyclonedx | sbom-spdx | terraform | k8s | python | etc.
    mime_type:         str = "application/octet-stream"
    detected_keywords: List[str] = Field(default_factory=list)
    manifest_keys:     List[str] = Field(default_factory=list)
    size_bytes:        int = 0
    archive_members:   List[str] = Field(default_factory=list)
    parsed_data:       Optional[Dict[str, Any]] = None  # pre-parsed JSON/YAML
