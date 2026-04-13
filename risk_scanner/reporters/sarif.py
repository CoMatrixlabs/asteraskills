"""
SARIF 2.1.0 reporter — GitHub Actions / VS Code compatible.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from risk_scanner.core.models import Finding, ScanResult
from risk_scanner.reporters import BaseReporter

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


class SARIFReporter(BaseReporter):
    def render(self, result: ScanResult) -> str:
        rules = self._build_rules(result.findings)
        results = [self._finding_to_sarif(f) for f in result.findings]
        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "risk-scanner",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/astera-skills/risk-scanner",
                            "rules": rules,
                        }
                    },
                    "artifacts": [
                        {"location": {"uri": result.artifact_path}, "length": -1}
                    ],
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": result.error is None,
                            "toolExecutionNotifications": (
                                [{"message": {"text": result.error}, "level": "error"}]
                                if result.error else []
                            ),
                        }
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        seen = {}
        for f in findings:
            if f.taxonomy_code not in seen:
                seen[f.taxonomy_code] = {
                    "id": f.taxonomy_code,
                    "name": f.taxonomy_code.replace("-", "").replace(".", "_"),
                    "shortDescription": {"text": f.summary or f.taxonomy_code},
                    "fullDescription": {"text": f.severity_rationale},
                    "defaultConfiguration": {
                        "level": _SEVERITY_LEVEL.get(f.severity.value, "warning")
                    },
                    "properties": {
                        "domain": f.domain.value,
                        "tags": [f.domain.value],
                    },
                }
        return list(seen.values())

    def _finding_to_sarif(self, finding: Finding) -> Dict[str, Any]:
        ev = finding.evidence
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": ev.file_path or ""},
            }
        }
        if ev.line_start is not None:
            location["physicalLocation"]["region"] = {
                "startLine": ev.line_start,
                "endLine": ev.line_end or ev.line_start,
            }

        result: Dict[str, Any] = {
            "ruleId": finding.taxonomy_code,
            "level": _SEVERITY_LEVEL.get(finding.severity.value, "warning"),
            "message": {
                "text": f"{finding.summary or finding.taxonomy_code}. {finding.remediation}"
            },
            "locations": [location],
            "fingerprints": {"primary/v1": finding.id},
            "properties": {
                "risk_scanner_id": finding.id,
                "domain": finding.domain.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "false_positive_score": finding.false_positive_score,
                "attack_techniques": [
                    a.technique_id for a in finding.attack_chain
                ],
                "control_gaps": [
                    f"{c.control_id} ({c.framework})"
                    for c in finding.control_gaps
                ],
            },
        }
        if finding.cross_refs:
            result["relatedLocations"] = [
                {"id": i, "message": {"text": ref_id}}
                for i, ref_id in enumerate(finding.cross_refs)
            ]
        return result
