"""
CSV reporter — flat tabular output with all key Finding fields.
"""

from __future__ import annotations

import csv
import io

from risk_scanner.core.models import ScanResult
from risk_scanner.reporters import BaseReporter


class CSVReporter(BaseReporter):
    def render(self, result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "finding_id", "domain", "taxonomy_code", "severity", "confidence",
            "false_positive_score", "file_path", "line_start", "line_end",
            "matched_rule", "summary", "severity_rationale",
            "attack_techniques", "attack_tactics", "control_ids", "control_frameworks",
            "remediation", "cross_refs", "analyzer_sources", "pack_version",
        ])
        writer.writeheader()
        for f in result.findings:
            ev = f.evidence
            writer.writerow({
                "finding_id": f.id,
                "domain": f.domain.value,
                "taxonomy_code": f.taxonomy_code,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 3),
                "false_positive_score": round(f.false_positive_score, 3),
                "file_path": ev.file_path or "",
                "line_start": ev.line_start or "",
                "line_end": ev.line_end or "",
                "matched_rule": ev.matched_rule_id,
                "summary": f.summary,
                "severity_rationale": f.severity_rationale[:200],
                "attack_techniques": "|".join(a.technique_id for a in f.attack_chain),
                "attack_tactics": "|".join(a.tactic for a in f.attack_chain),
                "control_ids": "|".join(c.control_id for c in f.control_gaps),
                "control_frameworks": "|".join(c.framework for c in f.control_gaps),
                "remediation": f.remediation[:200],
                "cross_refs": "|".join(f.cross_refs),
                "analyzer_sources": "|".join(f.analyzer_sources),
                "pack_version": f.pack_version,
            })
        return output.getvalue()
