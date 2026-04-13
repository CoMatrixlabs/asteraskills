"""
Eval runner — loads assertion YAML files, runs scanner against fixtures,
compares findings to expected assertions.

Usage:
    python -m evals.runner --assertions evals/assertions/ --fixture-dir tests/fixtures/
    python -m evals.runner --assertion evals/assertions/sbom_cve.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console
from rich.table import Table

console = Console()


def load_assertion_file(path: str) -> "AssertionFile":
    from evals.assertions.finding_schema import AssertionFile
    with open(path) as f:
        data = yaml.safe_load(f)
    return AssertionFile(**data)


def run_assertion_file(assertion_file: "AssertionFile") -> Dict[str, Any]:
    """Run scanner against the fixture and check all assertions. Returns result dict."""
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy

    policy = ScanPolicy(severity_threshold="INFO", meta_analysis_enabled=False)
    scanner = Scanner(policy=policy)

    scan_result = scanner.scan(
        assertion_file.fixture_path,
        domain_override=assertion_file.domain_override,
    )

    passed = []
    failed = []
    for assertion in assertion_file.assertions:
        result = _check_assertion(assertion, scan_result)
        if result["passed"]:
            passed.append(result)
        else:
            failed.append(result)

    return {
        "fixture": assertion_file.fixture_path,
        "description": assertion_file.description,
        "total": len(assertion_file.assertions),
        "passed": len(passed),
        "failed": len(failed),
        "pass_rate": len(passed) / max(len(assertion_file.assertions), 1),
        "failures": failed,
        "scan_id": scan_result.scan_id,
        "finding_count": len(scan_result.findings),
    }


def _check_assertion(assertion: Any, scan_result: Any) -> Dict[str, Any]:
    from risk_scanner.core.models import Severity

    _SEV_ORDER = [s.value for s in [
        Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
    ]]

    # Find matching finding(s)
    candidates = [
        f for f in scan_result.findings
        if f.taxonomy_code == assertion.taxonomy_code
    ]

    if not candidates:
        return {
            "passed": False,
            "assertion": assertion.taxonomy_code,
            "reason": f"No finding with taxonomy_code={assertion.taxonomy_code!r} found. "
                      f"Found: {[f.taxonomy_code for f in scan_result.findings[:10]]}",
        }

    # Check not_suppressed
    if assertion.not_suppressed:
        suppressed_codes = {f.taxonomy_code for f in scan_result.suppressed}
        if assertion.taxonomy_code in suppressed_codes and assertion.taxonomy_code not in {f.taxonomy_code for f in scan_result.findings}:
            return {
                "passed": False,
                "assertion": assertion.taxonomy_code,
                "reason": f"Finding {assertion.taxonomy_code!r} was suppressed.",
            }

    # Check each candidate finding against all assertion fields
    for finding in candidates:
        errors = []

        if assertion.domain and finding.domain.value != assertion.domain:
            errors.append(f"domain: expected {assertion.domain!r}, got {finding.domain.value!r}")

        if assertion.severity and finding.severity.value != assertion.severity.upper():
            errors.append(f"severity: expected {assertion.severity!r}, got {finding.severity.value!r}")

        if assertion.severity_min:
            min_idx = _SEV_ORDER.index(assertion.severity_min.upper())
            got_idx = _SEV_ORDER.index(finding.severity.value)
            if got_idx < min_idx:
                errors.append(f"severity_min: expected >= {assertion.severity_min!r}, got {finding.severity.value!r}")

        if assertion.confidence_min is not None and finding.confidence < assertion.confidence_min:
            errors.append(f"confidence_min: expected >= {assertion.confidence_min}, got {finding.confidence}")

        if assertion.has_technique:
            techniques = {a.technique_id for a in finding.attack_chain}
            if assertion.has_technique not in techniques:
                errors.append(f"has_technique: {assertion.has_technique!r} not in {sorted(techniques)}")

        if assertion.has_tactic:
            tactics = {a.tactic for a in finding.attack_chain}
            if assertion.has_tactic not in tactics:
                errors.append(f"has_tactic: {assertion.has_tactic!r} not in {sorted(tactics)}")

        if assertion.control_framework:
            frameworks = {c.framework for c in finding.control_gaps}
            if assertion.control_framework not in frameworks:
                errors.append(f"control_framework: {assertion.control_framework!r} not in {sorted(frameworks)}")

        if assertion.control_id:
            ctrl_ids = {c.control_id for c in finding.control_gaps}
            if assertion.control_id not in ctrl_ids:
                errors.append(f"control_id: {assertion.control_id!r} not in {sorted(ctrl_ids)}")

        if assertion.min_analyzer_sources > len(finding.analyzer_sources):
            errors.append(f"min_analyzer_sources: expected >= {assertion.min_analyzer_sources}, "
                          f"got {len(finding.analyzer_sources)}")

        if not errors:
            return {"passed": True, "assertion": assertion.taxonomy_code}

    # All candidates failed — report first candidate's failures
    return {
        "passed": False,
        "assertion": assertion.taxonomy_code,
        "reason": "; ".join(errors),
        "finding_id": candidates[0].id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Risk Scanner eval runner")
    parser.add_argument("--assertion", help="Single assertion YAML file")
    parser.add_argument("--assertions", help="Directory of assertion YAML files")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    if not args.assertion and not args.assertions:
        parser.print_help()
        return 1

    files = []
    if args.assertion:
        files.append(args.assertion)
    if args.assertions:
        d = Path(args.assertions)
        files.extend(str(p) for p in sorted(d.glob("*.yaml")) + list(d.glob("*.yml")))

    all_results = []
    for f in files:
        try:
            af = load_assertion_file(f)
            result = run_assertion_file(af)
            all_results.append(result)
        except Exception as exc:
            console.print(f"[red]Failed to run {f}: {exc}[/red]")
            all_results.append({"fixture": f, "error": str(exc), "passed": 0, "failed": 1, "total": 1})

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        _print_results_table(all_results)

    total_failed = sum(r.get("failed", 0) for r in all_results)
    return 1 if total_failed > 0 else 0


def _print_results_table(results: List[Dict[str, Any]]) -> None:
    table = Table(title="Eval Results")
    table.add_column("Fixture")
    table.add_column("Total")
    table.add_column("Passed", style="green")
    table.add_column("Failed", style="red")
    table.add_column("Pass Rate")
    for r in results:
        rate = f"{r.get('pass_rate', 0):.0%}"
        table.add_row(
            str(Path(r.get("fixture", "")).name),
            str(r.get("total", "?")),
            str(r.get("passed", "?")),
            str(r.get("failed", "?")),
            rate,
        )
        for failure in r.get("failures", []):
            console.print(f"  [red]FAIL[/red] {failure['assertion']}: {failure.get('reason', '')}")
    console.print(table)


if __name__ == "__main__":
    sys.exit(main())
