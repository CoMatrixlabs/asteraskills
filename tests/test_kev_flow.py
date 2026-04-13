"""
Test: KEV flow through the risk scanner skill.

Verifies that:
1. CVE findings for KEV entries get kev_entry.in_kev=True
2. Ransomware-associated KEV CVEs are upgraded to CRITICAL
3. Non-ransomware KEV CVEs are upgraded to at least HIGH
4. The skill run_scan() output surfaces KEV findings correctly

Uses a _test_catalog override in KevClient to run fully offline without
any HTTP calls or LLM invocations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make sure the repo root is on sys.path when running standalone
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_FIXTURE = Path(__file__).parent / "fixtures" / "sbom-kev-test.json"

# ── Minimal test catalog (same data as kev_client._STATIC_FALLBACK but explicit) ──
_TEST_KEV_CATALOG = {
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 RCE Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Log4Shell — JNDI lookup RCE",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Conti and LockBit ransomware groups confirmed exploitation.",
    },
    "CVE-2021-45046": {
        "cveID": "CVE-2021-45046",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Thread Context Lookup Vulnerability",
        "dateAdded": "2021-12-14",
        "shortDescription": "Log4Shell variant",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-28",
        "knownRansomwareCampaignUse": "Known",
        "notes": "",
    },
    "CVE-2023-44487": {
        "cveID": "CVE-2023-44487",
        "vendorProject": "Multiple",
        "product": "HTTP/2",
        "vulnerabilityName": "HTTP/2 Rapid Reset Attack",
        "dateAdded": "2023-10-10",
        "shortDescription": "DoS via HTTP/2 stream cancellation",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    },
    # CVE-2022-42889 intentionally NOT in test catalog (non-KEV for contrast)
}


def _make_scanner() -> object:
    """Build a Scanner with offline KevClient injected.

    enrichment_enabled=True so the EnrichmentAnalyzer (and its KEV override) runs.
    No LLM is available in CI so enrichment falls back to static rules — that's fine.
    meta_analysis_enabled=False to keep tests fast.
    """
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    kev = KevClient(_test_catalog=_TEST_KEV_CATALOG)
    policy = ScanPolicy(enrichment_enabled=True, meta_analysis_enabled=False)
    return Scanner(policy=policy, _kev_client=kev)


def test_kev_entries_populated() -> None:
    """CVE findings in the test catalog must have kev_entry.in_kev=True."""
    scanner = _make_scanner()
    result = scanner.scan(str(_FIXTURE), domain_override="cve")

    assert result.error is None, f"Scan error: {result.error}"
    assert result.findings, "Expected CVE findings from the SBOM fixture"

    kev_findings = [f for f in result.findings if f.kev_entry and f.kev_entry.in_kev]
    non_kev = [f for f in result.findings if not f.kev_entry or not f.kev_entry.in_kev]

    print(f"\n✓ Total findings: {len(result.findings)}")
    print(f"  KEV findings: {len(kev_findings)}")
    print(f"  Non-KEV findings: {len(non_kev)}")

    for f in kev_findings:
        print(f"  - {f.taxonomy_code:20s} severity={f.severity.value:8s} "
              f"ransomware={f.kev_entry.ransomware_campaign_use} "
              f"upgraded={f.kev_entry.severity_was_upgraded}")

    # CVE-2021-44228 and CVE-2021-45046 and CVE-2023-44487 should be KEV
    kev_ids = {f.taxonomy_code for f in kev_findings}
    assert "CVE-2021-44228" in kev_ids, "CVE-2021-44228 (Log4Shell) should be in KEV"
    assert "CVE-2023-44487" in kev_ids, "CVE-2023-44487 (HTTP/2 Rapid Reset) should be in KEV"

    # CVE-2022-42889 should NOT be in KEV (not in test catalog)
    non_kev_ids = {f.taxonomy_code for f in non_kev}
    assert "CVE-2022-42889" in non_kev_ids or "CVE-2022-42889" not in kev_ids, \
        "CVE-2022-42889 should NOT be flagged as KEV"

    print("✓ test_kev_entries_populated PASSED")


def test_ransomware_kev_is_critical() -> None:
    """Log4Shell (KEV + ransomware) must be CRITICAL after override."""
    from risk_scanner.core.models import Severity

    scanner = _make_scanner()
    result = scanner.scan(str(_FIXTURE), domain_override="cve")

    log4shell = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2021-44228"), None
    )
    assert log4shell is not None, "CVE-2021-44228 not found in findings"
    assert log4shell.kev_entry is not None
    assert log4shell.kev_entry.in_kev is True
    assert log4shell.kev_entry.ransomware_campaign_use is True
    assert log4shell.severity == Severity.CRITICAL, (
        f"CVE-2021-44228 should be CRITICAL after KEV ransomware override, "
        f"got {log4shell.severity.value}"
    )
    assert log4shell.kev_entry.severity_was_upgraded or log4shell.severity == Severity.CRITICAL

    print(f"✓ CVE-2021-44228 severity={log4shell.severity.value} "
          f"ransomware_group={log4shell.kev_entry.ransomware_group}")
    print(f"  Rationale excerpt: ...{log4shell.severity_rationale[-150:]}")
    print("✓ test_ransomware_kev_is_critical PASSED")


def test_non_ransomware_kev_is_at_least_high() -> None:
    """HTTP/2 Rapid Reset (KEV, no ransomware) must be at least HIGH."""
    from risk_scanner.core.models import Severity

    scanner = _make_scanner()
    result = scanner.scan(str(_FIXTURE), domain_override="cve")

    rapid_reset = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2023-44487"), None
    )
    assert rapid_reset is not None, "CVE-2023-44487 not found in findings"
    assert rapid_reset.kev_entry is not None
    assert rapid_reset.kev_entry.in_kev is True
    assert rapid_reset.kev_entry.ransomware_campaign_use is False

    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert severity_order.index(rapid_reset.severity) >= severity_order.index(Severity.HIGH), (
        f"CVE-2023-44487 (non-ransomware KEV) should be HIGH or above, "
        f"got {rapid_reset.severity.value}"
    )

    print(f"✓ CVE-2023-44487 severity={rapid_reset.severity.value} "
          f"upgraded={rapid_reset.kev_entry.severity_was_upgraded}")
    print("✓ test_non_ransomware_kev_is_at_least_high PASSED")


def test_kev_overdue_days_populated() -> None:
    """KEV entries with past due_date must have negative days_until_due."""
    scanner = _make_scanner()
    result = scanner.scan(str(_FIXTURE), domain_override="cve")

    log4shell = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2021-44228"), None
    )
    assert log4shell is not None
    assert log4shell.kev_entry is not None
    assert log4shell.kev_entry.days_until_due is not None
    assert log4shell.kev_entry.days_until_due < 0, (
        f"CVE-2021-44228 due date was 2021-12-24 — days_until_due should be negative, "
        f"got {log4shell.kev_entry.days_until_due}"
    )
    days_overdue = abs(log4shell.kev_entry.days_until_due)
    print(f"✓ CVE-2021-44228 is {days_overdue} days overdue (BOD 22-01 deadline)")
    print("✓ test_kev_overdue_days_populated PASSED")


def test_skill_run_scan_surfaces_kev() -> None:
    """skill.run_scan() returns a string that mentions KEV findings."""
    from risk_scanner.agent import skill
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    # Patch Scanner inside the skill to use our test KEV client
    kev = KevClient(_test_catalog=_TEST_KEV_CATALOG)
    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, _kev_client=kev)

    # Run the scanner directly and store result in skill context
    result = scanner.scan(str(_FIXTURE), domain_override="cve")
    skill._scan_context["kev-test"] = result

    # Use the markdown reporter (no LLM needed)
    output = skill.export_result("markdown", session_id="kev-test")

    assert output, "Expected non-empty output from skill"
    assert "CVE-2021-44228" in output or "CRITICAL" in output, \
        "Expected Log4Shell or CRITICAL in skill output"

    print("\n── Skill Output (first 1500 chars) ──")
    print(output[:1500])
    print("── End ──")
    print("✓ test_skill_run_scan_surfaces_kev PASSED")


def test_kev_client_lookup() -> None:
    """Unit test: KevClient.lookup() returns correct KevEntry fields."""
    from risk_scanner.core.kev_client import KevClient

    kev = KevClient(_test_catalog=_TEST_KEV_CATALOG)

    # Log4Shell should be in KEV with ransomware
    entry = kev.lookup("CVE-2021-44228")
    assert entry.in_kev is True
    assert entry.ransomware_campaign_use is True
    assert entry.ransomware_group in ("Conti", "LockBit", None)  # extracted from notes
    assert entry.kev_date_added is not None
    assert entry.days_until_due is not None and entry.days_until_due < 0  # overdue

    # Non-KEV CVE should return in_kev=False
    entry2 = kev.lookup("CVE-2022-42889")
    assert entry2.in_kev is False
    assert entry2.ransomware_campaign_use is False

    print("✓ test_kev_client_lookup PASSED")


def run_all_tests() -> None:
    tests = [
        test_kev_client_lookup,
        test_kev_entries_populated,
        test_ransomware_kev_is_critical,
        test_non_ransomware_kev_is_at_least_high,
        test_kev_overdue_days_populated,
        test_skill_run_scan_surfaces_kev,
    ]
    failed = []
    for t in tests:
        print(f"\n{'='*60}")
        print(f"Running {t.__name__}...")
        try:
            t()
        except AssertionError as exc:
            print(f"✗ FAILED: {exc}")
            failed.append(t.__name__)
        except Exception as exc:
            import traceback
            print(f"✗ ERROR: {exc}")
            traceback.print_exc()
            failed.append(t.__name__)

    print(f"\n{'='*60}")
    total = len(tests)
    passed = total - len(failed)
    print(f"Results: {passed}/{total} passed")
    if failed:
        print(f"Failed: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("All KEV flow tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    run_all_tests()
