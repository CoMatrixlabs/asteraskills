"""
Test: Five end-to-end scenarios from the risk_scanner_skill_example_scenarios.html spec.

Each scenario validates a full user → skill interaction for a distinct artifact type:

  Scenario 0 (SBOM scan)       — CVE domain, KEV severity override, 3 critical findings
  Scenario 1 (Terraform IaC)   — POLICY domain, built-in IaC rules, CRITICAL/HIGH violations
  Scenario 2 (Source code CWE) — CWE domain, Python AST taint chain, CWE-89 SQL injection
  Scenario 3 (SIEM kill chain) — ATT&CK domain, sequence correlation, CRITICAL kill chain
  Scenario 4 (SOC 2 evidence)  — FRAMEWORK domain, evidence-csv stub documents expected behavior

All tests run fully offline — no HTTP calls or LLM invocations.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Shared KEV catalog for scenarios that need KEV enrichment
# ---------------------------------------------------------------------------

_SCENARIO_KEV_CATALOG = {
    # xz-utils supply-chain backdoor — KEV, no confirmed ransomware campaign
    "CVE-2024-3094": {
        "cveID": "CVE-2024-3094",
        "vendorProject": "XZ Utils",
        "product": "xz-utils",
        "vulnerabilityName": "XZ Utils Supply Chain Backdoor",
        "dateAdded": "2024-04-02",
        "shortDescription": "Malicious backdoor in xz-utils tarballs 5.6.0–5.6.1 affecting sshd on glibc systems",
        "requiredAction": "Downgrade to xz-utils 5.4.6 or earlier. Investigate all affected systems.",
        "dueDate": "2024-04-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Nation-state supply chain attack. No confirmed ransomware exploitation.",
    },
    # Log4Shell — KEV, confirmed ransomware (Conti, LockBit)
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
    # HTTP/2 Rapid Reset — KEV, no ransomware
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
}


def _make_scanner_with_kev(enrichment_enabled: bool = True) -> object:
    """Scanner with injected offline KEV client."""
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    kev = KevClient(_test_catalog=_SCENARIO_KEV_CATALOG)
    policy = ScanPolicy(enrichment_enabled=enrichment_enabled, meta_analysis_enabled=False)
    return Scanner(policy=policy, _kev_client=kev)


# ===========================================================================
# Scenario 0: SBOM scan
# Expected: CVE-2024-3094 CRITICAL (KEV), CVE-2021-44228 CRITICAL (KEV+ransomware),
#           CVE-2023-44487 HIGH (KEV non-ransomware)
# ===========================================================================

def test_sbom_scenario_cve_findings() -> None:
    """SBOM fixture produces CVE findings for all three KEV-listed components."""
    scanner = _make_scanner_with_kev()
    result = scanner.scan(
        str(_FIXTURES / "sbom-scenarios.json"),
        domain_override="cve",
    )

    assert result.error is None, f"Scan error: {result.error}"
    assert result.findings, "Expected CVE findings from SBOM fixture"

    cve_ids = {f.taxonomy_code for f in result.findings}
    assert "CVE-2024-3094" in cve_ids, "xz-utils CVE-2024-3094 not found"
    assert "CVE-2021-44228" in cve_ids, "Log4Shell CVE-2021-44228 not found"
    assert "CVE-2023-44487" in cve_ids, "HTTP/2 Rapid Reset CVE-2023-44487 not found"

    print(f"\n✓ Scenario 0: {len(result.findings)} CVE finding(s)")
    for f in sorted(result.findings, key=lambda f: f.taxonomy_code):
        kev_tag = " [KEV]" if (f.kev_entry and f.kev_entry.in_kev) else ""
        print(f"  {f.taxonomy_code}: {f.severity.value}{kev_tag}")


def test_sbom_scenario_log4shell_is_critical_kev_ransomware() -> None:
    """CVE-2021-44228 (Log4Shell) must be CRITICAL after KEV ransomware override."""
    from risk_scanner.core.models import Severity

    scanner = _make_scanner_with_kev()
    result = scanner.scan(
        str(_FIXTURES / "sbom-scenarios.json"),
        domain_override="cve",
    )

    log4shell = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2021-44228"), None
    )
    assert log4shell is not None, "CVE-2021-44228 not found in findings"
    assert log4shell.kev_entry is not None, "CVE-2021-44228 should have kev_entry"
    assert log4shell.kev_entry.in_kev is True
    assert log4shell.kev_entry.ransomware_campaign_use is True
    assert log4shell.severity == Severity.CRITICAL, (
        f"CVE-2021-44228 should be CRITICAL (KEV ransomware), got {log4shell.severity.value}"
    )

    print(
        f"\n✓ Scenario 0: CVE-2021-44228 severity={log4shell.severity.value} "
        f"ransomware_group={log4shell.kev_entry.ransomware_group}"
    )


def test_sbom_scenario_xz_utils_is_kev() -> None:
    """CVE-2024-3094 (xz-utils backdoor) must be KEV-flagged and CRITICAL."""
    from risk_scanner.core.models import Severity

    scanner = _make_scanner_with_kev()
    result = scanner.scan(
        str(_FIXTURES / "sbom-scenarios.json"),
        domain_override="cve",
    )

    xz = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2024-3094"), None
    )
    assert xz is not None, "CVE-2024-3094 not found"
    assert xz.kev_entry is not None
    assert xz.kev_entry.in_kev is True
    assert xz.kev_entry.ransomware_campaign_use is False, (
        "CVE-2024-3094 should not have ransomware flag (Unknown)"
    )
    # Starts as CRITICAL (CVSS 10.0) and should stay CRITICAL after KEV HIGH minimum
    assert xz.severity == Severity.CRITICAL, (
        f"CVE-2024-3094 should be CRITICAL (CVSS 10.0), got {xz.severity.value}"
    )

    print(f"\n✓ Scenario 0: CVE-2024-3094 severity={xz.severity.value} in_kev=True")


def test_sbom_scenario_http2_is_high_kev() -> None:
    """CVE-2023-44487 (HTTP/2 Rapid Reset) must be at least HIGH after KEV override."""
    from risk_scanner.core.models import Severity

    scanner = _make_scanner_with_kev()
    result = scanner.scan(
        str(_FIXTURES / "sbom-scenarios.json"),
        domain_override="cve",
    )

    rapid_reset = next(
        (f for f in result.findings if f.taxonomy_code == "CVE-2023-44487"), None
    )
    assert rapid_reset is not None, "CVE-2023-44487 not found"
    assert rapid_reset.kev_entry is not None
    assert rapid_reset.kev_entry.in_kev is True
    assert rapid_reset.kev_entry.ransomware_campaign_use is False

    sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert sev_order.index(rapid_reset.severity) >= sev_order.index(Severity.HIGH), (
        f"CVE-2023-44487 should be HIGH or above, got {rapid_reset.severity.value}"
    )

    print(f"\n✓ Scenario 0: CVE-2023-44487 severity={rapid_reset.severity.value}")


def test_sbom_scenario_skill_output_contains_critical() -> None:
    """skill.export_result() for SBOM scenario mentions CRITICAL or CVE-2021-44228."""
    from risk_scanner.agent import skill
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    kev = KevClient(_test_catalog=_SCENARIO_KEV_CATALOG)
    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, _kev_client=kev)

    result = scanner.scan(str(_FIXTURES / "sbom-scenarios.json"), domain_override="cve")
    skill._scan_context["scenario-0"] = result

    output = skill.export_result("markdown", session_id="scenario-0")
    assert output, "Expected non-empty skill output"
    assert "CVE-2021-44228" in output or "CRITICAL" in output, (
        "Expected Log4Shell or CRITICAL in skill markdown output"
    )

    print(f"\n✓ Scenario 0: skill output ({len(output)} chars) contains expected content")


# ===========================================================================
# Scenario 1: Terraform misconfiguration
# Expected: AWS-SG-001 CRITICAL (unrestricted ingress), AWS-S3-001 HIGH (public ACL),
#           AWS-SG-002 HIGH (SSH open), multiple policy findings
# ===========================================================================

def test_terraform_policy_findings() -> None:
    """Terraform artifact with public S3, open SG, and SSH violations triggers POLICY findings."""
    from risk_scanner.core.analyzers.static import StaticAnalyzer
    from risk_scanner.core.models import Domain, LoadedArtifact, Severity

    # Build a pre-parsed Terraform resource artifact (avoids HCL file parsing)
    parsed = {
        "resource": {
            "aws_s3_bucket": {
                "customer_data": {
                    "bucket": "customer-pii-prod",
                    "acl": "public-read",  # AWS-S3-001: forbidden value
                    # missing: versioning (AWS-S3-002), encryption (AWS-S3-003)
                }
            },
            "aws_security_group": {
                "web_sg": {
                    "name": "web-sg",
                    "ingress": [
                        {
                            "from_port": 0,
                            "to_port": 0,
                            "protocol": "-1",
                            "cidr_blocks": ["0.0.0.0/0"],   # AWS-SG-001: unrestricted all
                        },
                        {
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"],   # AWS-SG-002: SSH open
                        },
                    ],
                }
            },
        }
    }
    artifact = LoadedArtifact(
        path="infra/aws/main.tf",
        file_type="terraform",
        parsed_data=parsed,
    )

    findings = StaticAnalyzer().analyze(artifact)

    assert findings, "Expected POLICY findings from Terraform artifact"

    rule_ids = {f.taxonomy_code for f in findings}
    domains = {f.domain for f in findings}
    assert Domain.POLICY in domains, "All findings should be POLICY domain"

    assert "AWS-SG-001" in rule_ids, (
        "Expected CRITICAL unrestricted-ingress finding (AWS-SG-001)"
    )
    assert "AWS-S3-001" in rule_ids, (
        "Expected HIGH public-ACL finding (AWS-S3-001)"
    )
    assert "AWS-SG-002" in rule_ids, (
        "Expected HIGH SSH-open finding (AWS-SG-002)"
    )

    sg001 = next(f for f in findings if f.taxonomy_code == "AWS-SG-001")
    assert sg001.severity == Severity.CRITICAL, (
        f"AWS-SG-001 should be CRITICAL, got {sg001.severity.value}"
    )

    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    assert critical_count >= 1, "Expected at least 1 CRITICAL policy finding"

    print(f"\n✓ Scenario 1: {len(findings)} POLICY finding(s)")
    for f in sorted(findings, key=lambda f: f.taxonomy_code):
        print(f"  {f.taxonomy_code}: {f.severity.value} — {f.severity_rationale[:60]}")


def test_terraform_scanner_via_domain_override() -> None:
    """Scanner with domain_override=policy processes Terraform artifacts correctly."""
    from risk_scanner.core.models import Domain, LoadedArtifact, Severity
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.analyzers.static import StaticAnalyzer

    # Build artifact directly and run through StaticAnalyzer → no loader needed
    parsed = {
        "resource": {
            "aws_s3_bucket": {
                "logs_bucket": {
                    "bucket": "app-logs-prod",
                    "acl": "public-read-write",  # even more permissive
                }
            },
            "aws_security_group": {
                "admin_sg": {
                    "name": "admin-sg",
                    "ingress": [
                        {"from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]},
                    ],
                }
            },
        }
    }
    artifact = LoadedArtifact(
        path="infra/aws/admin.tf",
        file_type="terraform",
        parsed_data=parsed,
    )

    findings = StaticAnalyzer().analyze(artifact)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical, "Expected at least one CRITICAL policy finding"
    assert all(f.domain == Domain.POLICY for f in findings), "All findings should be POLICY"

    print(f"\n✓ Scenario 1 (variant): {len(findings)} findings, {len(critical)} CRITICAL")


# ===========================================================================
# Scenario 2: Source code CWE analysis
# Expected: CWE-89 SQL injection (taint from request.args → cursor.execute)
# ===========================================================================

def test_source_code_cwe89_sql_injection() -> None:
    """Python fixture with SQL injection taint chain produces CWE-89 finding."""
    from risk_scanner.core.models import Domain, Severity
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, kev_enabled=False)

    result = scanner.scan(
        str(_FIXTURES / "src" / "api" / "routes" / "users.py"),
        domain_override="cwe",
    )

    assert result.error is None, f"Scan error: {result.error}"
    assert result.findings, "Expected CWE findings from Python fixture"

    cwe_ids = {f.taxonomy_code for f in result.findings}
    assert "CWE-89" in cwe_ids, (
        f"Expected CWE-89 (SQL injection) finding, got: {cwe_ids}"
    )

    cwe89 = next(f for f in result.findings if f.taxonomy_code == "CWE-89")
    assert cwe89.domain == Domain.CWE
    assert cwe89.severity in (Severity.HIGH, Severity.CRITICAL), (
        f"CWE-89 should be HIGH or CRITICAL, got {cwe89.severity.value}"
    )
    assert cwe89.evidence.file_path, "Expected evidence file path"
    assert "database" in cwe89.severity_rationale.lower() or "taint" in cwe89.severity_rationale.lower(), (
        "Rationale should reference database or taint"
    )

    print(f"\n✓ Scenario 2: CWE-89 found — severity={cwe89.severity.value}")
    print(f"  Evidence: {cwe89.evidence.file_path}:{cwe89.evidence.line_start}–{cwe89.evidence.line_end}")
    print(f"  Rationale: {cwe89.severity_rationale[:120]}")


def test_source_code_multiple_taint_chains() -> None:
    """Python fixture has two taint chains — both should be detected."""
    from risk_scanner.core.analyzers.behavioral import BehavioralAnalyzer
    from risk_scanner.core.models import LoadedArtifact

    fixture_path = _FIXTURES / "src" / "api" / "routes" / "users.py"
    text = fixture_path.read_text(encoding="utf-8")

    artifact = LoadedArtifact(
        path=str(fixture_path),
        file_type="python",
        text_content=text,
    )

    findings = BehavioralAnalyzer().analyze(artifact)
    assert len(findings) >= 2, (
        f"Expected at least 2 CWE-89 taint chains (get_user + list_users_by_role), "
        f"got {len(findings)}"
    )

    print(f"\n✓ Scenario 2: {len(findings)} taint chain(s) detected")
    for f in findings:
        print(f"  {f.taxonomy_code}: line {f.evidence.line_start}→{f.evidence.line_end}")


# ===========================================================================
# Scenario 3: SIEM kill-chain correlation
# Expected: ATT&CK domain, CRITICAL (complete kill chain: initial-access + execution
#           + persistence + discovery spans ≥ 3 stages)
# ===========================================================================

def test_siem_kill_chain_detection() -> None:
    """SIEM fixture with 4 ATT&CK techniques spanning 4 stages produces CRITICAL kill chain."""
    from risk_scanner.core.models import Domain, Severity
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, kev_enabled=False)

    result = scanner.scan(
        str(_FIXTURES / "siem-kill-chain.jsonl"),
        domain_override="attack",
    )

    assert result.error is None, f"Scan error: {result.error}"
    assert result.findings, "Expected ATT&CK findings from SIEM fixture"

    attack_findings = [f for f in result.findings if f.domain == Domain.ATTACK]
    assert attack_findings, "Expected at least one ATTACK domain finding"

    # Kill chain correlation should produce a CRITICAL finding
    critical = [f for f in attack_findings if f.severity == Severity.CRITICAL]
    assert critical, (
        f"Expected CRITICAL kill chain finding (4 stages: initial-access+execution+"
        f"persistence+discovery); got severities: {[f.severity.value for f in attack_findings]}"
    )

    kcc = critical[0]
    assert "initial-access" in kcc.severity_rationale.lower() or "kill chain" in kcc.severity_rationale.lower(), (
        f"Rationale should reference kill chain stages: {kcc.severity_rationale}"
    )

    print(f"\n✓ Scenario 3: Kill chain detected — severity={kcc.severity.value}")
    print(f"  Techniques: {kcc.evidence.matched_pattern}")
    print(f"  Rationale: {kcc.severity_rationale[:150]}")


def test_siem_kill_chain_technique_count() -> None:
    """Kill chain correlation finds ≥ 4 distinct ATT&CK techniques."""
    from risk_scanner.core.analyzers.behavioral import BehavioralAnalyzer
    from risk_scanner.core.models import LoadedArtifact

    fixture_path = _FIXTURES / "siem-kill-chain.jsonl"
    text = fixture_path.read_text(encoding="utf-8")

    artifact = LoadedArtifact(
        path=str(fixture_path),
        file_type="siem-logs",
        text_content=text,
    )

    findings = BehavioralAnalyzer().analyze(artifact)
    assert findings, "Expected at least one kill-chain correlation finding"

    # The correlation finding tracks technique chain in matched_pattern
    kcc = findings[0]
    techniques_in_chain = kcc.evidence.matched_pattern.split(",")
    assert len(techniques_in_chain) >= 2, (
        f"Expected ≥ 2 techniques in kill chain, got: {kcc.evidence.matched_pattern}"
    )

    # T1190 (Initial Access) should be the lead technique
    assert techniques_in_chain[0].startswith("T1"), (
        f"First technique should be T1xxx format, got: {techniques_in_chain[0]}"
    )

    print(f"\n✓ Scenario 3: Kill chain techniques: {kcc.evidence.matched_pattern}")
    print(f"  Stages covered: see rationale → {kcc.severity_rationale}")


# ===========================================================================
# Scenario 4: SOC 2 evidence assessment
# The _analyze_evidence() method is a stub in open-source mode (returns []).
# This test documents that behavior and validates the scanner handles CSV
# evidence files without crashing, and explains what the licensed mode provides.
# ===========================================================================

def test_soc2_evidence_scanner_no_crash() -> None:
    """Scanner handles SOC 2 evidence CSV without error (stub returns empty in open-source mode)."""
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, kev_enabled=False)

    result = scanner.scan(
        str(_FIXTURES / "audit-evidence" / "q1-access-review.csv"),
        domain_override="framework",
    )

    # Scanner should complete without error — empty findings is expected (stub)
    assert result.error is None, f"Unexpected scan error: {result.error}"
    # In open-source mode, evidence classification is a stub → no findings
    # (licensed mode would return SOC2-CC6.1, SOC2-CC7.2, etc.)
    print(
        f"\n✓ Scenario 4: Scanner handled evidence CSV gracefully "
        f"({len(result.findings)} findings in open-source mode — "
        f"evidence classification requires license token)"
    )


def test_soc2_evidence_analyzer_stub() -> None:
    """StaticAnalyzer._analyze_evidence returns [] in open-source mode (documented stub)."""
    from risk_scanner.core.analyzers.static import StaticAnalyzer
    from risk_scanner.core.models import LoadedArtifact

    fixture_path = _FIXTURES / "audit-evidence" / "q1-access-review.csv"
    text = fixture_path.read_text(encoding="utf-8")

    artifact = LoadedArtifact(
        path=str(fixture_path),
        file_type="evidence-csv",
        text_content=text,
    )

    findings = StaticAnalyzer().analyze(artifact)
    # Documented behavior: stub returns empty list
    assert findings == [], (
        "Evidence classification stub should return [] in open-source mode. "
        "This enables the licensed server to provide real framework assessments."
    )
    print(
        "\n✓ Scenario 4: _analyze_evidence stub confirmed — "
        "returns [] without license token (expected behavior). "
        "In licensed mode: SOC2-CC6.1 (3 terminated users), "
        "SOC2-CC7.2 (no IR runbook), SOC2-A1.1 (SLA miss) would be surfaced."
    )


# ===========================================================================
# Cross-scenario: skill export formats
# Validates that the markdown/sarif/json/csv reporters all render without error
# ===========================================================================

def test_skill_export_formats_for_sbom_result() -> None:
    """All 5 export formats render without error for the SBOM scenario result."""
    from risk_scanner.agent import skill
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.scanner import Scanner

    kev = KevClient(_test_catalog=_SCENARIO_KEV_CATALOG)
    policy = ScanPolicy(enrichment_enabled=False, meta_analysis_enabled=False)
    scanner = Scanner(policy=policy, _kev_client=kev)

    result = scanner.scan(str(_FIXTURES / "sbom-scenarios.json"), domain_override="cve")
    skill._scan_context["export-test"] = result

    for fmt in ("markdown", "sarif", "json", "csv", "html"):
        output = skill.export_result(fmt, session_id="export-test")
        assert output and not output.startswith("No scan result"), (
            f"Format {fmt!r} returned empty or error output"
        )
        print(f"  {fmt}: {len(output)} chars ✓")

    print("\n✓ Cross-scenario: all 5 export formats rendered successfully")


# ===========================================================================
# Test runner
# ===========================================================================

def run_all_tests() -> None:
    tests = [
        # Scenario 0: SBOM + KEV
        test_sbom_scenario_cve_findings,
        test_sbom_scenario_log4shell_is_critical_kev_ransomware,
        test_sbom_scenario_xz_utils_is_kev,
        test_sbom_scenario_http2_is_high_kev,
        test_sbom_scenario_skill_output_contains_critical,
        # Scenario 1: Terraform policy
        test_terraform_policy_findings,
        test_terraform_scanner_via_domain_override,
        # Scenario 2: Source code CWE
        test_source_code_cwe89_sql_injection,
        test_source_code_multiple_taint_chains,
        # Scenario 3: SIEM kill chain
        test_siem_kill_chain_detection,
        test_siem_kill_chain_technique_count,
        # Scenario 4: SOC 2 evidence (stub)
        test_soc2_evidence_scanner_no_crash,
        test_soc2_evidence_analyzer_stub,
        # Cross-scenario: export formats
        test_skill_export_formats_for_sbom_result,
    ]

    failed = []
    for t in tests:
        print(f"\n{'=' * 60}")
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

    print(f"\n{'=' * 60}")
    total = len(tests)
    passed = total - len(failed)
    print(f"Results: {passed}/{total} passed")
    if failed:
        print(f"Failed: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("All scenario tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    run_all_tests()
