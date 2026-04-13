"""
Claude agent skill entry point for Risk Scanner.

Functions here are called directly by Claude when the risk-scanner skill is active.
Session state (scan results) is stored in-process keyed by session_id.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# In-process session context: session_id → ScanResult
_scan_context: Dict[str, Any] = {}


# ------------------------------------------------------------------
# Primary skill functions (called by Claude)
# ------------------------------------------------------------------

def run_scan(
    path: str,
    domain: Optional[str] = None,
    frameworks: Optional[List[str]] = None,
    output_format: str = "markdown",
    session_id: str = "default",
) -> str:
    """Run a security scan and return a formatted summary.

    Args:
        path: File or directory path to scan.
        domain: Optional domain override (cve|cwe|attack|policy|framework).
        frameworks: Compliance frameworks to assess (default: cis-8, nist-800-53).
        output_format: Output format for raw export (markdown/sarif/json/csv/html).
        session_id: Session ID for multi-turn context.

    Returns:
        Formatted scan summary (PROMPT-13 narrative or structured report).
    """
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy
    import os

    policy = ScanPolicy.default()
    policy.license_token = os.environ.get("RISK_SCANNER_LICENSE_TOKEN")

    scanner = Scanner(policy=policy, frameworks=frameworks)
    result = scanner.scan(path, domain_override=domain, frameworks_override=frameworks)
    _scan_context[session_id] = result

    # Use PROMPT-13 for summary output if LLM available
    llm_summary = _generate_scan_summary(result, session_id)
    if llm_summary:
        return llm_summary

    # Fallback: use Markdown reporter
    from risk_scanner.reporters.markdown import MarkdownReporter
    return MarkdownReporter().render(result)


def explain_finding(finding_id: str, session_id: str = "default") -> str:
    """Deep explanation of a specific finding.

    Args:
        finding_id: The finding ID (e.g. RS-A1B2C3D4).
        session_id: Session ID to look up the scan context.

    Returns:
        Detailed Markdown explanation of the finding.
    """
    result = _scan_context.get(session_id)
    if result is None:
        return f"No scan result found for session '{session_id}'. Run a scan first."

    finding = result.get_finding(finding_id)
    if finding is None:
        return (
            f"Finding `{finding_id}` not found. "
            f"Available: {', '.join(f.id for f in result.findings[:10])}"
        )

    lines = [
        f"## Finding `{finding_id}` — {finding.taxonomy_code}\n",
        f"**Domain:** {finding.domain.value.upper()}  ",
        f"**Severity:** {finding.severity.value}  ",
        f"**Confidence:** {finding.confidence:.0%}\n",
        f"### What is this?",
        finding.severity_rationale,
        "",
    ]
    if finding.summary:
        lines += [f"### Summary", finding.summary, ""]
    ev = finding.evidence
    if ev.file_path:
        lines.append(f"**Location:** `{ev.file_path}`"
                     + (f" (line {ev.line_start})" if ev.line_start else ""))
    if ev.snippet:
        lines += [f"\n```\n{ev.snippet[:400]}\n```"]

    if finding.attack_chain:
        lines += ["\n### ATT&CK Techniques Enabled"]
        for atk in finding.attack_chain:
            lines.append(
                f"- **{atk.technique_id}** {atk.technique_name} ({atk.tactic})  \n"
                f"  {atk.rationale}"
            )

    if finding.control_gaps:
        lines += ["\n### Control Gaps"]
        for ctrl in finding.control_gaps:
            sat = ctrl.satisfaction.value
            lines.append(
                f"- **{ctrl.control_id}** ({ctrl.framework}): {sat}"
                + (f"\n  Gap: {ctrl.gap_narrative}" if ctrl.gap_narrative else "")
            )

    if finding.remediation:
        lines += ["\n### Remediation", finding.remediation]

    if finding.cross_refs:
        lines += ["\n### Related Findings", ", ".join(f"`{r}`" for r in finding.cross_refs)]

    return "\n".join(lines)


def remediate_finding(finding_id: str, session_id: str = "default") -> str:
    """Generate a remediation ticket for a specific finding (PROMPT-14).

    Args:
        finding_id: The finding ID.
        session_id: Session ID to look up the scan context.

    Returns:
        Markdown ticket body ready for Jira/GitHub Issues/Linear.
    """
    result = _scan_context.get(session_id)
    if result is None:
        return f"No scan result for session '{session_id}'."

    finding = result.get_finding(finding_id)
    if finding is None:
        return f"Finding `{finding_id}` not found."

    # Try LLM generation (PROMPT-14)
    llm = _get_llm()
    if llm:
        try:
            from risk_scanner.core.prompts import format_prompt
            prompt = format_prompt(
                "PROMPT-14",
                severity=finding.severity.value,
                severity_rationale=finding.severity_rationale,
                taxonomy_code=finding.taxonomy_code,
                evidence_location=f"{finding.evidence.file_path or 'N/A'}"
                                  + (f" L{finding.evidence.line_start}"
                                     if finding.evidence.line_start else ""),
                techniques=", ".join(a.technique_id for a in finding.attack_chain),
                control_ids=", ".join(c.control_id for c in finding.control_gaps),
                finding_json=json.dumps(finding.model_dump(mode="json"), default=str, indent=2)[:2000],
            )
            from langchain_core.messages import HumanMessage
            resp = llm.invoke([HumanMessage(content=prompt)])
            return resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            log.debug("PROMPT-14 LLM failed: %s", exc)

    # Static ticket template
    return _static_ticket(finding)


def export_result(
    fmt: str = "sarif",
    session_id: str = "default",
) -> str:
    """Export the last scan result in the requested format.

    Args:
        fmt: Output format: sarif | json | markdown | csv | html.
        session_id: Session ID.

    Returns:
        Rendered report string.
    """
    result = _scan_context.get(session_id)
    if result is None:
        return f"No scan result for session '{session_id}'. Run a scan first."
    from risk_scanner.reporters import get_reporter
    try:
        reporter = get_reporter(fmt)  # type: ignore[arg-type]
        return reporter.render(result)
    except ValueError as exc:
        return str(exc)


def watch_kev(
    sbom_path: str,
    poll_interval_hours: int = 6,
    session_id: str = "default",
) -> str:
    """Register a SBOM's component inventory for continuous KEV monitoring.

    Extracts CVE references from the last scan result (or runs a fresh CVE scan),
    then starts a background KevClient watch that alerts whenever CISA adds a new
    matching entry to the KEV catalog.

    Args:
        sbom_path: Path to the SBOM file (used for fresh scan if no session exists).
        poll_interval_hours: How often to poll the CISA catalog (default: 6 hours).
        session_id: Session ID for context lookup.

    Returns:
        Status message describing what is being monitored and current KEV matches.
    """
    from risk_scanner.core.kev_client import KevClient

    # Get or run a scan to build the component inventory
    result = _scan_context.get(session_id)
    if result is None:
        result_str = run_scan(sbom_path, domain="cve", session_id=session_id)
        result = _scan_context.get(session_id)
        if result is None:
            return f"Could not scan {sbom_path} to build component inventory."

    # Build CVE inventory from scan findings
    cve_inventory: dict = {}
    for f in result.findings:
        if f.domain.value == "cve":
            cve_inventory[f.taxonomy_code] = f.evidence.matched_pattern or f.taxonomy_code

    if not cve_inventory:
        return (
            f"No CVE findings in session '{session_id}' — nothing to watch. "
            "Run a CVE scan first or provide a SBOM path."
        )

    # Check current KEV status immediately
    kev_client = KevClient()
    current_matches = [
        cve for cve in cve_inventory if kev_client.is_in_kev(cve)
    ]

    # Register new-KEV callback
    new_kev_alerts: list = []

    def _on_new_kev(cve_id: str, kev_entry: object) -> None:
        msg = (
            f"[KEV ALERT] {cve_id} was added to the CISA KEV catalog. "
            f"Ransomware: {getattr(kev_entry, 'ransomware_campaign_use', False)}. "
            f"Required action: {getattr(kev_entry, 'required_action', 'see CISA catalog')}."
        )
        new_kev_alerts.append(msg)
        log.warning(msg)

    kev_client.watch(
        component_inventory=cve_inventory,
        callback=_on_new_kev,
        poll_interval_seconds=poll_interval_hours * 3600,
    )

    # Store client so watch persists for this session
    _scan_context[f"{session_id}:kev_client"] = kev_client

    lines = [
        f"## KEV Watch Active — {len(cve_inventory)} CVEs monitored\n",
        f"**Poll interval:** every {poll_interval_hours} hours",
        f"**Catalog size:** {kev_client.kev_count()} KEV entries\n",
    ]
    if current_matches:
        lines += [
            f"### {len(current_matches)} CVE(s) already in KEV catalog:",
        ]
        for cve_id in current_matches:
            entry = kev_client.lookup(cve_id)
            ransomware = " [RANSOMWARE]" if entry.ransomware_campaign_use else ""
            overdue = ""
            if entry.days_until_due is not None and entry.days_until_due < 0:
                overdue = f" [OVERDUE {abs(entry.days_until_due)}d]"
            lines.append(f"- `{cve_id}`{ransomware}{overdue}")
    else:
        lines.append("No monitored CVEs are currently in the KEV catalog.")

    lines += [
        "\nBackground watch is running. When CISA adds a new entry matching your inventory,",
        "an alert will be logged. Ask me `watch_kev alerts` to check for new matches.",
    ]
    return "\n".join(lines)


def sbom_attribution(
    sbom_path: str,
    max_related: int = 5,
    session_id: str = "default",
) -> str:
    """Generate a per-component CVE source attribution report for a SBOM (Capability 2 & 3).

    For each component in the SBOM: resolves CPE, lists direct CVEs with CVSS/EPSS/exploit
    maturity, pre-seeds ATT&CK technique mappings, and optionally expands related CVEs that
    share those techniques.

    Args:
        sbom_path: Path to a CycloneDX or SPDX SBOM file.
        max_related: Number of related CVEs to surface per component (0 = off).
        session_id: Session ID to store a ScanResult in context.

    Returns:
        Markdown attribution report keyed by component.
    """
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy
    import os

    policy = ScanPolicy.default()
    policy.license_token = os.environ.get("RISK_SCANNER_LICENSE_TOKEN")

    scanner = Scanner(
        policy=policy,
        enrich_cpe=True,
        max_related_cves=max_related,
    )
    result = scanner.scan(sbom_path, domain_override="cve")
    _scan_context[session_id] = result

    source_map = result.source_map or {}
    if not source_map and not result.findings:
        return f"No CVE findings or SBOM components resolved for `{sbom_path}`."

    lines = [f"## SBOM CVE Attribution — `{sbom_path}`\n"]
    lines.append(f"**Components analysed:** {len(source_map) or len(result.findings)}")
    lines.append(f"**Total findings:** {len(result.findings)}\n")

    for comp_key, comp_data in source_map.items():
        cpe = comp_data.get("cpe_uri", "—")
        conf = comp_data.get("resolution_confidence", 0)
        direct = comp_data.get("cves", [])
        related = comp_data.get("related_cves", [])
        techniques = comp_data.get("technique_surface", [])
        max_cvss = comp_data.get("max_cvss", 0)
        lines.append(f"### `{comp_key}`")
        lines.append(f"- **CPE:** `{cpe}` (confidence {conf:.0%})")
        lines.append(f"- **Max CVSS:** {max_cvss:.1f}")
        lines.append(f"- **ATT&CK surface:** {', '.join(techniques) or 'none'}")
        if direct:
            lines.append(f"- **Direct CVEs ({len(direct)}):** {', '.join(f'`{c}`' for c in direct[:10])}")
        if related:
            lines.append(f"- **Related CVEs ({len(related)}):**")
            for r in related[:max_related]:
                cve_id = r.get("cve_id", "")
                score = r.get("composite_score", 0)
                shared = ", ".join(r.get("shared_techniques", []))
                lines.append(f"  - `{cve_id}` (score {score:.2f}, shared: {shared})")
        lines.append("")

    return "\n".join(lines)


def related_cves_query(
    query: str,
    max_results: int = 10,
    min_cvss: float = 0.0,
) -> str:
    """Find CVEs related to a software package, ATT&CK technique, tactic, or kill chain phase (Capability 3).

    Routes through an intent classifier — no need to specify the query type.

    Args:
        query: Natural language or structured query. Examples:
               'openssl 3.0.7', 'T1190', 'Initial Access',
               'Exploitation kill chain phase', 'pkg:npm/lodash@4.17.21'
        max_results: Maximum number of CVEs to return.
        min_cvss: Minimum CVSS score filter.

    Returns:
        Markdown table of ranked CVEs with CVSS, EPSS, exploit maturity, and techniques.
    """
    try:
        from asteraskills.tools.related_cves_skill import _execute_related_cves
        data = _execute_related_cves(query=query, max_results=max_results, min_cvss=min_cvss)
    except Exception as exc:
        return f"Related CVE query failed: {exc}"

    intent = data.get("intent_type", "unknown")
    results = data.get("results", [])

    # SBOM returns source_map, not a flat results list
    if intent == "sbom":
        source_map = data.get("source_map", {})
        lines = [f"## Related CVEs — SBOM query: `{query}`\n"]
        for comp, info in source_map.items():
            lines.append(f"### `{comp}`")
            for r in info.get("related_cves", []):
                lines.append(
                    f"- `{r['cve_id']}` score {r['composite_score']:.2f} — "
                    f"shared: {', '.join(r.get('shared_techniques', []))}"
                )
        return "\n".join(lines)

    if not results:
        return f"No related CVEs found for query `{query}` (intent: {intent})."

    lines = [
        f"## Related CVEs — `{query}` (intent: {intent})\n",
        "| CVE | CVSS | EPSS | Exploit | Techniques | Score |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        techniques = ", ".join(r.get("matched_technique_ids", [])[:3])
        lines.append(
            f"| `{r['cve_id']}` "
            f"| {r.get('cvss_score', 0):.1f} "
            f"| {r.get('epss_score', 0):.3f} "
            f"| {r.get('exploit_maturity', 'none')} "
            f"| {techniques or '—'} "
            f"| {r.get('composite_score', 0):.3f} |"
        )
    return "\n".join(lines)


def correlate_findings(session_id: str = "default") -> str:
    """Explain relationships across findings from the last scan (PROMPT-15).

    Returns compound risk analysis when findings share components/techniques.
    """
    result = _scan_context.get(session_id)
    if result is None:
        return f"No scan result for session '{session_id}'. Run a scan first."

    if not result.findings:
        return "No findings to correlate."

    # Group by shared ATT&CK technique
    from collections import defaultdict
    technique_groups: Dict[str, List[Any]] = defaultdict(list)
    for f in result.findings:
        for atk in f.attack_chain:
            technique_groups[atk.technique_id].append(f)

    # Find most correlated group
    shared = {t: fs for t, fs in technique_groups.items() if len(fs) > 1}
    if not shared:
        return "No cross-finding correlations detected (no shared ATT&CK techniques)."

    top_technique, top_findings = max(shared.items(), key=lambda x: len(x[1]))

    llm = _get_llm()
    if llm:
        try:
            from risk_scanner.core.prompts import format_prompt
            prompt = format_prompt(
                "PROMPT-15",
                related_findings_json=json.dumps(
                    [f.model_dump(mode="json") for f in top_findings],
                    default=str, indent=2
                )[:3000],
                correlation_type="attack_technique",
                correlation_value=top_technique,
            )
            from langchain_core.messages import HumanMessage
            resp = llm.invoke([HumanMessage(content=prompt)])
            return resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            log.debug("PROMPT-15 LLM failed: %s", exc)

    # Static correlation summary
    lines = [
        f"## Cross-Finding Correlation — `{top_technique}`\n",
        f"{len(top_findings)} findings share technique `{top_technique}`:\n",
    ]
    for f in top_findings:
        lines.append(f"- `{f.id}` {f.taxonomy_code} ({f.severity.value}) in `{f.evidence.file_path or 'N/A'}`")
    lines.append("\nReview all related findings together — they may represent a compound attack path.")
    return "\n".join(lines)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _generate_scan_summary(result: Any, session_id: str) -> Optional[str]:
    """Use PROMPT-13 to generate the agent skill output."""
    llm = _get_llm()
    if not llm:
        return None
    try:
        from risk_scanner.core.prompts import format_prompt
        prompt = format_prompt(
            "PROMPT-13",
            scan_result_json=json.dumps(
                result.model_dump(mode="json"), default=str, indent=2
            )[:6000],
            artifact_type=result.artifact_type,
            user_role="security engineer",
            requested_frameworks=", ".join(result.scan_policy.get("enabled_frameworks", [])),
        )
        from langchain_core.messages import HumanMessage
        resp = llm.invoke([HumanMessage(content=prompt)])
        return resp.content if hasattr(resp, "content") else str(resp)
    except Exception as exc:
        log.debug("PROMPT-13 LLM failed: %s", exc)
        return None


def _get_llm() -> Optional[Any]:
    try:
        from asteraskills.core.llm import get_llm
        return get_llm(temperature=0.1)
    except Exception:
        return None


def _static_ticket(finding: Any) -> str:
    """Fallback static remediation ticket."""
    ev = finding.evidence
    techniques = ", ".join(f"`{a.technique_id}`" for a in finding.attack_chain)
    controls = ", ".join(f"`{c.control_id}`" for c in finding.control_gaps)
    return f"""## Summary
{finding.taxonomy_code} ({finding.severity.value}) in `{ev.file_path or 'unknown'}`.

## Severity
**{finding.severity.value}** — {finding.severity_rationale}

## Finding Detail
- Taxonomy code: `{finding.taxonomy_code}`
- File / resource: `{ev.file_path or 'N/A'}`{f" L{ev.line_start}" if ev.line_start else ""}
- ATT&CK techniques enabled: {techniques or "none mapped"}
- Control gaps: {controls or "none identified"}

## Reproduction
1. Run: `risk-scanner scan {ev.file_path or "<path>"} --domain {finding.domain.value}`
2. Look for finding `{finding.id}`

## Remediation Steps
{finding.remediation or "Review the finding evidence and apply appropriate controls."}

## Acceptance Criteria
- Re-scan returns no findings for `{finding.taxonomy_code}`
- Relevant controls are marked `satisfied` in next compliance assessment

## References
- {finding.taxonomy_code}: https://cve.mitre.org (CVE) / https://cwe.mitre.org (CWE)
"""
