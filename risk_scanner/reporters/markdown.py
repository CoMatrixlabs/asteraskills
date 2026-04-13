"""
Markdown reporter — severity breakdown table + per-finding narratives.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from risk_scanner.core.models import Domain, Finding, ScanResult, Severity
from risk_scanner.reporters import BaseReporter
from risk_scanner.reporters.detail_resolvers import (
    build_enrichment_summary_lines,
    format_loss_outcomes,
    get_cve_detail_for_report,
    lookup_attack_technique_name,
    lookup_framework_item_metadata,
)

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _md_cell(s: object) -> str:
    """Escape pipe/newlines for markdown tables."""
    if s is None:
        return "—"
    t = str(s).replace("|", "/").replace("\n", " ").strip()
    return t if t else "—"


class MarkdownReporter(BaseReporter):
    def render(self, result: ScanResult) -> str:
        lines: List[str] = []

        # Header
        lines.append(f"# Risk Scanner Report — {result.scan_id}")
        lines.append(f"\n**Artifact:** `{result.artifact_path}`  ")
        lines.append(f"**Scanned:** {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}  ")
        lines.append(f"**Duration:** {result.duration_ms}ms  ")
        lines.append(f"**Domains:** {', '.join(d.value for d in result.domains_run)}")
        lines.append("")

        # Verdict
        if not result.findings:
            lines.append("> **No findings detected.** The artifact appears clean.")
        elif result.critical_count > 0:
            lines.append(f"> ⚠️ **Critical findings present** — immediate action required.")
        else:
            lines.append(f"> ℹ️ Findings present — review and remediate.")
        lines.append("")

        # Severity breakdown
        lines.append("## Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = sum(1 for f in result.findings if f.severity == sev)
            if count:
                lines.append(f"| {_SEV_EMOJI[sev]} {sev.value} | {count} |")
        lines.append("")

        # Executive summary (enrichment context)
        lines.append("## Enrichment summary\n")
        for s in build_enrichment_summary_lines(result):
            lines.append(s)
        lines.append("")

        # Critical and High findings — detailed
        critical_high = [f for f in result.findings
                         if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_high:
            lines.append("## Critical & High Findings\n")
            for finding in critical_high:
                lines.extend(self._render_finding_detail(finding))

        # Medium findings
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        if medium:
            lines.append("## Medium Findings\n")
            for finding in medium:
                lines.append(self._render_finding_oneliner(finding))
            lines.append("")

        # Low / Info findings
        low_info = [f for f in result.findings
                    if f.severity in (Severity.LOW, Severity.INFO)]
        if low_info:
            lines.append("## Low / Info Findings\n")
            for finding in low_info:
                lines.append(self._render_finding_oneliner(finding))
            lines.append("")

        # Suppressed
        if result.suppressed:
            lines.append(f"## Suppressed Findings ({len(result.suppressed)} deduplicated/filtered)\n")
            for f in result.suppressed:
                lines.append(f"- `{f.id}` `{f.taxonomy_code}` — {f.severity_rationale[:80]}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(
            "_Ask me to explain any finding, generate a remediation ticket, "
            "or export this report as SARIF / JSON / CSV / HTML._"
        )
        return "\n".join(lines)

    def _render_finding_detail(self, finding: Finding) -> List[str]:
        ev = finding.evidence
        emoji = _SEV_EMOJI.get(finding.severity, "")
        lines = [
            f"### {emoji} `{finding.id}` — {finding.taxonomy_code} ({finding.domain.value.upper()})\n",
            f"**Severity:** {finding.severity.value} | **Confidence:** {finding.confidence:.0%}  ",
            f"**File:** `{ev.file_path or 'N/A'}`"
            + (f" line {ev.line_start}" if ev.line_start else ""),
            "",
            f"{finding.severity_rationale}",
            "",
        ]

        if finding.domain == Domain.CVE:
            d = get_cve_detail_for_report(finding)
            if d and d.get("description"):
                lines.append(f"**Overview:** {_md_cell(str(d['description'])[:500])}\n")

        if finding.summary:
            lines.append(f"**Summary:** {finding.summary}\n")

        if finding.domain == Domain.CVE:
            lines.extend(self._render_cve_intel_block(finding))

        if finding.attack_chain:
            lines.append("**ATT&CK techniques**\n")
            lines.append("| Technique | Name | Tactic | Confidence | Notes |")
            lines.append("|-----------|------|--------|------------|-------|")
            for atk in finding.attack_chain:
                tname = self._resolve_technique_display_name(atk)
                tac = atk.tactic if atk.tactic and atk.tactic != "unknown" else "—"
                rat = (atk.rationale or "")[:120].replace("|", "/")
                lines.append(
                    f"| `{atk.technique_id}` | {_md_cell(tname)} | {_md_cell(tac)} | "
                    f"{atk.confidence:.0%} | {_md_cell(rat)} |"
                )
            lines.append("")

        if finding.control_gaps:
            lines.append("**Control gaps (framework mapping)**\n")
            lines.append("| Control ID | Name (from DB) | Framework | Status | Mapping / gap |")
            lines.append("|------------|------------------|-----------|--------|----------------|")
            for ctrl in finding.control_gaps[:12]:
                sat_label = ctrl.satisfaction.value if ctrl.satisfaction else "unknown"
                meta = lookup_framework_item_metadata(ctrl.framework, ctrl.control_id)
                db_name = (meta.get("name", "") if meta else "").strip()
                if not db_name:
                    db_name = (ctrl.control_name or "").strip()
                gap = (ctrl.gap_narrative or ctrl.remediation or "")[:200].replace("|", "/")
                lines.append(
                    f"| `{ctrl.control_id}` | {_md_cell(db_name or '—')} | "
                    f"{_md_cell(ctrl.framework)} v{ctrl.framework_version} | {sat_label} | {_md_cell(gap)} |"
                )
            lines.append("")
            for ctrl in finding.control_gaps[:5]:
                meta = lookup_framework_item_metadata(ctrl.framework, ctrl.control_id)
                if meta and (meta.get("description") or meta.get("trigger")):
                    lines.append(f"**`{ctrl.control_id}`** — {_md_cell(meta.get('name', ''))}")
                    if meta.get("description"):
                        lines.append(f"\n{_md_cell(meta['description'][:1200])}\n")
                    if meta.get("trigger"):
                        lines.append(f"\n*Trigger:* {_md_cell(str(meta['trigger'])[:500])}\n")
                    lo = format_loss_outcomes(meta.get("loss_outcomes"))
                    if lo:
                        lines.append(f"\n*Loss outcomes:* {lo}\n")
                    lines.append("")

        if finding.remediation:
            lines.append(f"**Remediation:** {finding.remediation}\n")

        if finding.cross_refs:
            lines.append(f"**Related findings:** {', '.join(f'`{r}`' for r in finding.cross_refs[:5])}\n")

        if ev.snippet:
            lines.append(f"```\n{ev.snippet[:300]}\n```\n")

        lines.append("---\n")
        return lines

    def _resolve_technique_display_name(self, atk: object) -> str:
        tid = getattr(atk, "technique_id", "") or ""
        name = (getattr(atk, "technique_name", "") or "").strip()
        if name and name.lower() != "unknown" and name != tid:
            return name
        resolved = lookup_attack_technique_name(tid)
        if resolved:
            return resolved
        return name or tid or "—"

    def _render_cve_intel_block(self, finding: Finding) -> List[str]:
        lines: List[str] = []
        detail = get_cve_detail_for_report(finding)
        if detail:
            lines.append("**CVE intelligence** *(cache / NVD-derived)*\n")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **CVE** | `{finding.taxonomy_code}` |")
            cvss = detail.get("cvss_score")
            if cvss is not None:
                vec = detail.get("cvss_vector") or "—"
                lines.append(f"| **CVSS** | {_md_cell(str(cvss))} ({_md_cell(str(vec))}) |")
            lines.append(f"| **Attack vector** | {_md_cell(detail.get('attack_vector') or '—')} |")
            epss_v = detail.get("epss_score")
            lines.append(
                f"| **EPSS** | {_md_cell(epss_v if epss_v is not None else '—')} |"
            )
            em = detail.get("exploit_maturity")
            lines.append(f"| **Exploit maturity** | {_md_cell(em if em else '—')} |")
            cwes = detail.get("cwe_ids") or []
            if cwes:
                lines.append(f"| **CWEs** | {', '.join(str(c) for c in cwes[:10])} |")
            prods = detail.get("affected_products") or []
            if prods:
                pl = ", ".join(str(p) for p in prods[:8])
                lines.append(f"| **Affected products (sample)** | {_md_cell(pl[:400])} |")
            if detail.get("published_date"):
                lines.append(f"| **Published** | {_md_cell(str(detail.get('published_date')))} |")
            if detail.get("last_modified"):
                lines.append(f"| **Last modified** | {_md_cell(str(detail.get('last_modified')))} |")
            lines.append("")
        else:
            lines.append(
                "**CVE intelligence:** *No row in `cve_intelligence` / `cve_cache` — "
                "populate via ingest or CVE enrichment.*\n"
            )

        cpe_matches = getattr(finding, "cpe_matches", None) or []
        source_cpe_uri = getattr(finding, "source_cpe_uri", None)
        cpe_attempted = getattr(finding, "cpe_enrichment_attempted", False)
        if cpe_matches:
            lines.append("**CPE Matches** *(Stage 1.5 resolution)*\n")
            lines.append("| CPE URI | Vendor | Product | Version Range | Method |")
            lines.append("|---------|--------|---------|---------------|--------|")
            for m in cpe_matches[:20]:
                uri = _md_cell(m.get("cpe_uri") or "—")
                vendor = _md_cell(m.get("vendor") or "—")
                product = _md_cell(m.get("product") or "—")
                v_start = m.get("version_start_incl") or ""
                v_end = m.get("version_end_excl") or ""
                ver_range = f">={v_start}" if v_start else ""
                if v_end:
                    ver_range += f" <{v_end}" if ver_range else f"<{v_end}"
                ver_range = _md_cell(ver_range or "—")
                method = _md_cell(m.get("resolution_method") or "—")
                lines.append(f"| {uri} | {vendor} | {product} | {ver_range} | {method} |")
            lines.append("")
        elif source_cpe_uri:
            lines.append(f"**CPE:** `{source_cpe_uri}`\n")
        elif cpe_attempted:
            lines.append(
                "**CPE Matches:** *No CPE matches found — CPE registry may not be populated; "
                "run `cpe_registry_cli` to ingest CPE data, then re-run with `--cpe`.*\n"
            )

        if finding.kev_entry and finding.kev_entry.in_kev:
            k = finding.kev_entry
            lines.append("**CISA KEV**\n")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append("| **Listed** | Yes |")
            if k.kev_date_added:
                lines.append(f"| **Date added** | {k.kev_date_added} |")
            if k.kev_due_date:
                lines.append(f"| **Remediation due** | {k.kev_due_date} |")
            if k.ransomware_campaign_use:
                lines.append(f"| **Ransomware use** | Known ({_md_cell(k.ransomware_group or '')}) |")
            if k.required_action:
                lines.append(f"| **Required action** | {_md_cell(k.required_action[:800])} |")
            if k.kev_notes:
                lines.append(f"| **Notes** | {_md_cell(k.kev_notes[:800])} |")
            lines.append("")
        return lines

    def _render_finding_oneliner(self, finding: Finding) -> str:
        ev = finding.evidence
        loc = f"`{ev.file_path}`" if ev.file_path else ""
        if ev.line_start:
            loc += f" L{ev.line_start}"
        techniques = ", ".join(a.technique_id for a in finding.attack_chain[:2])
        t_suffix = f" → `{techniques}`" if techniques else ""
        return (
            f"- `{finding.id}` **{finding.taxonomy_code}** {loc} "
            f"— {finding.severity_rationale[:80]}{t_suffix}"
        )
