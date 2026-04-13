"""
CLI scan commands — `risk-scanner scan` and `risk-scanner scan-all`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Scan security artifacts for CVE, CWE, ATT&CK, Policy, and Framework risks.")
console = Console(stderr=True)


@app.command("run")
def cmd_scan(
    path: str = typer.Argument(..., help="File or directory path to scan"),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d",
        help="Constrain to a single domain: cve|cwe|attack|policy|framework",
    ),
    frameworks: Optional[str] = typer.Option(
        None, "--frameworks", "-f",
        help="Comma-separated frameworks: soc2,nist-800-53,cis-8,iso27001",
    ),
    fmt: str = typer.Option(
        "markdown", "--format", "-o",
        help="Output format: markdown|sarif|json|csv|html",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O",
        help="Write output to file instead of stdout",
    ),
    severity: str = typer.Option(
        "LOW", "--severity", "-s",
        help="Minimum severity threshold: CRITICAL|HIGH|MEDIUM|LOW|INFO",
    ),
    no_enrich: bool = typer.Option(False, "--no-enrich", help="Disable ATT&CK enrichment"),
    no_meta: bool = typer.Option(False, "--no-meta", help="Disable FP filter / dedup"),
    cpe: bool = typer.Option(False, "--cpe", help="Enable CPE Stage 1.5 enrichment (resolves affected products to canonical CPE URIs)"),
    related_cves: int = typer.Option(0, "--related-cves", help="Append N related CVEs per finding (0 = off)"),
    license_token: Optional[str] = typer.Option(
        None, "--token",
        envvar="RISK_SCANNER_LICENSE_TOKEN",
        help="License token for intelligence server",
    ),
    show_stats: bool = typer.Option(False, "--stats", help="Print scan stats to stderr"),
) -> None:
    """Scan a single artifact file or directory."""
    _bootstrap()
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.models import Severity
    from risk_scanner.reporters import get_reporter

    frameworks_list = [f.strip() for f in frameworks.split(",")] if frameworks else None

    try:
        sev_threshold = Severity(severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity!r}[/red]")
        raise typer.Exit(1)

    policy = ScanPolicy(
        severity_threshold=sev_threshold,
        enrichment_enabled=not no_enrich,
        meta_analysis_enabled=not no_meta,
    )

    scanner = Scanner(
        policy=policy,
        license_token=license_token,
        frameworks=frameworks_list,
        enrich_cpe=cpe,
        max_related_cves=related_cves,
    )

    try:
        result = scanner.scan(path, domain_override=domain, frameworks_override=frameworks_list)
    except Exception as exc:
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(2)

    if result.error:
        console.print(f"[red]Scan error:[/red] {result.error}")
        raise typer.Exit(2)

    if show_stats:
        _print_stats(result)

    try:
        reporter = get_reporter(fmt)  # type: ignore[arg-type]
        rendered = reporter.render(result)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to[/green] {output}")
    else:
        print(rendered)

    # Exit code: 1 if critical, 0 otherwise
    raise typer.Exit(1 if result.critical_count > 0 else 0)


@app.command("all")
def cmd_scan_all(
    directory: str = typer.Argument(..., help="Directory to scan recursively"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    frameworks: Optional[str] = typer.Option(None, "--frameworks", "-f"),
    fmt: str = typer.Option("markdown", "--format", "-o"),
    output: Optional[Path] = typer.Option(None, "--output", "-O"),
    severity: str = typer.Option("LOW", "--severity", "-s"),
) -> None:
    """Scan all recognized files in a directory recursively."""
    _bootstrap()
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.core.models import Severity
    from risk_scanner.reporters import get_reporter

    frameworks_list = [f.strip() for f in frameworks.split(",")] if frameworks else None
    try:
        sev_threshold = Severity(severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity!r}[/red]")
        raise typer.Exit(1)

    policy = ScanPolicy(severity_threshold=sev_threshold)
    scanner = Scanner(policy=policy, frameworks=frameworks_list)

    try:
        results = scanner.scan_all(directory, domain_override=domain, frameworks_override=frameworks_list)
    except Exception as exc:
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(2)

    if not results:
        console.print("[green]No findings detected in any artifacts.[/green]")
        raise typer.Exit(0)

    # Merge all results for reporting
    _print_scan_all_summary(results, fmt, output)
    has_critical = any(r.critical_count > 0 for r in results)
    raise typer.Exit(1 if has_critical else 0)


@app.command("kev-watch")
def cmd_kev_watch(
    path: str = typer.Argument(..., help="SBOM file to extract CVE inventory from"),
    poll_hours: int = typer.Option(6, "--poll-hours", help="Catalog poll interval in hours"),
    once: bool = typer.Option(False, "--once", help="Check once and exit (no background loop)"),
    fmt: str = typer.Option("markdown", "--format", "-o", help="Output format: markdown|json"),
) -> None:
    """Check a SBOM's CVE inventory against the CISA KEV catalog.

    In default mode, prints current KEV matches and exits.
    Use --once for CI gates: exits with code 1 if any KEV CVE is found.
    """
    _bootstrap()
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.core.analyzers.static import StaticAnalyzer
    from risk_scanner.core.loader import ArtifactLoader

    loader = ArtifactLoader()
    try:
        artifacts = loader.load(path)
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc}")
        raise typer.Exit(2)

    # Extract CVE IDs from SBOM
    static = StaticAnalyzer()
    cve_ids: list = []
    for artifact in artifacts:
        if static.can_handle(artifact):
            findings = static.analyze(artifact)
            for f in findings:
                if f.domain.value == "cve":
                    cve_ids.append(f.taxonomy_code)

    if not cve_ids:
        console.print("[yellow]No CVE findings detected in artifact.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[cyan]Checking {len(cve_ids)} CVEs against CISA KEV catalog...[/cyan]", file=sys.stderr)
    kev = KevClient()

    matches = [(cve_id, kev.lookup(cve_id)) for cve_id in cve_ids if kev.is_in_kev(cve_id)]

    if not matches:
        console.print("[green]No KEV matches found.[/green]")
        raise typer.Exit(0)

    if fmt == "json":
        import json as _json
        output = [
            {
                "cve_id": cid,
                "in_kev": True,
                "ransomware": entry.ransomware_campaign_use,
                "ransomware_group": entry.ransomware_group,
                "date_added": str(entry.kev_date_added),
                "due_date": str(entry.kev_due_date),
                "days_until_due": entry.days_until_due,
                "required_action": entry.required_action,
            }
            for cid, entry in matches
        ]
        print(_json.dumps(output, indent=2))
    else:
        table = Table(title=f"CISA KEV Matches — {path}")
        table.add_column("CVE ID", style="bold red")
        table.add_column("Ransomware", style="red")
        table.add_column("Date Added")
        table.add_column("Due Date")
        table.add_column("Days Until Due")
        table.add_column("Required Action")
        for cid, entry in matches:
            due_style = "red" if (entry.days_until_due or 0) < 0 else "yellow"
            table.add_row(
                cid,
                "[bold red]YES[/bold red]" if entry.ransomware_campaign_use else "No",
                str(entry.kev_date_added or ""),
                str(entry.kev_due_date or ""),
                f"[{due_style}]{entry.days_until_due}[/{due_style}]" if entry.days_until_due is not None else "—",
                (entry.required_action or "")[:60],
            )
        console.print(table)
        ransomware_count = sum(1 for _, e in matches if e.ransomware_campaign_use)
        overdue_count = sum(1 for _, e in matches if (e.days_until_due or 0) < 0)
        console.print(
            f"\n[bold]{len(matches)} KEV match(es)[/bold] — "
            f"[red]{ransomware_count} ransomware[/red], "
            f"[yellow]{overdue_count} overdue[/yellow]"
        )

    # Exit 1 if any KEV matches (use as CI gate)
    raise typer.Exit(1 if matches else 0)


@app.command("enrich-cve")
def cmd_enrich_cve(
    cve_id: str = typer.Argument(..., help="CVE ID to enrich, e.g. CVE-2021-44228"),
    severity: str = typer.Option(
        "HIGH", "--severity", "-s",
        help="Starting severity: CRITICAL|HIGH|MEDIUM|LOW",
    ),
    description: Optional[str] = typer.Option(
        None, "--description", "-D",
        help="Optional short description of the vulnerability",
    ),
    frameworks: Optional[str] = typer.Option(
        None, "--frameworks", "-f",
        help="Comma-separated frameworks: soc2,nist-800-53,cis-8,iso27001",
    ),
    fmt: str = typer.Option(
        "markdown", "--format", "-o",
        help="Output format: markdown|sarif|json|csv|html",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O",
        help="Write output to file instead of stdout",
    ),
    no_kev: bool = typer.Option(False, "--no-kev", help="Skip CISA KEV catalog check"),
    no_controls: bool = typer.Option(
        False, "--no-controls",
        help="Skip framework control mapping (fast; avoids many LLM calls for cis/nist)",
    ),
    cpe: bool = typer.Option(
        False, "--cpe",
        help="Resolve affected products to canonical CPE URIs (requires CPE registry)",
    ),
    related_cves: int = typer.Option(
        0, "--related-cves",
        help="Surface N related CVEs via ATT&CK technique overlap (0 = off)",
    ),
    license_token: Optional[str] = typer.Option(
        None, "--token",
        envvar="RISK_SCANNER_LICENSE_TOKEN",
    ),
) -> None:
    """Enrich a single CVE ID — ATT&CK mapping, KEV check, and framework controls.

    No file needed. Pass a CVE ID and get the full enrichment chain output.

    Examples:

        risk-scanner scan enrich-cve CVE-2021-44228

        risk-scanner scan enrich-cve CVE-2024-3094 --severity CRITICAL --frameworks nist-800-53,cis-8

        risk-scanner scan enrich-cve CVE-2023-44487 --format json
    """
    _bootstrap()
    import uuid
    import time
    from risk_scanner.core.models import Domain, Evidence, Finding, ScanResult, Severity
    from risk_scanner.core.analyzers.enrichment import EnrichmentAnalyzer
    from risk_scanner.core.pack_client import PackClient
    from risk_scanner.core.kev_client import KevClient
    from risk_scanner.reporters import get_reporter

    # Validate inputs
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        console.print(f"[red]Invalid CVE ID: {cve_id!r} — must start with 'CVE-'[/red]")
        raise typer.Exit(1)

    try:
        sev = Severity(severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity!r}[/red]")
        raise typer.Exit(1)

    if no_controls:
        frameworks_list: Optional[List[str]] = []
    else:
        frameworks_list = [f.strip() for f in frameworks.split(",")] if frameworks else None

    # Build a minimal Finding — no file required
    finding = Finding(
        domain=Domain.CVE,
        taxonomy_code=cve_id,
        severity=sev,
        severity_rationale=description or f"Direct CVE enrichment request for {cve_id}",
        evidence=Evidence(matched_rule_id="direct-input", snippet=description),
        confidence=1.0,
    )

    # Run enrichment chain
    pack_client = PackClient(license_token=license_token)
    kev_client = None if no_kev else KevClient()

    try:
        llm = _get_llm_quietly()
    except Exception:
        llm = None

    enricher = EnrichmentAnalyzer(
        pack_client=pack_client,
        llm=llm,
        frameworks=frameworks_list,
        kev_client=kev_client,
        enrich_cpe=cpe,
        max_related_cves=related_cves,
    )

    steps = ["ATT&CK"]
    if not no_controls:
        steps.append("frameworks")
    if cpe:
        steps.append("CPE resolution")
    if related_cves:
        steps.append(f"related CVEs (top {related_cves})")
    console.print(
        f"[dim]Enriching ({' + '.join(steps)}; LLM calls can take several minutes). "
        "Use --no-controls for a faster run.[/dim]"
    )
    t0 = time.monotonic()
    enriched = enricher.enrich([finding])
    duration_ms = int((time.monotonic() - t0) * 1000)

    result = ScanResult(
        scan_id=f"RS-CVE-{uuid.uuid4().hex[:8].upper()}",
        artifact_path=cve_id,
        artifact_type="cve-direct",
        domains_run=[Domain.CVE],
        findings=enriched,
        duration_ms=duration_ms,
    )

    try:
        reporter = get_reporter(fmt)  # type: ignore[arg-type]
        rendered = reporter.render(result)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to[/green] {output}")
    else:
        print(rendered)

    raise typer.Exit(1 if result.critical_count > 0 else 0)


@app.command("sbom-attr")
def cmd_sbom_attr(
    path: str = typer.Argument(..., help="CycloneDX or SPDX SBOM file path"),
    max_related: int = typer.Option(
        5, "--max-related", help="Related CVEs to surface per component (0 = off)"
    ),
    fmt: str = typer.Option(
        "markdown", "--format", "-o",
        help="Output format: markdown|json",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-O"),
    license_token: Optional[str] = typer.Option(
        None, "--token", envvar="RISK_SCANNER_LICENSE_TOKEN"
    ),
) -> None:
    """SBOM CVE attribution — per-component CPE resolution, direct CVEs, and related CVE expansion.

    Examples:

        risk-scanner scan sbom-attr sbom.json

        risk-scanner scan sbom-attr sbom.json --max-related 10 --format json
    """
    _bootstrap()
    import uuid, time
    from risk_scanner.core.scanner import Scanner
    from risk_scanner.core.scan_policy import ScanPolicy
    from risk_scanner.reporters import get_reporter

    policy = ScanPolicy.default()
    scanner = Scanner(
        policy=policy,
        license_token=license_token,
        enrich_cpe=True,
        max_related_cves=max_related,
    )

    t0 = time.monotonic()
    try:
        result = scanner.scan(path, domain_override="cve")
    except Exception as exc:
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(2)

    if result.error:
        console.print(f"[red]Scan error:[/red] {result.error}")
        raise typer.Exit(2)

    if fmt == "json":
        import json as _json
        rendered = _json.dumps(
            {
                "scan_id": result.scan_id,
                "source_map": result.source_map,
                "findings": result.model_dump(mode="json")["findings"],
            },
            indent=2,
            default=str,
        )
    else:
        # Markdown attribution view
        source_map = result.source_map or {}
        lines = [f"## SBOM CVE Attribution — `{path}`\n"]
        lines.append(f"**Scan ID:** {result.scan_id}  ")
        lines.append(f"**Duration:** {int((time.monotonic() - t0) * 1000)}ms  ")
        lines.append(f"**Components resolved:** {len(source_map)}  ")
        lines.append(f"**Total CVE findings:** {len(result.findings)}\n")
        for comp_key, comp_data in source_map.items():
            cpe = comp_data.get("cpe_uri", "—")
            conf = comp_data.get("resolution_confidence", 0)
            direct = comp_data.get("cves", [])
            related = comp_data.get("related_cves", [])
            max_cvss = comp_data.get("max_cvss", 0)
            techniques = comp_data.get("technique_surface", [])
            lines.append(f"### `{comp_key}`")
            lines.append(f"- **CPE:** `{cpe}` (confidence {conf:.0%})")
            lines.append(f"- **Max CVSS:** {max_cvss:.1f}")
            lines.append(f"- **ATT&CK surface:** {', '.join(techniques) or 'none'}")
            if direct:
                lines.append(
                    f"- **Direct CVEs ({len(direct)}):** "
                    + ", ".join(f"`{c}`" for c in direct[:10])
                )
            if related:
                lines.append(f"- **Related CVEs ({len(related)}):**")
                for r in related[:max_related]:
                    shared = ", ".join(r.get("shared_techniques", []))
                    lines.append(
                        f"  - `{r['cve_id']}` "
                        f"(score {r.get('composite_score', 0):.2f}, shared: {shared})"
                    )
            lines.append("")
        rendered = "\n".join(lines)

    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to[/green] {output}")
    else:
        print(rendered)

    raise typer.Exit(1 if result.critical_count > 0 else 0)


@app.command("investigate")
def cmd_investigate(
    cve_id: str = typer.Argument(..., help="CVE ID to investigate, e.g. CVE-2024-26855"),
    environment: Optional[str] = typer.Option(
        None,
        "--environment",
        "-e",
        help="Deployment environment: k8s|cloud_vm|bare_metal|container|mixed",
    ),
    criticality: Optional[str] = typer.Option(
        None,
        "--criticality",
        "-c",
        help="Asset criticality: crown_jewel|high|medium|low",
    ),
    controls: Optional[str] = typer.Option(
        None,
        "--controls",
        "-C",
        help="Comma-separated security controls in place: selinux,apparmor,edr,network_policy,...",
    ),
    source: Optional[str] = typer.Option(
        None,
        "--source",
        "-s",
        help="Data source to focus playbook on: windows_security_events|kubernetes_audit|sysmon|...",
    ),
    frameworks: Optional[str] = typer.Option(
        None,
        "--frameworks",
        "-f",
        help="Comma-separated frameworks for control mapping: soc2,nist-800-53,cis-8,iso27001. "
             "Omit to skip control mapping entirely (faster).",
    ),
    cpe: bool = typer.Option(
        False,
        "--cpe",
        help="Resolve affected products to canonical CPE URIs (requires CPE registry).",
    ),
    severity: str = typer.Option(
        "HIGH",
        "--severity",
        help="Starting severity passed to enrichment: CRITICAL|HIGH|MEDIUM|LOW",
    ),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-o",
        help="Output format: markdown|json",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-O",
        help="Write output to file instead of stdout",
    ),
    no_kev: bool = typer.Option(False, "--no-kev", help="Skip CISA KEV catalog check"),
    license_token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="RISK_SCANNER_LICENSE_TOKEN",
    ),
) -> None:
    """Run a CVE investigation — ATT&CK mapping, KEV check, entity analysis, detection playbook.

    Control mapping (--frameworks) and CPE resolution (--cpe) are opt-in.
    Without them only ATT&CK enrichment and KEV are run, which is fast and
    requires no local data files.

    Examples:

        # Fast — ATT&CK + KEV only
        risk-scanner scan investigate CVE-2024-26855 \\
            --environment k8s --criticality crown_jewel \\
            --controls network_policy,apparmor \\
            --source kubernetes_audit \\
            --output investigation.md

        # With framework control mapping
        risk-scanner scan investigate CVE-2024-26855 \\
            --frameworks soc2 --output investigation.md

        # With CPE resolution
        risk-scanner scan investigate CVE-2024-26855 \\
            --cpe --frameworks nist-800-53 --output investigation.md
    """
    _bootstrap()

    import sys as _sys
    import time
    import uuid as _uuid

    from risk_scanner.core.models import Domain, Evidence, Finding, Severity
    from risk_scanner.core.analyzers.enrichment import EnrichmentAnalyzer
    from risk_scanner.core.pack_client import PackClient
    from risk_scanner.core.kev_client import KevClient

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        console.print(f"[red]Invalid CVE ID: {cve_id!r} — must start with 'CVE-'[/red]")
        raise typer.Exit(1)

    try:
        sev = Severity(severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity!r}[/red]")
        raise typer.Exit(1)

    # ── Step 1: CVE enrichment (same pipeline as enrich-cve) ─────────────────
    finding = Finding(
        domain=Domain.CVE,
        taxonomy_code=cve_id,
        severity=sev,
        severity_rationale=f"CVE investigation for {cve_id}",
        evidence=Evidence(matched_rule_id="direct-input", snippet=None),
        confidence=1.0,
    )

    pack_client = PackClient(license_token=license_token)
    kev_client = None if no_kev else KevClient()

    try:
        llm = _get_llm_quietly()
    except Exception:
        llm = None

    # Pre-fetch CVE details via pack_client before the enricher runs.
    # The enricher's Step 1 (ATT&CK) falls back to a direct NVD call that
    # silently catches a 'value' KeyError, leaving cve_detail empty.
    # Pre-fetching and injecting into finding.cve_detail lets the enricher
    # skip that broken NVD path entirely.
    _sys.path.insert(0, str(Path(__file__).parents[3] / "app"))
    try:
        from asteraskills.tools.cve_enrichment import _execute_cve_enrich
        prefetched = _execute_cve_enrich(cve_id)
        if prefetched.get("cvss_score") or prefetched.get("description"):
            finding.cve_detail = prefetched  # type: ignore[attr-defined]
    except Exception:
        pass

    # Parse --frameworks into a list; empty list = skip control mapping entirely.
    # Only search vector store / Postgres — no local YAML fallback.
    frameworks_list = (
        [f.strip() for f in frameworks.split(",") if f.strip()]
        if frameworks
        else []
    )

    enricher = EnrichmentAnalyzer(
        pack_client=pack_client,
        llm=llm,
        frameworks=frameworks_list,   # [] skips Step 2; ["soc2"] queries DB/vector store
        kev_client=kev_client,
        enrich_cpe=cpe,               # only True when --cpe flag is explicitly passed
        max_related_cves=0,
    )

    console.print(f"[dim]Step 1/3 — Enriching {cve_id} (ATT&CK + KEV + CVE details)...[/dim]")
    t0 = time.monotonic()
    enriched_list = enricher.enrich([finding])
    duration_ms = int((time.monotonic() - t0) * 1000)
    enriched = enriched_list[0] if enriched_list else finding

    cve_detail   = enriched.cve_detail or {}
    attack_chain = enriched.attack_chain or []
    kev_entry    = enriched.kev_entry
    in_kev       = bool(kev_entry and kev_entry.in_kev)

    # Warn early rather than silently producing an empty analysis
    if not cve_detail.get("cvss_score"):
        console.print(
            f"[yellow]Warning: CVE details for {cve_id} could not be fetched — "
            "entity analysis will use default values.[/yellow]"
        )

    # ── Step 2: find related entities and perform deeper analysis ────────────
    console.print("[dim]Step 2/3 — Finding related entities...[/dim]")
    try:
        from asteraskills.agents.entity_investigation import (
            build_graph,
            render_conversation,
        )
        graph = build_graph(
            cve_id=cve_id,
            cve_detail=cve_detail,
            attack_chain=attack_chain,
            kev_entry=kev_entry,
            environment=environment or "bare_metal",
            criticality=criticality or "medium",
            controls_csv=controls or "",
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Entity analysis error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # ── Step 3: synthesise detection playbook from related entities ──────────
    console.print("[dim]Step 3/3 — Synthesising detection playbook...[/dim]")
    playbook_md = ""
    try:
        from asteraskills.agents.playbook_synthesizer import PlaybookSynthesizer

        cvss_vector = cve_detail.get("cvss_vector", "")
        cvss_base   = float(cve_detail.get("cvss_score", 0.0))
        epss_score  = float(cve_detail.get("epss_score", 0.0))
        kev_ransomware = bool(kev_entry and kev_entry.ransomware_campaign_use)

        av_field = ""
        for part in cvss_vector.split("/"):
            if part.startswith("AV:"):
                av_field = part[3:]
                break

        synth = PlaybookSynthesizer()
        pb_result = synth.synthesize(
            cve_id=cve_id,
            cvss_vector=cvss_vector,
            cvss_base=cvss_base,
            epss_score=epss_score,
            in_kev=in_kev,
            kev_ransomware=kev_ransomware,
            environment_type=environment or "bare_metal",
            asset_criticality=criticality or "medium",
            internet_facing=(av_field == "N"),
            has_controls=bool(controls),
            source_id=source,
        )
        playbook_md = pb_result.to_markdown()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Playbook synthesis skipped: {exc}[/yellow]")

    # ── Render ────────────────────────────────────────────────────────────────
    if fmt == "json":
        import json as _json
        rendered = _json.dumps(
            {
                "cve_id": cve_id,
                "environment": environment,
                "criticality": criticality,
                "controls": controls,
                "source_focus": source,
                # CVE details — same fields as enrich-cve
                "cvss_score": cve_detail.get("cvss_score"),
                "cvss_vector": cve_detail.get("cvss_vector"),
                "epss_score": cve_detail.get("epss_score"),
                "description": cve_detail.get("description"),
                "in_kev": in_kev,
                "kev_ransomware": bool(kev_entry and kev_entry.ransomware_campaign_use),
                "severity": enriched.severity.value,
                "attack_techniques": [
                    {
                        "id": a.technique_id,
                        "name": a.technique_name,
                        "tactic": a.tactic,
                        "kill_chain_pos": a.kill_chain_pos,
                        "confidence": a.confidence,
                    }
                    for a in attack_chain
                ],
                "control_gaps": [
                    {"id": c.control_id, "name": c.control_name, "framework": c.framework}
                    for c in (enriched.control_gaps or [])
                ],
                # Deeper analysis
                "p_exploitation": graph.p_exploitation,
                "risk_tier": graph.risk_tier,
                "p_access": graph.p_access,
                "p_exploit_given_access": graph.p_exploit_given_access,
                "p_blocked": graph.p_blocked,
                "domain_scores": graph.domain_scores,
                "related_entities": [
                    {"id": n.node_id, "type": n.node_type, "name": n.name, "properties": n.properties}
                    for n in graph.nodes
                ],
                "relationships": [
                    {"id": e.edge_id, "type": e.edge_type, "from": e.source_node_id,
                     "to": e.target_node_id, "confidence": e.confidence}
                    for e in graph.edges
                ],
                "remediation_scenarios": graph.counterfactuals,
                "playbook": playbook_md,
                "duration_ms": duration_ms,
            },
            indent=2,
            default=str,
        )
    else:
        from risk_scanner.core.models import ScanResult
        from risk_scanner.reporters import get_reporter

        # ── Section 1: the same enrichment report enrich-cve produces ────────
        scan_result = ScanResult(
            scan_id=f"RS-INV-{_uuid.uuid4().hex[:8].upper()}",
            artifact_path=cve_id,
            artifact_type="cve-investigate",
            domains_run=[Domain.CVE],
            findings=enriched_list or [finding],
            duration_ms=duration_ms,
        )
        try:
            enrich_md = get_reporter("markdown").render(scan_result)  # type: ignore[arg-type]
        except Exception:
            enrich_md = f"*Enrichment report unavailable.*\n"

        # ── Section 2: deeper entity analysis + detection playbook ───────────
        entity_md = render_conversation(
            graph=graph,
            cve_id=cve_id,
            cve_detail=cve_detail,
            attack_chain=attack_chain,
            kev_entry=kev_entry,
            environment=environment or "bare_metal",
            criticality=criticality or "medium",
            controls_csv=controls or "",
            playbook_md=playbook_md,
        )

        rendered = enrich_md + "\n\n---\n\n" + entity_md

    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Investigation written to[/green] {output}")
    else:
        print(rendered)

    raise typer.Exit(1 if (in_kev and (criticality or "") == "crown_jewel") else 0)


@app.command("related-cves")
def cmd_related_cves(
    query: str = typer.Argument(
        ...,
        help=(
            "Query: software name+version, T-code, tactic, kill chain phase, or purl. "
            "Examples: 'openssl 3.0.7', 'T1190', 'Initial Access', "
            "'Exploitation kill chain phase', 'pkg:npm/lodash@4.17.21'"
        ),
    ),
    max_results: int = typer.Option(20, "--max", "-n", help="Maximum results to return"),
    min_cvss: float = typer.Option(0.0, "--min-cvss", help="Minimum CVSS score"),
    fmt: str = typer.Option(
        "markdown", "--format", "-o", help="Output format: markdown|json"
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-O"),
) -> None:
    """Find CVEs related by ATT&CK technique — routes by intent (software, technique, tactic, kill chain, SBOM).

    Examples:

        risk-scanner scan related-cves 'openssl 3.0.7'

        risk-scanner scan related-cves T1190 --min-cvss 7.0 --max 10

        risk-scanner scan related-cves 'Initial Access' --format json

        risk-scanner scan related-cves 'Exploitation kill chain phase'
    """
    _bootstrap()
    try:
        from asteraskills.tools.related_cves_skill import _execute_related_cves
        data = _execute_related_cves(query=query, max_results=max_results, min_cvss=min_cvss)
    except Exception as exc:
        console.print(f"[red]Related CVE query failed:[/red] {exc}")
        raise typer.Exit(2)

    if fmt == "json":
        import json as _json
        rendered = _json.dumps(data, indent=2, default=str)
    else:
        intent = data.get("intent_type", "unknown")
        results = data.get("results", [])
        source_map = data.get("source_map", {})

        lines = [f"## Related CVEs — `{query}` (intent: **{intent}**)\n"]

        if intent == "sbom" and source_map:
            for comp, info in source_map.items():
                lines.append(f"### `{comp}`")
                for r in info.get("related_cves", []):
                    lines.append(
                        f"- `{r['cve_id']}` score {r.get('composite_score', 0):.2f} — "
                        f"shared: {', '.join(r.get('shared_techniques', []))}"
                    )
            rendered = "\n".join(lines)
        elif results:
            table = Table(title=f"Related CVEs — {query}")
            table.add_column("CVE ID", style="bold")
            table.add_column("CVSS", style="red")
            table.add_column("EPSS")
            table.add_column("Exploit")
            table.add_column("Techniques")
            table.add_column("Score")
            for r in results:
                table.add_row(
                    r.get("cve_id", ""),
                    f"{r.get('cvss_score', 0):.1f}",
                    f"{r.get('epss_score', 0):.3f}",
                    r.get("exploit_maturity", "none"),
                    ", ".join(r.get("matched_technique_ids", [])[:3]),
                    f"{r.get('composite_score', 0):.3f}",
                )
            console.print(table)
            rendered = ""
        else:
            rendered = f"No related CVEs found for `{query}` (intent: {intent})."

    if rendered:
        if output:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Report written to[/green] {output}")
        else:
            print(rendered)

    raise typer.Exit(0)


def _get_llm_quietly() -> object:
    """Return the asteraskills LLM instance, or raise if unavailable."""
    from asteraskills.core.llm import get_llm
    return get_llm()


def _bootstrap() -> None:
    """Load .env — CWD first, then asteraskills repo root, then ASTERASKILLS_ENV_FILE."""
    try:
        from dotenv import load_dotenv, find_dotenv
        # 1. CWD / parent search — picks up complianceskill/.env (or any project .env)
        #    when risk-scanner is run from that directory.  override=False so shell
        #    env vars (e.g. already-exported OPENAI_API_KEY) are never clobbered.
        cwd_env = find_dotenv(usecwd=True)
        if cwd_env:
            load_dotenv(cwd_env, override=False)
    except Exception:
        pass
    try:
        # 2. asteraskills repo root .env + ASTERASKILLS_ENV_FILE (existing behaviour)
        from asteraskills.bridge import bootstrap
        bootstrap()
    except Exception:
        pass


def _print_stats(result: object) -> None:
    table = Table(title=f"Scan {result.scan_id}")  # type: ignore[union-attr]
    table.add_column("Domain", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")
    table.add_column("Medium")
    table.add_column("Low")
    table.add_column("Total")
    from collections import defaultdict
    from risk_scanner.core.models import Severity
    by_domain: dict = defaultdict(lambda: defaultdict(int))
    for f in result.findings:  # type: ignore[union-attr]
        by_domain[f.domain.value][f.severity.value] += 1
    for domain, counts in sorted(by_domain.items()):
        total = sum(counts.values())
        table.add_row(
            domain,
            str(counts.get("CRITICAL", 0)),
            str(counts.get("HIGH", 0)),
            str(counts.get("MEDIUM", 0)),
            str(counts.get("LOW", 0)),
            str(total),
        )
    console.print(table)
    console.print(f"Duration: {result.duration_ms}ms | Suppressed: {len(result.suppressed)}")  # type: ignore[union-attr]


def _print_scan_all_summary(results: list, fmt: str, output: Optional[Path]) -> None:
    from risk_scanner.reporters import get_reporter
    # For multi-file scan, print each result
    all_output = []
    for r in results:
        try:
            reporter = get_reporter(fmt)  # type: ignore[arg-type]
            all_output.append(reporter.render(r))
        except Exception:
            pass
    combined = "\n\n---\n\n".join(all_output)
    if output:
        output.write_text(combined, encoding="utf-8")
        console.print(f"[green]Reports written to[/green] {output}")
    else:
        print(combined)
