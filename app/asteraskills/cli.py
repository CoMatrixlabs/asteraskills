"""
Console entrypoint: list and run vendored LangChain security tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import typer
from rich.console import Console
from rich.table import Table

from langchain_core.messages import AIMessage, HumanMessage

from asteraskills import __version__
from asteraskills.bridge import bootstrap, list_tools, load_tool_registry, run_tool

app = typer.Typer(no_args_is_help=True, add_completion=False)
agent_app = typer.Typer(help="LangGraph CVE / CWE / ATT&CK orchestrator")
console = Console(stderr=True)

app.add_typer(agent_app, name="agent")


def _parse_args_json(raw: Optional[str]) -> Dict[str, Any]:
    if not raw or not raw.strip():
        return {}
    try:
        val = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON: {exc}") from exc
    if not isinstance(val, dict):
        raise typer.BadParameter(
            "JSON for --args must be an object, e.g. {\"cve_id\": \"CVE-2024-1\"}"
        )
    return val


@app.command("list")
def cmd_list(
    repo_root: Optional[Path] = typer.Option(
        None,
        "--repo-root",
        help="Path to asteraskills repository root (directory containing app/).",
    ),
) -> None:
    """Print all tool names and descriptions."""
    bootstrap(repo_root)
    _, registry, _ = load_tool_registry()
    rows = list_tools(registry)
    table = Table(title=f"Astera tools ({len(rows)})")
    table.add_column("name", style="cyan", no_wrap=True)
    table.add_column("description")
    for name, desc in rows:
        table.add_row(name, desc[:500] + ("…" if len(desc) > 500 else ""))
    console.print(table)


@app.command("run")
def cmd_run(
    tool_name: str = typer.Argument(..., help="Registry key, e.g. cve_enrich"),
    args: Optional[str] = typer.Option(
        None,
        "--args",
        "-a",
        help='JSON object of tool arguments, e.g. \'{"cve_id":"CVE-2024-3400"}\'',
    ),
    repo_root: Optional[Path] = typer.Option(None, "--repo-root"),
    pretty: bool = typer.Option(True, "--pretty/--compact"),
) -> None:
    """Invoke a single StructuredTool; JSON on stdout."""
    bootstrap(repo_root)
    _, registry, _ = load_tool_registry()
    payload = _parse_args_json(args)
    try:
        result = run_tool(registry, tool_name, payload)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if pretty:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(json.dumps(result, default=str))


@app.command("doctor")
def cmd_doctor(
    repo_root: Optional[Path] = typer.Option(None, "--repo-root"),
) -> None:
    """Verify settings import and TOOL_REGISTRY load."""
    try:
        root = bootstrap(repo_root)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]bootstrap failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]OK[/green] repo root: {root}")
    try:
        _, reg, _ = load_tool_registry()
        console.print(f"[green]OK[/green] TOOL_REGISTRY size: {len(reg)}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]import failed:[/red] {exc}")
        console.print(
            "Install runtime dependencies: pip install -e '.[runtime]' "
            "and configure Postgres / vector store env vars (see skills/astera-security-intel/SKILL.md)."
        )
        raise typer.Exit(1) from exc


@app.command("version")
def cmd_version() -> None:
    typer.echo(__version__)


@agent_app.command("run")
def cmd_agent_run(
    question: str = typer.Argument(..., help="Natural-language security question"),
    repo_root: Optional[Path] = typer.Option(None, "--repo-root"),
    thread_id: str = typer.Option(
        "default",
        "--thread-id",
        "-t",
        envvar="ASTERASKILLS_THREAD_ID",
        help="Session id for multi-turn memory (LangGraph checkpointer)",
    ),
    show_domain: bool = typer.Option(
        False,
        "--show-domain",
        "-d",
        help="Print chosen specialist (cve|cwe|attack|general) to stderr",
    ),
    show_last_specialist: bool = typer.Option(
        False,
        "--show-last-specialist",
        help="Print previous specialist after run (handoff hint) to stderr",
    ),
) -> None:
    """Run the LangGraph orchestrator (router → CVE / CWE / ATT&CK / general ReAct agent)."""
    bootstrap(repo_root)
    try:
        from asteraskills.agents.orchestrator import get_intel_orchestrator, invoke_config
    except ImportError as exc:
        console.print(f"[red]Import error:[/red] {exc}")
        console.print("Install agents stack: pip install -e '.[runtime]'")
        raise typer.Exit(1) from exc
    orch = get_intel_orchestrator()
    cfg = invoke_config(thread_id)
    try:
        out = orch.invoke(
            {"messages": [HumanMessage(content=question)]},
            config=cfg,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Agent error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if show_domain:
        console.print(f"[cyan]domain[/cyan]: {out.get('domain', '?')}")
    if show_last_specialist:
        console.print(f"[cyan]last_specialist[/cyan]: {out.get('last_specialist', '?')}")
    msgs = out.get("messages") or []
    last = msgs[-1] if msgs else None
    if isinstance(last, AIMessage):
        text = last.content
        print(text if isinstance(text, str) else str(text))
    else:
        print(json.dumps(out, indent=2, default=str))


@agent_app.command("investigate")
def cmd_agent_investigate(
    message: str = typer.Argument(
        ...,
        help=(
            "CVE alert or follow-up. Turn 1: 'CVE-2024-26855 on EKS, crown_jewel, "
            "network_policy'. Subsequent turns: any follow-up question about the graph."
        ),
    ),
    repo_root: Optional[Path] = typer.Option(None, "--repo-root"),
    thread_id: str = typer.Option(
        "default",
        "--thread-id",
        "-t",
        envvar="ASTERASKILLS_THREAD_ID",
        help="Session id — reuse across turns to continue the investigation",
    ),
    show_stage: bool = typer.Option(
        False,
        "--show-stage",
        help="Print current stage and node count to stderr",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text|json",
    ),
) -> None:
    """Interactive CVE investigation — multi-turn conversation.

    On turn 1 the agent enriches the CVE, finds all related entities (affected
    asset, attack techniques, controls, threat signals), and seeds the session
    with a deeper analysis. Follow-up turns can ask about any related entity,
    risk domain score, remediation scenario, or detection question.

    Examples:

        # Turn 1 — start (CVE + environment hints)
        asteraskills agent investigate \\
          "CVE-2024-26855, environment k8s, criticality crown_jewel, controls network_policy" \\
          --thread-id inv-001

        # Turn 2 — ask about a specific step
        asteraskills agent investigate \\
          "Why is p_exploit_given_access so high? What does T1611 enable?" \\
          --thread-id inv-001

        # Turn 3 — ask about a remediation scenario
        asteraskills agent investigate \\
          "What is the risk if we isolate the node instead of patching?" \\
          --thread-id inv-001
    """
    import re as _re
    bootstrap(repo_root)

    try:
        from asteraskills.agents.cve_alert_agent import (
            run_investigation_turn,
            get_last_response,
            get_session_state,
        )
    except ImportError as exc:
        console.print(f"[red]Import error:[/red] {exc}")
        console.print("Install agents stack: pip install -e '.[runtime]'")
        raise typer.Exit(1) from exc

    # ── On turn 1: detect CVE, pre-enrich, build graph, inject as context ────
    cve_match = _re.search(r"CVE-\d{4}-\d+", message, _re.IGNORECASE)
    sess = get_session_state(thread_id)
    is_first_turn = sess is None or not sess.get("cve_id")

    if cve_match and is_first_turn:
        cve_id = cve_match.group(0).upper()
        console.print(f"[dim]Enriching {cve_id} and finding related entities...[/dim]")

        # Parse inline hints from the message
        env_match = _re.search(
            r"\b(?:environment|env)\s*[:\s]\s*(k8s|kubernetes|cloud_vm|container|bare_metal|cloud)",
            message, _re.IGNORECASE,
        )
        crit_match = _re.search(
            r"\b(?:criticality|crit)\s*[:\s]\s*(crown_jewel|high|medium|low|critical)",
            message, _re.IGNORECASE,
        )
        ctrl_match = _re.search(
            r"\b(?:controls?)\s*[:\s]\s*([\w,_ ]+)",
            message, _re.IGNORECASE,
        )
        environment = env_match.group(1).lower() if env_match else "bare_metal"
        criticality = crit_match.group(1).lower() if crit_match else "medium"
        controls_csv = ctrl_match.group(1).strip() if ctrl_match else ""

        # Run the working enrichment pipeline
        try:
            from risk_scanner.core.models import Domain, Evidence, Finding, Severity
            from risk_scanner.core.analyzers.enrichment import EnrichmentAnalyzer
            from risk_scanner.core.pack_client import PackClient
            from risk_scanner.core.kev_client import KevClient

            finding = Finding(
                domain=Domain.CVE,
                taxonomy_code=cve_id,
                severity=Severity.HIGH,
                severity_rationale=f"CVE investigation for {cve_id}",
                evidence=Evidence(matched_rule_id="direct-input", snippet=None),
                confidence=1.0,
            )
            enricher = EnrichmentAnalyzer(
                pack_client=PackClient(),
                llm=None,
                frameworks=None,
                kev_client=KevClient(),
                enrich_cpe=False,
                max_related_cves=0,
            )
            enriched_list = enricher.enrich([finding])
            enriched = enriched_list[0] if enriched_list else finding

            cve_detail   = enriched.cve_detail or {}
            attack_chain = enriched.attack_chain or []
            kev_entry    = enriched.kev_entry

            from asteraskills.agents.entity_investigation import build_graph, render_conversation
            graph = build_graph(
                cve_id=cve_id,
                cve_detail=cve_detail,
                attack_chain=attack_chain,
                kev_entry=kev_entry,
                environment=environment,
                criticality=criticality,
                controls_csv=controls_csv,
            )

            # Render the full entity investigation report as the seeding context
            graph_context = render_conversation(
                graph=graph,
                cve_id=cve_id,
                cve_detail=cve_detail,
                attack_chain=attack_chain,
                kev_entry=kev_entry,
                environment=environment,
                criticality=criticality,
                controls_csv=controls_csv,
            )

            # Inject the graph as a pre-loaded context message so the agent
            # can answer follow-up questions about any node or score
            seeded_message = (
                f"{message}\n\n"
                f"[INVESTIGATION CONTEXT — {len(graph.nodes)} related entities, "
                f"{len(graph.edges)} relationships, P(exploitation)={graph.p_exploitation:.3f}]\n\n"
                f"{graph_context}"
            )
            if show_stage:
                console.print(
                    f"[cyan]entities[/cyan]: {len(graph.nodes)} related · "
                    f"{len(graph.edges)} relationships · P={graph.p_exploitation:.3f} "
                    f"({graph.risk_tier})"
                )
            message = seeded_message

        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Pre-enrichment skipped: {exc} — proceeding with agent only.[/yellow]")

    # ── Run the LangGraph investigation agent ────────────────────────────────
    try:
        state = run_investigation_turn(message, thread_id=thread_id)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Agent error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if show_stage:
        stage = state.get("analysis_stage", "?")
        questions = state.get("questions_asked", 0)
        console.print(f"[cyan]stage[/cyan]: {stage}  [cyan]questions_asked[/cyan]: {questions}")

    if fmt == "json":
        updated_sess = get_session_state(thread_id)
        out = {
            "thread_id": thread_id,
            "response": get_last_response(state),
            "analysis_stage": state.get("analysis_stage"),
            "cve_id": state.get("cve_id"),
            "environment_type": updated_sess.get("environment_type") if updated_sess else None,
            "asset_criticality": updated_sess.get("asset_criticality") if updated_sess else None,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print(get_last_response(state))


@agent_app.command("route")
def cmd_agent_route(
    question: str = typer.Argument(..., help="Question to classify only"),
    repo_root: Optional[Path] = typer.Option(None, "--repo-root"),
) -> None:
    """Print which specialist domain would run (fast; no tool calls)."""
    bootstrap(repo_root)
    try:
        from asteraskills.agents.orchestrator import router_node
    except ImportError as exc:
        console.print(f"[red]Import error:[/red] {exc}")
        raise typer.Exit(1) from exc
    st = router_node({"messages": [HumanMessage(content=question)]})
    typer.echo(st.get("domain", "general"))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
