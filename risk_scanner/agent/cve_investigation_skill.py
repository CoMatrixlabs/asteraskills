"""
Claude skill entry point for CVE Alert Investigation.

Functions here are called directly by Claude when a CVE investigation conversation
is active. Session state is stored in-process keyed by session_id, backed by the
LangGraph MemorySaver checkpointer inside cve_alert_agent.

Typical conversation flow:
    investigate_cve_alert("CVE-2024-26855", "scanner says HIGH", session_id="abc")
    → agent enriches CVE, returns severity summary + first question

    ask_followup("Kubernetes EKS worker nodes", session_id="abc")
    → agent records environment, asks about asset criticality

    ask_followup("crown jewel nodes, process PII", session_id="abc")
    → agent delivers full analysis: kill chain, priority, detection queries, CPE guide

    get_detection_queries(session_id="abc", platform="kql")
    get_priority_assessment(session_id="abc")
    get_attack_path(session_id="abc")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# In-process session context: session_id → last state dict
# (The LangGraph MemorySaver in cve_alert_agent is the authoritative store;
#  this dict caches the last returned state for fast extraction functions.)
_session_context: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Primary skill functions (called by Claude)
# ---------------------------------------------------------------------------


def investigate_cve_alert(
    cve_id_or_report: str,
    question: str = "",
    session_id: str = "default",
) -> str:
    """Start or continue a CVE investigation conversation.

    Call this when the user first mentions a CVE alert. The agent will enrich the
    CVE automatically and respond with a severity summary + one clarifying question.

    Args:
        cve_id_or_report: A CVE ID (e.g. "CVE-2024-26855"), a raw alert message,
                          or a path to a CVE report file.
        question:         Additional context from the user (e.g. "scanner says HIGH,
                          should I page someone?"). Appended to the message.
        session_id:       Session identifier for multi-turn persistence.

    Returns:
        Agent's first response: severity reality check + first clarifying question.
    """
    from asteraskills.agents.cve_alert_agent import run_investigation_turn

    # Build the initial message
    message_parts = [cve_id_or_report.strip()]
    if question.strip():
        message_parts.append(question.strip())
    user_text = " ".join(message_parts)

    # If it looks like a file path, try to read a summary line
    if cve_id_or_report.endswith(".md") or "/" in cve_id_or_report:
        try:
            import pathlib
            p = pathlib.Path(cve_id_or_report)
            if p.exists():
                content = p.read_text()[:1500]
                user_text = f"CVE report: {content}\n\n{question}".strip()
        except Exception:
            pass  # Fall through to plain text

    try:
        state = run_investigation_turn(user_text, thread_id=session_id)
        _session_context[session_id] = state
        from asteraskills.agents.cve_alert_agent import get_last_response
        return get_last_response(state)
    except Exception as exc:
        log.error("investigate_cve_alert failed: %s", exc)
        return (
            f"I encountered an error starting the CVE investigation: {exc}\n\n"
            "Please check that the CVE ID is valid (e.g. CVE-2024-26855) and try again."
        )


def ask_followup(
    message: str,
    session_id: str = "default",
) -> str:
    """Continue an existing CVE investigation thread with a user reply.

    Use this for every message after the initial investigate_cve_alert call.
    The agent tracks conversation state automatically — it will ask the next
    clarifying question or deliver the full analysis when enough context is gathered.

    Args:
        message:    The user's reply to the agent's last question (e.g. environment
                    description, asset criticality, controls list).
        session_id: Session identifier — must match the original investigate_cve_alert call.

    Returns:
        Agent's next response: follow-up question or full analysis.
    """
    from asteraskills.agents.cve_alert_agent import run_investigation_turn, get_last_response

    if session_id not in _session_context:
        return (
            f"No active investigation found for session '{session_id}'. "
            "Start a new investigation with investigate_cve_alert() first."
        )

    try:
        state = run_investigation_turn(message, thread_id=session_id)
        _session_context[session_id] = state
        return get_last_response(state)
    except Exception as exc:
        log.error("ask_followup failed: %s", exc)
        return f"Error continuing investigation: {exc}"


def get_detection_queries(
    session_id: str = "default",
    platform: str = "kql",
) -> str:
    """Extract detection queries from a completed or in-progress investigation.

    If the investigation has reached the analysis stage, returns ready-to-use
    detection queries for the requested platform. If the agent hasn't generated
    queries yet, runs the detection_query_builder tool directly.

    Args:
        session_id: Session identifier.
        platform:   Target platform: "kql" (Microsoft Sentinel), "splunk", "elastic",
                    or "sigma" (vendor-neutral).

    Returns:
        Detection queries as a Markdown code block, with false positive notes.
    """
    state = _session_context.get(session_id)
    if state is None:
        return f"No active investigation for session '{session_id}'. Run investigate_cve_alert() first."

    # Try cached detection_queries from state
    detection_queries = state.get("detection_queries")
    if detection_queries and isinstance(detection_queries, dict):
        platform_queries = detection_queries.get(platform, detection_queries.get("kql", ""))
        if platform_queries:
            return f"## Detection Queries ({platform.upper()})\n\n{platform_queries}"

    # Extract CVE ID from state messages and call the tool directly
    cve_id = state.get("cve_id")
    if not cve_id:
        return "No CVE ID found in session. Start an investigation first."

    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("detection_query_builder")
        if not factory:
            return "detection_query_builder tool not available."
        tool = factory()
        result = tool.invoke({"cve_id": cve_id, "platform": platform})
        return str(result)
    except Exception as exc:
        log.error("get_detection_queries failed: %s", exc)
        return f"Failed to generate detection queries: {exc}"


def get_priority_assessment(session_id: str = "default") -> str:
    """Extract the priority score and remediation SLA from the investigation.

    Returns the multi-factor priority tier (P0-P5), SLA recommendation, page-on-call
    decision, and score rationale. Useful for VM/patch team reporting.

    Args:
        session_id: Session identifier.

    Returns:
        Priority assessment as a Markdown summary.
    """
    state = _session_context.get(session_id)
    if state is None:
        return f"No active investigation for session '{session_id}'."

    priority_result = state.get("priority_result")
    if priority_result and isinstance(priority_result, dict):
        tier = priority_result.get("priority_tier", "—")
        score = priority_result.get("raw_score", 0)
        sla = priority_result.get("sla_days", "—")
        page = priority_result.get("page_on_call", False)
        rationale = priority_result.get("rationale", "")
        return (
            f"## Priority Assessment — {state.get('cve_id', 'CVE')}\n\n"
            f"**Tier:** {tier}  \n"
            f"**Score:** {score:.3f}  \n"
            f"**Remediation SLA:** {sla} days  \n"
            f"**Page on-call:** {'Yes' if page else 'No'}  \n\n"
            f"**Rationale:** {rationale}"
        )

    cve_id = state.get("cve_id")
    if not cve_id:
        return "No CVE ID in session. Run investigate_cve_alert() first."

    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("priority_score_calculator")
        if not factory:
            return "priority_score_calculator tool not available."
        tool = factory()
        criticality = state.get("asset_criticality", "medium")
        internet = state.get("internet_facing", False)
        result = tool.invoke({
            "cve_id": cve_id,
            "asset_criticality": criticality,
            "internet_facing": internet,
        })
        return str(result)
    except Exception as exc:
        log.error("get_priority_assessment failed: %s", exc)
        return f"Failed to calculate priority: {exc}"


def get_attack_path(session_id: str = "default") -> str:
    """Extract the kill chain and ATT&CK technique path from the investigation.

    Returns the full kill chain with ATT&CK phases, techniques, and environment-specific
    notes. Useful for threat intelligence team reporting and detection engineering.

    Args:
        session_id: Session identifier.

    Returns:
        Kill chain as a Markdown table with ATT&CK technique IDs and tactics.
    """
    state = _session_context.get(session_id)
    if state is None:
        return f"No active investigation for session '{session_id}'."

    kill_chain = state.get("kill_chain")
    if kill_chain and isinstance(kill_chain, dict):
        stages = kill_chain.get("stages", [])
        if stages:
            lines = [
                f"## Kill Chain — {state.get('cve_id', 'CVE')}",
                f"**Attack Vector:** {kill_chain.get('attack_vector', '—')}",
                f"**Environment:** {state.get('environment_type', '—')}\n",
                "| Phase | Tactic | Techniques | Notes |",
                "|---|---|---|---|",
            ]
            for s in stages:
                phase = s.get("phase", "")
                tactic = s.get("tactic", "")
                techniques = ", ".join(s.get("att&ck", s.get("techniques", [])))
                notes = s.get("notes", "—")
                lines.append(f"| {phase} | {tactic} | {techniques} | {notes} |")
            return "\n".join(lines)

    cve_id = state.get("cve_id")
    if not cve_id:
        return "No CVE ID in session. Run investigate_cve_alert() first."

    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("kill_chain_builder")
        if not factory:
            return "kill_chain_builder tool not available."
        tool = factory()
        env = state.get("environment_type", "")
        result = tool.invoke({"cve_id": cve_id, "environment_context": env})
        return str(result)
    except Exception as exc:
        log.error("get_attack_path failed: %s", exc)
        return f"Failed to build attack path: {exc}"


def get_cpe_commands(session_id: str = "default") -> str:
    """Get the commands to verify whether your environment is affected.

    Returns environment-specific shell commands, Kubernetes queries, or Ansible
    tasks to confirm whether the CVE's affected software/version is present.

    Args:
        session_id: Session identifier.

    Returns:
        Investigation commands as Markdown code blocks, by environment type.
    """
    state = _session_context.get(session_id)
    if state is None:
        return f"No active investigation for session '{session_id}'."

    cpe_guide = state.get("cpe_guide")
    if cpe_guide and isinstance(cpe_guide, dict):
        return str(cpe_guide.get("content", cpe_guide))

    cve_id = state.get("cve_id")
    if not cve_id:
        return "No CVE ID in session. Run investigate_cve_alert() first."

    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("cpe_investigation_guide")
        if not factory:
            return "cpe_investigation_guide tool not available."
        tool = factory()
        env = state.get("environment_type", "linux")
        result = tool.invoke({"cve_id": cve_id, "environment_type": env})
        return str(result)
    except Exception as exc:
        log.error("get_cpe_commands failed: %s", exc)
        return f"Failed to generate CPE investigation guide: {exc}"


def list_active_sessions() -> str:
    """List all active CVE investigation sessions.

    Returns:
        Markdown list of session IDs with CVE ID and current analysis stage.
    """
    if not _session_context:
        return "No active investigation sessions."

    lines = ["## Active CVE Investigation Sessions\n"]
    for sid, state in _session_context.items():
        cve_id = state.get("cve_id", "unknown CVE")
        stage = state.get("analysis_stage", "unknown")
        questions = state.get("questions_asked", 0)
        lines.append(f"- **{sid}**: {cve_id} — stage: `{stage}`, questions asked: {questions}")
    return "\n".join(lines)


def list_data_sources(investigation_type: Optional[str] = None) -> str:
    """List all available detection playbook data sources.

    Shows the data sources for which investigation playbooks exist, with the
    investigation types each source covers and supported SIEM platforms.
    Use this to help the user select which data source to run a playbook against.

    Args:
        investigation_type: Optional filter — e.g. "lateral_movement",
            "privilege_escalation", "command_and_control", "exfiltration", "impact".

    Returns:
        Markdown table of available data sources.
    """
    try:
        from asteraskills.tools import TOOL_REGISTRY
        factory = TOOL_REGISTRY.get("list_playbook_data_sources")
        if not factory:
            return "list_playbook_data_sources tool not available."
        tool = factory()
        result = tool.invoke({"investigation_type": investigation_type})
        import json
        data = json.loads(result) if isinstance(result, str) else result
        sources = data.get("sources", [])
        if not sources:
            return f"No data sources found for investigation_type='{investigation_type}'."

        lines = ["## Available Detection Playbook Data Sources\n"]
        if investigation_type:
            lines[0] = f"## Data Sources — {investigation_type}\n"
        lines += [
            "| Source ID | Description | Investigation Types | Platforms |",
            "|---|---|---|---|",
        ]
        for s in sources:
            types = ", ".join(s.get("investigation_types", []))
            platforms = ", ".join(s.get("platform_hints", [])[:2])
            lines.append(
                f"| `{s['source_id']}` | {s['description']} | {types} | {platforms} |"
            )
        lines.append(
            "\nTo fetch investigation questions for a source, call "
            "`get_playbook_for_source(source_id=..., investigation_scenario=...)`"
        )
        return "\n".join(lines)
    except Exception as exc:
        log.error("list_data_sources failed: %s", exc)
        return f"Failed to list data sources: {exc}"


def get_playbook_for_source(
    source_id: str,
    investigation_scenario: str = "",
    investigation_type: Optional[str] = None,
    session_id: str = "default",
) -> str:
    """Fetch detection playbook investigation questions for a chosen data source.

    The user selects a data source (e.g. 'sysmon', 'aws_cloudtrail') and describes
    what they are investigating. The function returns the matching playbook(s) with
    natural language investigation questions that the user can then run as queries
    on their SIEM platform of choice.

    Args:
        source_id:               Data source identifier from list_data_sources().
                                 e.g. "windows_security_events", "sysmon", "kubernetes_audit"
        investigation_scenario:  What the user is investigating. Used for similarity
                                 search against the playbook knowledge base.
                                 e.g. "credential theft lateral movement", "container escape"
        investigation_type:      Optional filter: initial_access | lateral_movement |
                                 privilege_escalation | execution | command_and_control |
                                 exfiltration | defense_evasion | reconnaissance | impact
        session_id:              Session identifier (used to enrich scenario with CVE context).

    Returns:
        Markdown-formatted playbook with natural language investigation questions.
    """
    import json

    state = _session_context.get(session_id)

    # Pull enrichment from active session
    cve_id_from_session = state.get("cve_id") if state else None
    cvss_vector   = (state or {}).get("cvss_vector")
    cvss_score    = (state or {}).get("cvss_score")
    epss_score    = (state or {}).get("epss_score", 0.0)
    in_kev        = (state or {}).get("in_kev", False)
    kev_ransomware= (state or {}).get("kev_ransomware", False)
    env_type      = (state or {}).get("environment_type", "bare_metal")
    criticality   = (state or {}).get("asset_criticality", "medium")
    internet      = (state or {}).get("internet_facing", False)
    controls      = bool((state or {}).get("controls_in_place"))

    # Try the full causal synthesizer first (uses KB + causal engine)
    try:
        from asteraskills.tools import TOOL_REGISTRY

        synth_factory = TOOL_REGISTRY.get("synthesize_playbook")
        if synth_factory and cve_id_from_session:
            tool = synth_factory()
            raw = tool.invoke({
                "cve_id":           cve_id_from_session,
                "cvss_vector":      cvss_vector,
                "cvss_base":        cvss_score,
                "epss_score":       epss_score or 0.0,
                "in_kev":           in_kev or False,
                "kev_ransomware":   kev_ransomware or False,
                "environment_type": env_type or "bare_metal",
                "asset_criticality":criticality or "medium",
                "internet_facing":  internet or False,
                "has_controls":     controls,
                "source_id":        source_id,
            })
            data = json.loads(raw) if isinstance(raw, str) else raw
            if data.get("synthesised_playbooks"):
                # Render the causal playbook as Markdown
                from asteraskills.agents.playbook_synthesizer import PlaybookSynthesizer
                synth = PlaybookSynthesizer()
                result = synth.synthesize(
                    cve_id=cve_id_from_session,
                    cvss_vector=cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cvss_base=float(cvss_score or 9.8),
                    epss_score=float(epss_score or 0.0),
                    in_kev=bool(in_kev),
                    kev_ransomware=bool(kev_ransomware),
                    environment_type=env_type or "bare_metal",
                    asset_criticality=criticality or "medium",
                    internet_facing=bool(internet),
                    has_controls=controls,
                    source_id=source_id,
                )
                return result.to_markdown()
    except Exception as exc:
        log.debug("Causal synthesizer path failed, falling back to KB search: %s", exc)

    # Fallback: direct similarity search against detection_playbooks collection
    try:
        query_parts = [investigation_scenario] if investigation_scenario else []
        if cve_id_from_session:
            query_parts.append(cve_id_from_session)
        if env_type:
            query_parts.append(env_type)
        query = " ".join(query_parts) or "security investigation"

        factory = TOOL_REGISTRY.get("detection_playbook_search")
        if not factory:
            return "detection_playbook_search tool not available."
        tool = factory()
        result = tool.invoke({
            "query": query,
            "source_id": source_id,
            "investigation_type": investigation_type,
            "top_k": 3,
        })

        data = json.loads(result) if isinstance(result, str) else result
        if not data.get("success"):
            return f"Playbook search failed: {data.get('error', 'unknown error')}"

        playbooks = data.get("results", [])
        if not playbooks:
            return (
                f"No playbooks found for source_id=`{source_id}`. "
                "Try `list_data_sources()` to see available sources."
            )

        lines = [
            f"## Detection Playbooks — `{source_id}`",
            f"**Investigation context:** {investigation_scenario or 'general'}",
        ]
        if cve_id_from_session:
            lines.append(f"**CVE:** {cve_id_from_session}")
        lines.append("")

        for pb in playbooks:
            questions = pb.get("investigation_questions", [])
            lines += [
                f"### {pb.get('playbook_title', 'Playbook')}",
                f"**Trigger:** {pb.get('trigger', '')}  ",
                f"**Investigation type:** `{pb.get('investigation_type', '')}`  ",
                "",
            ]
            if questions:
                lines.append("**Investigation Questions:**\n")
                for i, q in enumerate(questions, 1):
                    lines.append(f"{i}. {q}")
            lines.append("")

        lines += [
            "---",
            "_Use `get_detection_queries()` to generate platform-specific queries from these questions._",
        ]
        return "\n".join(lines)

    except Exception as exc:
        log.error("get_playbook_for_source failed: %s", exc)
        return f"Failed to fetch playbook for source '{source_id}': {exc}"


def clear_session(session_id: str = "default") -> str:
    """Clear a CVE investigation session.

    Args:
        session_id: Session ID to clear.

    Returns:
        Confirmation message.
    """
    if session_id in _session_context:
        del _session_context[session_id]
        # Also clear the LangGraph checkpointer thread if accessible
        try:
            from asteraskills.agents.cve_alert_agent import clear_agent_cache
            clear_agent_cache()
        except Exception:
            pass
        return f"Session '{session_id}' cleared."
    return f"No session '{session_id}' found."
