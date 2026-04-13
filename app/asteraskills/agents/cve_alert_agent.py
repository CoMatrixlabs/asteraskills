"""
CVE Alert Investigation Agent — standalone LangGraph StateGraph.

Conversational flow:
  intake → gather_context (1-3 turns) → analyze → respond

The agent enriches the CVE automatically on the first turn, then asks focused
clarifying questions (environment → criticality → controls) before running the
full detection analysis suite.

Usage::

    from asteraskills.agents.cve_alert_agent import run_investigation_turn

    # Turn 1 — initial alert
    result = run_investigation_turn(
        "We got CVE-2024-26855 on our Kubernetes nodes.",
        thread_id="session-abc123",
    )

    # Turn 2 — answer the agent's question
    result = run_investigation_turn(
        "They're EKS worker nodes running kernel 6.5.x",
        thread_id="session-abc123",
    )
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import List, Literal, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import MessagesState
from langgraph.prebuilt import ToolNode

log = logging.getLogger(__name__)

# Shared in-process checkpointer (swap for Postgres saver in production)
_CHECKPOINTER = MemorySaver()

# Keys from TOOL_REGISTRY for the CVE alert agent
CVE_ALERT_TOOL_KEYS: List[str] = [
    # Core CVE data
    "cve_intelligence",
    "epss_lookup",
    "cisa_kev_check",
    # Detection analysis
    "detection_scenario_search",
    "kill_chain_builder",
    "priority_score_calculator",
    "cpe_investigation_guide",
    "detection_query_builder",
    "cvss_vector_explainer",
    # Detection playbooks (by data source, NL investigation questions)
    "detection_playbook_search",
    "list_playbook_data_sources",
    "synthesize_playbook",
    # ATT&CK / control mapping
    "cve_to_attack_mapper",
    "attack_to_control_mapper",
    "cwe_capec_attack_mappings_db",
]


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class CVEAlertState(MessagesState, total=False):
    """Conversation state for the CVE alert investigation agent."""

    # Extracted from initial message
    cve_id: Optional[str]

    # CVE enrichment (populated in intake node)
    cve_data: Optional[dict]
    cvss_vector: Optional[str]
    attack_vector: Optional[str]       # "network" | "local" | "adjacent" | "physical"
    cvss_score: Optional[float]
    epss_score: Optional[float]
    in_kev: Optional[bool]
    kev_ransomware: Optional[bool]

    # Environment context (gathered from user)
    environment_type: Optional[str]    # "k8s" | "cloud_vm" | "bare_metal" | "container" | "mixed"
    affected_assets: Optional[list]
    asset_criticality: Optional[str]   # "crown_jewel" | "high" | "medium" | "low"
    controls_in_place: Optional[list]
    internet_facing: Optional[bool]

    # Analysis outputs
    kill_chain: Optional[dict]
    priority_result: Optional[dict]
    detection_queries: Optional[dict]
    cpe_guide: Optional[dict]

    # Conversation tracking
    analysis_stage: str                # "intake" | "gathering" | "analyzing" | "complete"
    questions_asked: int
    current_question_topic: Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_cve_id(text: str) -> Optional[str]:
    m = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def _latest_user_text(state: CVEAlertState) -> str:
    for m in reversed(state["messages"]):
        if isinstance(m, HumanMessage):
            c = m.content
            return c if isinstance(c, str) else str(c)
    return ""


def _infer_environment(text: str) -> Optional[str]:
    t = text.lower()
    if any(k in t for k in ("kubernetes", "k8s", "eks", "aks", "gke", "pod", "node")):
        return "k8s"
    if any(k in t for k in ("container", "docker", "containerd")):
        return "container"
    if any(k in t for k in ("bare metal", "baremetal", "physical server")):
        return "bare_metal"
    if any(k in t for k in ("ec2", "gce", "azure vm", "cloud vm", "virtual machine", "vm")):
        return "cloud_vm"
    if "mixed" in t:
        return "mixed"
    return None


def _infer_criticality(text: str) -> Optional[str]:
    t = text.lower()
    if any(k in t for k in ("crown jewel", "critical", "pci", "phi", "pii", "production", "prod")):
        return "crown_jewel"
    if any(k in t for k in ("high", "important", "sensitive")):
        return "high"
    if any(k in t for k in ("dev", "staging", "test", "low", "non-prod")):
        return "low"
    return None


def _load_tools() -> List[BaseTool]:
    """Lazily load detection agent tools from TOOL_REGISTRY."""
    from asteraskills.tools import TOOL_REGISTRY
    tools: List[BaseTool] = []
    for key in CVE_ALERT_TOOL_KEYS:
        factory = TOOL_REGISTRY.get(key)
        if factory:
            try:
                tools.append(factory())
            except Exception as exc:
                log.warning("CVE alert agent: failed to load tool %s: %s", key, exc)
    return tools


def _get_llm(tools: Optional[List[BaseTool]] = None):
    from asteraskills.core.llm import get_llm
    llm = get_llm(temperature=0.1)
    if tools:
        return llm.bind_tools(tools)
    return llm


def _load_system_prompt() -> str:
    import pathlib
    prompt_path = pathlib.Path(__file__).parent / "prompts" / "cve_alert.md"
    try:
        return prompt_path.read_text()
    except FileNotFoundError:
        return (
            "You are a CVE alert investigation assistant. "
            "Enrich the CVE, ask about environment and asset criticality, "
            "then provide kill chain, priority, and detection queries."
        )


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

def intake_node(state: CVEAlertState) -> dict:
    """
    Turn 1: extract CVE ID from user message, set initial stage.
    The actual enrichment happens inside the agent_node via tool calls.
    """
    text = _latest_user_text(state)
    cve_id = state.get("cve_id") or _extract_cve_id(text)
    updates: dict = {
        "analysis_stage": "intake",
        "questions_asked": 0,
    }
    if cve_id:
        updates["cve_id"] = cve_id
    return updates


def gather_context_node(state: CVEAlertState) -> dict:
    """
    Update state from user's latest message: infer environment, criticality.
    Called after each user turn following intake.
    """
    text = _latest_user_text(state)
    updates: dict = {}

    env = _infer_environment(text)
    if env and not state.get("environment_type"):
        updates["environment_type"] = env

    crit = _infer_criticality(text)
    if crit and not state.get("asset_criticality"):
        updates["asset_criticality"] = crit

    # Parse controls mentioned
    controls = []
    for ctrl in ("selinux", "apparmor", "edr", "waf", "ids", "ips", "seccomp",
                 "network policy", "rbac", "restricted ssh", "egress filter"):
        if ctrl in text.lower():
            controls.append(ctrl)
    if controls and not state.get("controls_in_place"):
        updates["controls_in_place"] = controls

    if "internet" in text.lower() or "public" in text.lower():
        updates["internet_facing"] = True
    elif "internal" in text.lower() or "private" in text.lower():
        updates["internet_facing"] = False

    current = state.get("questions_asked", 0)
    updates["questions_asked"] = current

    # Determine if we have enough to proceed to analysis
    has_env = bool(state.get("environment_type") or updates.get("environment_type"))
    has_crit = bool(state.get("asset_criticality") or updates.get("asset_criticality"))
    questions = state.get("questions_asked", 0)

    if (has_env and has_crit) or questions >= 3:
        updates["analysis_stage"] = "analyzing"
    else:
        updates["analysis_stage"] = "gathering"

    return updates


def agent_node(state: CVEAlertState) -> dict:
    """
    Core LLM node: enriches CVE on first turn, asks questions, delivers analysis.
    Uses tool-calling for all data retrieval.
    """
    tools = _load_tools()
    llm = _get_llm(tools)
    system_prompt = _load_system_prompt()

    stage = state.get("analysis_stage", "intake")
    cve_id = state.get("cve_id", "")
    questions_asked = state.get("questions_asked", 0)

    # Inject structured context into system prompt
    context_parts = []
    if cve_id:
        context_parts.append(f"CVE under investigation: {cve_id}")
    if state.get("environment_type"):
        context_parts.append(f"Environment: {state['environment_type']}")
    if state.get("asset_criticality"):
        context_parts.append(f"Asset criticality: {state['asset_criticality']}")
    if state.get("controls_in_place"):
        context_parts.append(f"Controls in place: {', '.join(state['controls_in_place'])}")
    if state.get("internet_facing") is not None:
        context_parts.append(f"Internet-facing: {state['internet_facing']}")
    if state.get("in_kev") is not None:
        context_parts.append(f"In CISA KEV: {state['in_kev']}")
    if state.get("epss_score") is not None:
        context_parts.append(f"EPSS score: {state['epss_score']:.4f}")
    context_parts.append(f"Analysis stage: {stage}")
    context_parts.append(f"Questions asked so far: {questions_asked}")

    if stage == "intake":
        context_parts.append(
            "ACTION: Enrich the CVE using your tools (cve_intelligence, epss_lookup, "
            "cisa_kev_check, cvss_vector_explainer). Then give the user a one-paragraph "
            "severity reality check and ask ONE question about their environment."
        )
    elif stage == "gathering":
        missing = []
        if not state.get("environment_type"):
            missing.append("environment type (K8s / VM / bare metal / container)")
        if not state.get("asset_criticality"):
            missing.append("asset criticality (crown jewel / high / medium / low)")
        if not state.get("controls_in_place") and questions_asked >= 2:
            missing.append("security controls in place (EDR, SELinux, network isolation)")
        if missing:
            context_parts.append(
                f"ACTION: Ask ONE focused question to gather: {missing[0]}"
            )
        else:
            context_parts.append("ACTION: Proceed to full analysis.")
    elif stage == "analyzing":
        context_parts.append(
            "ACTION: Run kill_chain_builder, priority_score_calculator, "
            "cpe_investigation_guide, and detection_query_builder. "
            "Deliver the full structured analysis report."
        )

    full_system = system_prompt + "\n\n## Current Session Context\n" + "\n".join(
        f"- {p}" for p in context_parts
    )

    messages = [SystemMessage(content=full_system)] + list(state["messages"])

    response = llm.invoke(messages)

    # Track question count increments
    new_questions = questions_asked
    if stage == "gathering" and isinstance(response.content, str):
        if "?" in response.content:
            new_questions += 1

    return {
        "messages": [response],
        "questions_asked": new_questions,
    }


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def _should_use_tools(state: CVEAlertState) -> Literal["tools", "end"]:
    """Check if the last AI message has tool calls."""
    messages = state["messages"]
    for m in reversed(messages):
        if isinstance(m, AIMessage):
            if hasattr(m, "tool_calls") and m.tool_calls:
                return "tools"
            break
    return "end"


def _route_after_intake(state: CVEAlertState) -> Literal["gather_context", "agent"]:
    """After intake, always go to agent (which enriches and asks first question)."""
    return "agent"


def _route_after_gather(state: CVEAlertState) -> str:
    """After context gathering, go to agent."""
    return "agent"


def _route_after_tools(state: CVEAlertState) -> str:
    """After tool execution, return to agent to formulate response."""
    return "agent"


def _is_first_turn(state: CVEAlertState) -> bool:
    human_count = sum(1 for m in state["messages"] if isinstance(m, HumanMessage))
    return human_count <= 1


def _entry_router(state: CVEAlertState) -> str:
    """Route from START: first human message → intake, subsequent → gather_context."""
    if _is_first_turn(state):
        return "intake"
    return "gather_context"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_cve_alert_agent(checkpointer=None):
    """
    Build and compile the CVE alert investigation StateGraph.

    Nodes:
      intake         — extract CVE ID, set initial stage
      gather_context — parse environment/criticality from user reply
      agent          — LLM with tools (enrichment + analysis)
      tools          — ToolNode for all tool calls

    Edges:
      START → intake (turn 1) | gather_context (turn 2+)
      intake → agent
      gather_context → agent
      agent → tools (if tool_calls) | END (if plain response)
      tools → agent
    """
    g = StateGraph(CVEAlertState)

    # Nodes
    g.add_node("intake", intake_node)
    g.add_node("gather_context", gather_context_node)
    g.add_node("agent", agent_node)

    tools = _load_tools()
    g.add_node("tools", ToolNode(tools))

    # Edges from START
    g.add_conditional_edges(
        START,
        _entry_router,
        {"intake": "intake", "gather_context": "gather_context"},
    )

    # From intake → agent
    g.add_edge("intake", "agent")

    # From gather_context → agent
    g.add_edge("gather_context", "agent")

    # From agent → tools or END
    g.add_conditional_edges(
        "agent",
        _should_use_tools,
        {"tools": "tools", "end": END},
    )

    # From tools → back to agent
    g.add_edge("tools", "agent")

    cp = checkpointer if checkpointer is not None else _CHECKPOINTER
    return g.compile(checkpointer=cp)


@lru_cache(maxsize=1)
def get_cve_alert_agent():
    """Compiled CVE alert agent with process-wide MemorySaver."""
    return build_cve_alert_agent()


def clear_agent_cache() -> None:
    get_cve_alert_agent.cache_clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def invoke_config(thread_id: str) -> dict:
    """LangGraph config dict for a persistent session thread."""
    return {"configurable": {"thread_id": thread_id}}


def run_investigation_turn(
    user_text: str,
    *,
    thread_id: str = "default",
    agent=None,
) -> dict:
    """
    Append one user turn and run the CVE investigation agent.

    Args:
        user_text: The user's message (CVE alert text, answer to a question, etc.)
        thread_id: Session thread ID for multi-turn persistence.
        agent: Optional compiled agent (uses shared singleton if omitted).

    Returns:
        Final graph state dict. The agent's response is in state["messages"][-1].
    """
    app = agent or get_cve_alert_agent()
    return app.invoke(
        {"messages": [HumanMessage(content=user_text)]},
        config=invoke_config(thread_id),
    )


def get_last_response(state: dict) -> str:
    """Extract the last AI message text from a state dict."""
    for m in reversed(state.get("messages", [])):
        if isinstance(m, AIMessage):
            return m.content if isinstance(m.content, str) else str(m.content)
    return ""


def get_session_state(thread_id: str) -> Optional[CVEAlertState]:
    """Read current session state from checkpointer (without invoking a new turn)."""
    try:
        agent = get_cve_alert_agent()
        snapshot = agent.get_state(invoke_config(thread_id))
        return snapshot.values if snapshot else None
    except Exception as exc:
        log.debug("get_session_state failed for thread %s: %s", thread_id, exc)
        return None
