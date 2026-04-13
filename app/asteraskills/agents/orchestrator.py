"""
LangGraph orchestrator: router → one of four ReAct agents (CVE, CWE, ATT&CK, general).

Supports multi-turn sessions via a checkpointer (``thread_id``) and handoff: each turn
sees full ``messages``; the router can use recent history + ``last_specialist``.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Callable, Literal, Optional

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import MessagesState
from pydantic import BaseModel, Field

from asteraskills.agents.prompts import ROUTER_SYSTEM
from asteraskills.agents.specialists import get_cached_specialist_graph
from asteraskills.core.llm import get_llm

logger = logging.getLogger(__name__)

# Process-wide checkpoint store (CLI / single worker). Swap for Postgres saver in production.
_DEFAULT_CHECKPOINTER = MemorySaver()


class IntelOrchestratorState(MessagesState, total=False):
    """Conversation + routing + last specialist (handoff hint)."""

    domain: str
    last_specialist: str


class RouteDecision(BaseModel):
    domain: Literal["cve", "cwe", "attack", "general"] = Field(
        description="Single best domain for the user's question",
    )


def _latest_user_text(messages: list[BaseMessage]) -> str:
    for m in reversed(messages):
        if isinstance(m, HumanMessage):
            c = m.content
            return c if isinstance(c, str) else str(c)
    return ""


def _recent_transcript(messages: list[BaseMessage], max_messages: int = 10) -> str:
    """Compact recent dialogue for router context (oldest → newest within window)."""
    tail = messages[-max_messages:] if len(messages) > max_messages else messages
    lines: list[str] = []
    for m in tail:
        if isinstance(m, HumanMessage):
            role = "User"
            c = m.content
        elif isinstance(m, AIMessage):
            role = "Assistant"
            c = m.content
        else:
            continue
        text = c if isinstance(c, str) else str(c)
        lines.append(f"{role}: {text[:1200]}{'…' if len(text) > 1200 else ''}")
    return "\n".join(lines) if lines else "(no messages)"


def _heuristic_domain(text: str) -> Optional[str]:
    t = text.lower()
    if re.search(r"\bcve-\d{4}-\d+\b", t, re.I):
        return "cve"
    if re.search(r"\bcwe-\d+\b", t, re.I) or "capec" in t:
        return "cwe"
    if re.search(r"\bt\d{4}(?:\.\d{3})?\b", t, re.I) or "mitre attack" in t or "att&ck" in t:
        return "attack"
    return None


def router_node(state: IntelOrchestratorState) -> dict:
    messages = state["messages"]
    text = _latest_user_text(messages)
    guess = _heuristic_domain(text)
    if guess:
        return {"domain": guess}

    llm = get_llm(temperature=0.0)
    last_spec = (state.get("last_specialist") or "none").strip() or "none"
    transcript = _recent_transcript(messages)
    routing_user = (
        f"Latest user message:\n{text or '(empty)'}\n\n"
        f"Previous specialist (last turn): {last_spec}\n\n"
        f"Recent conversation (for handoff / follow-ups):\n{transcript}\n\n"
        "Choose the domain for the latest user message. "
        "If they ask to pivot (e.g. 'now map that to ATT&CK'), route to the new domain."
    )
    try:
        structured = llm.with_structured_output(RouteDecision)
        decision = structured.invoke(
            [
                SystemMessage(content=ROUTER_SYSTEM),
                HumanMessage(content=routing_user),
            ]
        )
        dom = decision.domain if isinstance(decision, RouteDecision) else "general"
    except Exception as exc:  # noqa: BLE001
        logger.warning("Structured router failed (%s); using general", exc)
        dom = "general"
    return {"domain": dom}


def _specialist_subgraph_node(domain: str) -> Callable[[IntelOrchestratorState], dict]:
    def _node(state: IntelOrchestratorState) -> dict:
        graph = get_cached_specialist_graph(domain)
        sub = graph.invoke({"messages": state["messages"]})
        new_messages = sub.get("messages") or []
        if not new_messages:
            return {
                "messages": [AIMessage(content="(no response from specialist)")],
                "last_specialist": domain,
            }

        last = new_messages[-1]
        if isinstance(last, AIMessage) and last.content:
            return {"messages": [last], "last_specialist": domain}

        for m in reversed(new_messages):
            if isinstance(m, AIMessage) and m.content:
                return {"messages": [m], "last_specialist": domain}
        return {"messages": [AIMessage(content=str(last))], "last_specialist": domain}

    return _node


def _route_after_router(state: IntelOrchestratorState) -> str:
    dom = (state.get("domain") or "general").lower()
    if dom not in ("cve", "cwe", "attack", "general"):
        return "general"
    return dom


def build_intel_orchestrator(checkpointer: Optional[MemorySaver] = None):
    """
    START → router → one of ``cve_agent`` | ``cwe_agent`` | ``attack_agent`` | ``general_agent`` → END.
    Pass ``checkpointer`` for persistence (default: shared in-process ``MemorySaver``).
    """
    g = StateGraph(IntelOrchestratorState)
    g.add_node("router", router_node)
    g.add_node("cve_agent", _specialist_subgraph_node("cve"))
    g.add_node("cwe_agent", _specialist_subgraph_node("cwe"))
    g.add_node("attack_agent", _specialist_subgraph_node("attack"))
    g.add_node("general_agent", _specialist_subgraph_node("general"))

    g.add_edge(START, "router")
    g.add_conditional_edges(
        "router",
        _route_after_router,
        {
            "cve": "cve_agent",
            "cwe": "cwe_agent",
            "attack": "attack_agent",
            "general": "general_agent",
        },
    )
    g.add_edge("cve_agent", END)
    g.add_edge("cwe_agent", END)
    g.add_edge("attack_agent", END)
    g.add_edge("general_agent", END)
    cp = checkpointer if checkpointer is not None else _DEFAULT_CHECKPOINTER
    return g.compile(checkpointer=cp)


@lru_cache(maxsize=1)
def get_intel_orchestrator():
    """Compiled orchestrator with process-wide ``MemorySaver``."""
    return build_intel_orchestrator()


def get_default_checkpointer() -> MemorySaver:
    """Shared checkpointer used by ``get_intel_orchestrator`` (for tests / inspection)."""
    return _DEFAULT_CHECKPOINTER


def clear_orchestrator_cache() -> None:
    get_intel_orchestrator.cache_clear()


def invoke_config(thread_id: str) -> dict:
    """LangGraph config for a persistent session."""
    return {"configurable": {"thread_id": thread_id}}


def run_intel_turn(
    user_text: str,
    *,
    thread_id: str = "default",
    orch=None,
) -> dict:
    """Append one user turn and run the graph (requires same ``thread_id`` for memory)."""
    app = orch or get_intel_orchestrator()
    return app.invoke(
        {"messages": [HumanMessage(content=user_text)]},
        config=invoke_config(thread_id),
    )
