"""Per-domain LangGraph ReAct agents (cached)."""

from __future__ import annotations

from functools import lru_cache
from typing import List, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import BaseTool
from langgraph.prebuilt import create_react_agent

from asteraskills.agents.prompts import SPECIALIST_PROMPTS
from asteraskills.agents.tool_sets import DOMAIN_TOOL_KEYS
from asteraskills.agents.tools_loader import tools_for_keys
from asteraskills.core.llm import get_llm

DomainName = Literal["cve", "cwe", "attack", "general"]


def build_specialist_tools(domain: DomainName) -> List[BaseTool]:
    keys = DOMAIN_TOOL_KEYS.get(domain) or DOMAIN_TOOL_KEYS["general"]
    return tools_for_keys(keys)


@lru_cache(maxsize=8)
def get_specialist_graph(domain: str, model_signature: str = "default"):
    """
    Compiled ReAct graph for one domain.

    ``model_signature`` busts the cache when you change LLM_MODEL / provider in settings.
    """
    _ = model_signature  # cache key only
    dom: DomainName
    if domain in ("cve", "cwe", "attack", "general"):
        dom = domain  # type: ignore[assignment]
    else:
        dom = "general"
    llm: BaseChatModel = get_llm(temperature=0.1)
    tools = build_specialist_tools(dom)
    prompt = SPECIALIST_PROMPTS[dom]
    return create_react_agent(
        llm,
        tools,
        prompt=prompt,
        name=f"astera_{dom}_agent",
    )


def specialist_cache_key() -> str:
    """Derive a stable key from current settings for LRU cache busting."""
    try:
        from asteraskills.config.settings import get_settings

        s = get_settings()
        return f"{s.LLM_PROVIDER}:{s.LLM_MODEL}"
    except Exception:  # noqa: BLE001
        return "default"


def get_cached_specialist_graph(domain: str):
    return get_specialist_graph(domain, specialist_cache_key())
