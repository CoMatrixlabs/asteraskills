"""Minimal LLM factory for tools (OpenAI / Anthropic via settings).

``get_settings()`` loads the repository ``.env`` (and optional ``ASTERASKILLS_ENV_FILE``)
when ``asteraskills.config.settings`` is first imported; tests should load the same via
``tests/conftest.py`` or ``_load_dotenv_for_tests`` before using the LLM.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

from asteraskills.config.settings import get_settings


def _request_timeout_seconds() -> float:
    raw = os.getenv("LLM_REQUEST_TIMEOUT", "120")
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 120.0


def get_llm(
    temperature: float = 0.2,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> Any:
    s = get_settings()
    model = model or s.LLM_MODEL
    prov = (provider or s.LLM_PROVIDER).lower()
    openai_key = s.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")
    anthropic_key = getattr(s, "ANTHROPIC_API_KEY", None) or os.getenv("ANTHROPIC_API_KEY")
    timeout = _request_timeout_seconds()
    if prov == "anthropic":
        return ChatAnthropic(
            model=model,
            temperature=temperature,
            anthropic_api_key=anthropic_key,
            timeout=timeout,
        )
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        top_p=1.0,
        frequency_penalty=0.0,
        presence_penalty=0.0,
        openai_api_key=openai_key,
        timeout=timeout,
    )
