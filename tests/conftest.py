"""
Pytest: load repository ``.env`` (and optional ``ASTERASKILLS_ENV_FILE``) before tests.

Ensures integration tests see the same Qdrant/Postgres/OpenAI keys as local development.
Existing OS environment wins (``override=False``) so CI secrets are not clobbered.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def pytest_configure(config: pytest.Config) -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    root = Path(__file__).resolve().parent.parent
    env_main = root / ".env"
    if env_main.is_file():
        load_dotenv(env_main, override=False)
    extra = os.environ.get("ASTERASKILLS_ENV_FILE")
    if extra:
        p = Path(extra).expanduser()
        if p.is_file():
            load_dotenv(p, override=False)

    try:
        from asteraskills.config.settings import clear_settings_cache

        clear_settings_cache()
    except ImportError:
        pass
