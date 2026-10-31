import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def offline_interpreter(monkeypatch):
    """No unit test may reach the live Gemini API.

    A configured key in .env would otherwise make the suite slow and
    non-deterministic, and tests must pass without any API access at all.
    tests/test_gemini_integration.py is the one deliberate exception, and only
    when AGENTGATE_GEMINI_TESTS=1 is set explicitly.
    """
    from ai import interpreter as ai_interpreter

    ai_interpreter.reset_gemini_state()

    if os.getenv("AGENTGATE_GEMINI_TESTS") == "1":
        return

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    ai_interpreter.reset_gemini_state()
