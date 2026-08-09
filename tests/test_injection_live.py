# tests/test_injection_live.py
"""No mocking, per project convention: this runs the real solvers against a
live Juice Shop instance (started per tests/test_framework.py Step 10) and
checks the live score-board."""
import pytest

import solvers.injection  # noqa: F401 - registers the solvers
from core.challenge_api import is_solved
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

INJECTION_KEYS = [
    "loginAdminChallenge", "loginBenderChallenge", "loginJimChallenge",
    "ephemeralAccountantChallenge", "unionSqlInjectionChallenge", "dbSchemaChallenge",
    "noSqlOrdersChallenge", "noSqlCommandChallenge", "noSqlReviewsChallenge",
    "sstiChallenge", "christmasSpecialChallenge",
]


def test_all_injection_challenges_solved():
    results = run_all(categories=["Injection"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in INJECTION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
