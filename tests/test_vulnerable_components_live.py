# tests/test_vulnerable_components_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance (started with challenges.safetyMode=disabled, see Step 1
above) and checks the live score-board."""
import pytest

import solvers.vulnerable_components  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

VULNERABLE_COMPONENTS_KEYS = [
    "fileWriteChallenge", "jwtUnsignedChallenge", "jwtForgedChallenge",
    "typosquattingNpmChallenge", "typosquattingAngularChallenge",
    "supplyChainAttackChallenge", "knownVulnerableComponentChallenge", "lfrChallenge",
]


def test_all_vulnerable_components_challenges_solved():
    results = run_all(categories=["Vulnerable Components"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in VULNERABLE_COMPONENTS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"


def test_video_xss_challenge_solved():
    results = run_all(categories=["XSS"])
    by_key = {r["key"]: r for r in results}
    assert by_key.get("videoXssChallenge", {}).get("solved"), by_key.get("videoXssChallenge")
