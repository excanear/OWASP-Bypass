# tests/test_cryptographic_issues_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.cryptographic_issues  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

CRYPTOGRAPHIC_ISSUES_KEYS = [
    "forgedCouponChallenge", "continueCodeChallenge", "easterEggLevelTwoChallenge",
    "premiumPaywallChallenge", "weirdCryptoChallenge",
]


def test_all_cryptographic_issues_challenges_solved():
    results = run_all(categories=["Cryptographic Issues"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in CRYPTOGRAPHIC_ISSUES_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
