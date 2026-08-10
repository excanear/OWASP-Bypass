import pytest

import solvers.unvalidated_redirects  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

UNVALIDATED_REDIRECTS_KEYS = ["redirectCryptoCurrencyChallenge", "redirectChallenge"]


def test_all_unvalidated_redirects_challenges_solved():
    results = run_all(categories=["Unvalidated Redirects"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in UNVALIDATED_REDIRECTS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
