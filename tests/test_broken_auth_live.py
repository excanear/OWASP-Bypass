# tests/test_broken_auth_live.py
import pytest

import solvers.broken_auth  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

BROKEN_AUTH_KEYS = [
    "weakPasswordChallenge", "oauthUserPasswordChallenge", "ghostLoginChallenge",
    "changePasswordBenderChallenge", "resetPasswordJimChallenge", "resetPasswordBenderChallenge",
    "resetPasswordBjoernChallenge", "resetPasswordBjoernOwaspChallenge",
    "twoFactorAuthUnsafeSecretStorageChallenge",
]


def test_all_broken_auth_challenges_solved():
    results = run_all(categories=["Broken Authentication"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in BROKEN_AUTH_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
