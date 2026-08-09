# tests/test_framework.py
"""Live smoke test — requires a Juice Shop instance already running at
localhost:3000 (start it manually with `npm start` in a juice-shop checkout
before running this). No mocking: this project only trusts live verification."""
import pytest

from core.challenge_api import get_challenges, is_solved
from core.client import JuiceShopClient


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")


def test_get_challenges_returns_110_or_more():
    client = JuiceShopClient()
    challenges = get_challenges(client)
    assert len(challenges) >= 110


def test_is_solved_for_unknown_key_raises():
    client = JuiceShopClient()
    with pytest.raises(KeyError):
        is_solved(client, "notARealChallengeKey")


def test_login_as_demo_user_succeeds():
    client = JuiceShopClient()
    # Juice Shop's seed "demo" user has customDomain: true with a bare
    # "demo" email (no @juice-sh.op suffix) -- confirmed against a live
    # instance's data/static/users.yml and /rest/user/login response.
    resp = client.login("demo", "demo")
    assert resp.status_code == 200
    assert client.token
