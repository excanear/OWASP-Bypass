import pytest

import solvers.xxe  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

# xxeDosChallenge is deliberately excluded — a genuine, well-investigated
# BLOCKED outcome (libxml2's entity-amplification guard + 200KB upload cap
# make the required timeout code path unreachable here), same deferral
# convention as nftMintChallenge/web3WalletChallenge/aiDebuggingChallenge.
XXE_KEYS = ["xxeFileDisclosureChallenge"]


def test_all_xxe_challenges_solved():
    results = run_all(categories=["XXE"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in XXE_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
