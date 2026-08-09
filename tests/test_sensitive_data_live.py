"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.sensitive_data  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

SENSITIVE_DATA_KEYS = [
    "nftUnlockChallenge", "passwordHashLeakChallenge", "emailLeakChallenge",
    "directoryListingChallenge", "forgottenDevBackupChallenge", "forgottenBackupChallenge",
    "loginRapperChallenge", "loginAmyChallenge", "exposedCredentialsChallenge",
    "dataExportChallenge", "dlpPastebinDataLeakChallenge", "leakedApiKeyChallenge",
    "retrieveBlueprintChallenge", "resetPasswordUvoginChallenge",
    "geoStalkingMetaChallenge", "geoStalkingVisualChallenge",
]


def test_all_sensitive_data_challenges_solved():
    results = run_all(categories=["Sensitive Data Exposure"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in SENSITIVE_DATA_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
