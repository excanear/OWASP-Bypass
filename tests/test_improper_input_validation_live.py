"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.improper_input_validation  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

IMPROPER_INPUT_VALIDATION_KEYS = [
    "registerAdminChallenge", "passwordRepeatChallenge", "emptyUserRegistration",
    "manipulateClockChallenge", "negativeOrderChallenge", "freeDeluxeChallenge",
    "uploadSizeChallenge", "uploadTypeChallenge", "zeroStarsChallenge",
    "missingEncodingChallenge", "nullByteChallenge",
]


def test_all_improper_input_validation_challenges_solved():
    results = run_all(categories=["Improper Input Validation"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in IMPROPER_INPUT_VALIDATION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
