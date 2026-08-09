"""Executes every registered solver against a fresh client each, then
confirms success via the live challenge API — never trusts the solver's
return value directly."""
import time

from core.challenge_api import is_solved
from core.client import JuiceShopClient
from solvers.base import all_solvers, SolverContext


def run_all(base_url: str = "http://localhost:3000", categories: list[str] | None = None,
            timeout: float = 15.0) -> list[dict]:
    results = []
    for solver in all_solvers():
        if categories and solver.category not in categories:
            continue
        client = JuiceShopClient(base_url)
        ctx = SolverContext(client=client, base_url=base_url)
        start = time.time()
        error = None
        try:
            solver.run(ctx)
        except Exception as exc:  # noqa: BLE001 - isolate one solver's failure from the rest
            error = f"{type(exc).__name__}: {exc}"
        duration = round(time.time() - start, 2)
        try:
            solved = is_solved(client, solver.key)
        except Exception as exc:  # noqa: BLE001
            solved = False
            error = error or f"{type(exc).__name__}: {exc}"
        results.append({
            "key": solver.key,
            "category": solver.category,
            "solved": solved,
            "duration": duration,
            "error": error,
        })
    return results
