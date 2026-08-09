"""Solver registry. Each challenge solver module imports `register` and
decorates one function per challenge key; `all_solvers()` is consumed by
core.runner."""
from dataclasses import dataclass
from typing import Callable

from core.client import JuiceShopClient


@dataclass
class SolverContext:
    client: JuiceShopClient
    base_url: str


@dataclass
class Solver:
    key: str
    category: str
    difficulty: int
    run: Callable[[SolverContext], None]


_REGISTRY: list[Solver] = []


def register(key: str, category: str, difficulty: int):
    def decorator(fn: Callable[[SolverContext], None]):
        _REGISTRY.append(Solver(key=key, category=category, difficulty=difficulty, run=fn))
        return fn
    return decorator


def all_solvers() -> list[Solver]:
    return list(_REGISTRY)
