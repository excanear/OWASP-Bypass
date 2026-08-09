"""Reads live challenge status from Juice Shop. This is the only trusted
success signal for the whole automator — solvers are never trusted directly."""
from core.client import JuiceShopClient


def get_challenges(client: JuiceShopClient) -> list[dict]:
    resp = client.get("/api/Challenges/")
    resp.raise_for_status()
    return resp.json()["data"]


def is_solved(client: JuiceShopClient, key: str) -> bool:
    for challenge in get_challenges(client):
        if challenge["key"] == key:
            return bool(challenge["solved"])
    raise KeyError(f"unknown challenge key: {key}")
