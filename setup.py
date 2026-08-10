"""Clones (if needed), installs, and starts a local Juice Shop instance via
npm start (not Docker — 17 challenges are unreachable under Docker)."""
import os
import shutil
import subprocess
import time

import requests

JUICE_SHOP_REPO = "https://github.com/juice-shop/juice-shop.git"


def _npm_path() -> str:
    # On Windows, "npm" resolves to npm.cmd, which subprocess can only
    # execute via CreateProcess if given its full, resolved path (a bare
    # "npm" string raises FileNotFoundError there, even though shutil.which
    # finds it fine) — shutil.which() returns that resolved path on every
    # platform, so use it instead of the bare command name.
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm not found on PATH.")
    return npm


def ensure_node() -> None:
    if shutil.which("node") is None:
        raise RuntimeError("Node.js not found on PATH. Install Node.js >= 18 first.")
    _npm_path()


def clone_if_missing(target_dir: str) -> None:
    if not os.path.isdir(target_dir):
        subprocess.run(["git", "clone", "--depth", "1", JUICE_SHOP_REPO, target_dir], check=True)


def npm_install(target_dir: str) -> None:
    if not os.path.isdir(os.path.join(target_dir, "node_modules")):
        subprocess.run([_npm_path(), "install"], cwd=target_dir, check=True)


def start_server(target_dir: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["NODE_CONFIG"] = '{"challenges":{"safetyMode":"disabled"}}'
    return subprocess.Popen([_npm_path(), "start"], cwd=target_dir, env=env)


def wait_ready(base_url: str = "http://localhost:3000", timeout: float = 180.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{base_url}/rest/admin/application-version", timeout=2)
            if resp.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise TimeoutError(f"Juice Shop at {base_url} did not become ready within {timeout}s")


def full_setup(target_dir: str = "./juice-shop", base_url: str = "http://localhost:3000") -> subprocess.Popen:
    ensure_node()
    clone_if_missing(target_dir)
    npm_install(target_dir)
    proc = start_server(target_dir)
    wait_ready(base_url)
    return proc
