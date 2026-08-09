"""Cryptographic Issues category solvers (5 of 5). Verified against
routes/order.ts, routes/coupon.ts, routes/restoreProgress.ts,
routes/premiumReward.ts, routes/easterEgg.ts, routes/verify.ts,
lib/insecurity.ts, and lib/utils.ts (fetched 2026-08-09)."""
import datetime
import urllib.parse
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
    # The z85 alphabet includes '#', '?', '&', etc., which are meaningful in a
    # URL (fragment/query delimiters) — without percent-encoding, a coupon
    # containing e.g. '#' gets silently truncated at that character before it
    # ever reaches the server, producing a 404 that looks like an invalid
    # coupon but is actually a mangled request path.
    apply_resp = ctx.client.put(f"/rest/basket/{bid}/coupon/{urllib.parse.quote(coupon, safe='')}")
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
